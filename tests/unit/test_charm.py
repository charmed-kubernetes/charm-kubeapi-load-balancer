# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import ipaddress
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import ops
import ops.testing
from charm import CharmKubeApiLoadBalancer


class TestCharm(unittest.TestCase):
    @patch("charm.NginxConfigurer", autospec=True)
    def setUp(self, mock_nginx):
        self.harness = ops.testing.Harness(CharmKubeApiLoadBalancer)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm
        self.mock_nginx = mock_nginx

    def test__as_address(self):
        self.assertEqual(self.charm._as_address("127.0.0.1"), ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(self.charm._as_address("::1"), ipaddress.IPv6Address("::1"))
        self.assertIsNone(self.charm._as_address("invalid"))

    def test__change_owner(self):
        with patch("charm.pwd.getpwnam") as mock_getpw, patch("charm.os.chown") as mock_chown:
            mock_getpw.return_value.pw_uid = "1000"
            mock_getpw.return_value.pw_gid = "1001"
            file_path = "/etc/foo/bar"
            user_name = "testuser"
            self.charm._change_owner(file_path, user_name)
            mock_chown.assert_called_once_with(path=file_path, uid="1000", gid="1001")

    def test__configure_hacluster(self):
        with patch.object(self.charm, "hacluster") as mock_hacluster:
            mock_hacluster.is_ready = True
            self.charm._configure_hacluster()
            mock_hacluster.update_vips.assert_called_once()
            mock_hacluster.update_dns.assert_called_once()
            mock_hacluster.configure_hacluster.assert_called_once()
            mock_hacluster.add_service.assert_called_once_with("nginx", "nginx")

    def test_configure_nginx(self):
        with patch.object(self.charm, "_write_nginx_logrotate_config") as mock_write:
            servers = {80: {("backend1", 8080), ("backend2", 8081)}}
            self.harness.update_config({"proxy_read_timeout": 10})
            self.charm._configure_nginx(servers)
            assert self.mock_nginx.return_value.configure_site.mock_calls == [
                call(
                    "apilb",
                    Path.cwd() / "templates" / "apilb.conf",
                    servers=servers,
                    server_certificate="/srv/kubernetes/server.crt",
                    server_key="/srv/kubernetes/server.key",
                    proxy_read_timeout=10,
                ),
                call(
                    "metrics",
                    Path.cwd() / "templates" / "metrics.conf",
                ),
            ]
            self.mock_nginx.return_value.remove_default_site.assert_called_once()
            mock_write.assert_called_once()

    def test__create_server_dict(self):
        mock_request1 = MagicMock()
        mock_request1.port_mapping = {80: 8080, 443: 8443}
        mock_request1.backends = {"10.1.1.1", "10.1.1.2"}

        mock_request2 = MagicMock()
        mock_request2.port_mapping = {80: 8080}
        mock_request2.backends = {"10.1.1.3"}

        self.charm.load_balancer.all_requests = [mock_request1, mock_request2]

        expected_servers = {
            80: {
                ("10.1.1.3", 8080),
                ("10.1.1.1", 8080),
                ("10.1.1.1", 8443),
                ("10.1.1.2", 8080),
                ("10.1.1.2", 8443),
            },
            443: {("10.1.1.2", 8080), ("10.1.1.1", 8443), ("10.1.1.2", 8443), ("10.1.1.1", 8080)},
        }

        servers = self.charm._create_server_dict()
        self.assertEqual(servers, expected_servers)

    @patch("charm.subprocess.run")
    def test_get_bind_addresses(self, mock_subprocess_run):
        mock_process = MagicMock()
        mock_process.stdout = json.dumps(
            [
                {
                    "ifname": "eth0",
                    "operstate": "UP",
                    "addr_info": [{"local": "10.1.1.1"}, {"local": "fe80::1"}],
                },
                {
                    "ifname": "eth1",
                    "operstate": "DOWN",
                    "addr_info": [{"local": "192.168.1.1"}],
                },
            ]
        )
        mock_subprocess_run.return_value = mock_process

        expected_addrs = ["10.1.1.1", "fe80::1"]

        addrs = self.charm._get_bind_addresses()

        self.assertEqual(addrs, expected_addrs)

    def test_get_lb_addresses_with_no_config(self):
        expected_addresses = []
        addresses = self.charm._get_lb_addresses()

        self.assertEqual(addresses, expected_addresses)

    def test_get_lb_addresses_with_loadbalancer_ips(self):
        self.harness.update_config({"loadbalancer-ips": "10.1.1.1 10.1.1.2"})
        expected_addresses = ["10.1.1.1", "10.1.1.2"]
        addresses = self.charm._get_lb_addresses()

        self.assertEqual(addresses, expected_addresses)

    def test_get_lb_addresses_with_ha_cluster_vip(self):
        self.harness.update_config({"ha-cluster-vip": "10.1.1.1 10.1.1.2"})
        with patch.object(self.charm, "hacluster") as mock_hacluster:
            mock_hacluster.is_ready = True
            expected_addresses = ["10.1.1.1", "10.1.1.2"]
            addresses = self.charm._get_lb_addresses()

            self.assertEqual(addresses, expected_addresses)

    def test_get_lb_addresses_with_ha_cluster_dns(self):
        self.harness.update_config({"ha-cluster-dns": "api.example.com"})
        with patch.object(self.charm, "hacluster") as mock_hacluster:
            mock_hacluster.is_ready = True
            expected_addresses = ["api.example.com"]
            addresses = self.charm._get_lb_addresses()

            self.assertEqual(addresses, expected_addresses)

    @patch("charm.CharmKubeApiLoadBalancer._restart_nginx")
    @patch("charm.CharmKubeApiLoadBalancer._manage_ports")
    @patch("charm.CharmKubeApiLoadBalancer._configure_nginx")
    @patch("charm.CharmKubeApiLoadBalancer._create_server_dict")
    @patch("charm.CharmKubeApiLoadBalancer._change_owner")
    @patch("charm.Path.exists")
    def test_install_load_balancer(
        self,
        mock_exists,
        mock_change_owner,
        mock_create_server_dict,
        mock_configure_nginx,
        mock_manage_ports,
        mock_restart_nginx,
    ):
        with patch.object(self.charm.load_balancer, "all_requests") as mock_requests:
            mock_requests.return_value = True
            mock_exists.return_value = True

            mock_servers = {80: "10.1.1.1", 443: "10.1.1.2"}
            mock_create_server_dict.return_value = mock_servers

            self.charm._install_load_balancer()

            mock_exists.assert_has_calls([call(), call()])
            mock_change_owner.assert_has_calls(
                [
                    call(Path("/srv/kubernetes/server.crt"), "www-data"),
                    call(Path("/srv/kubernetes/server.key"), "www-data"),
                ]
            )
            mock_create_server_dict.assert_called_once()
            mock_configure_nginx.assert_called_with(mock_servers)
            mock_manage_ports.assert_called_with(mock_servers.keys())
            mock_restart_nginx.assert_called_once()

    def test_manage_ports(self):
        with patch.object(self.charm.unit, "opened_ports") as mock_opened, patch.object(
            self.charm.unit, "open_port"
        ) as mock_open, patch.object(self.charm.unit, "close_port") as mock_close:
            mock_opened.return_value = [
                MagicMock(port=80),
                MagicMock(port=443),
                MagicMock(port=8080),
            ]

            ports = {80, 443, 8081}

            self.charm._manage_ports(ports)

            mock_open.assert_called_once_with(protocol="tcp", port=8081)
            mock_close.assert_called_once_with(protocol="tcp", port=8080)

    @patch("charm.Path")
    @patch("charm.tarfile", MagicMock())
    @patch("charm.service_running", MagicMock(return_value=True))
    @patch("charm.service_stop")
    @patch("charm.daemon_reload")
    @patch("charm.service_restart")
    def test_install_exporter(
        self,
        mock_service_restart,
        mock_daemon_reload,
        mock_service_stop,
        mock_path,
    ):
        with (patch.object(self.charm.model.resources, "fetch") as mock_fetch,):
            mock_resource = mock_fetch.return_value
            mock_resource.stat().st_size = 3000000
            self.charm._install_exporter()

            assert mock_path.mock_calls == [
                call("/opt", "nginx-prometheus-exporter"),
                call().mkdir(parents=True, exist_ok=True),
                call("/etc/systemd/system/nginx-prometheus-exporter.service"),
                call().exists(),
                call().exists().__bool__(),
            ]
            mock_service_stop.assert_called_once_with("nginx-prometheus-exporter")
            mock_daemon_reload.assert_called_once_with()
            mock_service_restart.assert_called_once_with("nginx-prometheus-exporter")

    @patch("charm.CharmKubeApiLoadBalancer._request_server_certificates")
    @patch("charm.CharmKubeApiLoadBalancer._write_certificates")
    @patch("charm.CharmKubeApiLoadBalancer._install_load_balancer")
    @patch("charm.CharmKubeApiLoadBalancer._install_exporter")
    @patch("charm.CharmKubeApiLoadBalancer._configure_hacluster")
    @patch("charm.CharmKubeApiLoadBalancer._set_nginx_version")
    def test_reconcile(
        self,
        mock_set_nginx_version,
        mock_configure_hacluster,
        mock_install_load_balancer,
        mock_install_exporter,
        mock_write_certificates,
        mock_request_server_certificates,
    ):
        mock_event = MagicMock()
        self.charm._reconcile(mock_event)

        mock_request_server_certificates.assert_called_once()
        mock_write_certificates.assert_called_once()
        mock_install_load_balancer.assert_called_once()
        mock_install_exporter.assert_called_once()
        mock_configure_hacluster.assert_called_once()
        mock_set_nginx_version.assert_called_once()

    @patch("charm.CharmKubeApiLoadBalancer._get_lb_addresses")
    def test_provide_lbs_with_tcp_protocol(self, mock_get_lb_addresses):
        with patch.object(self.charm, "load_balancer") as mock_load_balancer:
            mock_request = MagicMock()
            mock_request.protocol = "tcp"
            mock_request.public = True
            mock_lb_addresses = ["10.1.1.1", "10.1.1.2"]
            mock_event = MagicMock()
            mock_get_lb_addresses.return_value = mock_lb_addresses
            mock_load_balancer.new_requests = [mock_request]

            self.charm._provide_lbs(mock_event)

            mock_request.response.address = mock_lb_addresses[0]
            mock_load_balancer.send_response.assert_called_once_with(mock_request)

    @patch("charm.CharmKubeApiLoadBalancer._get_lb_addresses")
    def test_provide_lbs_with_unsupported_protocol(self, mock_get_lb_addresses):
        with patch.object(self.charm, "load_balancer") as mock_load_balancer:
            mock_request = MagicMock()
            mock_event = MagicMock()
            mock_request.protocol = "unsupported"
            mock_lb_addresses = ["10.1.1.1", "10.1.1.2"]
            mock_load_balancer.new_requests = [mock_request]
            mock_get_lb_addresses.return_value = mock_lb_addresses

            self.charm._provide_lbs(mock_event)

            mock_request.response.error_type = mock_request.response.error_types.unsupported
            mock_request.response.error_fields = {
                "protocol": "Protocol must be one of: tcp, http, https"
            }
            mock_load_balancer.send_response.assert_called_once_with(mock_request)

    @patch("charm.CharmKubeApiLoadBalancer._get_lb_addresses")
    def test_provide_lbs_with_no_lb_addresses(self, mock_get_lb_addresses):
        with patch.object(self.charm, "load_balancer") as mock_load_balancer, patch.object(
            self.charm.model, "get_binding"
        ) as mock_binding:
            mock_request = MagicMock()
            mock_request.protocol = "tcp"
            mock_load_balancer.new_requests = [mock_request]
            mock_get_lb_addresses.return_value = []
            mock_network = MagicMock()
            mock_network.network.bind_address = "10.1.1.3"
            mock_network.network.ingress_address = "10.1.1.4"
            mock_binding.return_value = mock_network

            self.charm._provide_lbs(MagicMock())

            mock_request.response.address = mock_network.network.bind_address
            mock_load_balancer.send_response.assert_called_once_with(mock_request)

    @patch("charm.CharmKubeApiLoadBalancer._get_lb_addresses")
    def test_provide_lbs_with_public_request(self, mock_get_lb_addresses):
        with patch.object(self.charm, "load_balancer") as mock_load_balancer:
            mock_request = MagicMock()
            mock_request.protocol = "tcp"
            mock_load_balancer.new_requests = [mock_request]
            mock_get_lb_addresses.return_value = []
            mock_lb_addresses = ["10.1.1.1", "10.1.1.2"]
            mock_get_lb_addresses.return_value = mock_lb_addresses

            mock_request.public = True

            self.charm._provide_lbs(None)
