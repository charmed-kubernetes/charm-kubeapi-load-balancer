import unittest
from unittest.mock import MagicMock, patch

from charm import CharmKubeApiLoadBalancer
from hacluster import HAClusterConfigMismatchError
from ops.testing import Harness


class TestHACluster(unittest.TestCase):
    @patch("charm.NginxConfigurer", MagicMock())
    def setUp(self):
        self.harness = Harness(CharmKubeApiLoadBalancer)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.cluster = self.harness.charm.hacluster

    def test_add_service(self):
        cluster = self.cluster
        with patch.object(cluster, "interface", autospec=True) as mock_interface:
            cluster.add_service("my-service", "my-service-name")
            cluster._update_services()
            mock_interface.add_systemd_service.assert_called_once_with(
                "my-service", "my-service-name"
            )

    def test_remove_service(self):
        cluster = self.cluster
        with patch.object(cluster, "interface", autospec=True) as mock_interface:
            cluster.add_service("my-service", "my-service-name")
            cluster.add_service("my-foo", "my-foo-name")
            cluster._update_services()
            cluster.remove_service("my-service", "my-service-name")
            cluster._update_services()
            mock_interface.remove_systemd_service.assert_called_once_with(
                "my-service", "my-service-name"
            )

    def test_configure_hacluster_with_vips(self):
        self.harness.update_config(
            {
                "ha-cluster-vip": "10.0.0.1 10.0.0.2",
            }
        )
        cluster = self.cluster
        with patch.object(cluster, "interface", autospec=True) as mock_interface:
            cluster.configure_hacluster()
            mock_interface.add_vip.assert_any_call(cluster._unit_name, "10.0.0.1")
            mock_interface.add_vip.assert_any_call(cluster._unit_name, "10.0.0.2")

    def test_configure_hacluster_with_dns(self):
        id = self.harness.add_relation("ha", "hacluster")
        self.harness.add_relation_unit(id, "hacluster/0")
        self.harness.update_config(
            {
                "ha-cluster-dns": "my-service.example.com",
            }
        )
        cluster = self.cluster
        with patch.object(cluster, "interface", autospec=True) as mock_interface:
            with patch.object(cluster.charm.model, "get_binding", autospec=True) as mock_binding:
                mock_binding.return_value.network.ingress_address = "127.0.0.1"
                cluster.configure_hacluster()
                mock_interface.add_dnsha.assert_called_once_with(
                    cluster._unit_name, "127.0.0.1", "my-service.example.com", "public"
                )

    def test_configure_hacluster_with_both_vips_and_dns(self):
        self.harness.update_config(
            {
                "ha-cluster-vip": "10.0.0.1",
                "ha-cluster-dns": "my-service.example.com",
            }
        )
        cluster = self.cluster
        with self.assertRaises(HAClusterConfigMismatchError):
            cluster.configure_hacluster()

    def test_update_vips(self):
        self.harness.update_config(
            {
                "ha-cluster-vip": "10.0.0.1 10.0.0.2",
            }
        )
        cluster = self.cluster
        with patch.object(cluster, "interface", autospec=True) as mock_interface:
            cluster.update_vips()
            cluster.configure_hacluster()
            self.harness.update_config(
                {
                    "ha-cluster-vip": "10.0.0.2 10.0.0.3",
                }
            )
            cluster.update_vips()
            cluster.configure_hacluster()
            mock_interface.remove_vip.assert_called_once_with(cluster._unit_name, "10.0.0.1")

    def test_update_dns(self):
        self.harness.update_config(
            {
                "ha-cluster-dns": "my-service.example.com",
            }
        )
        cluster = self.cluster
        with patch.object(cluster, "interface", autospec=True) as mock_interface:
            with patch.object(cluster.charm.model, "get_binding", autospec=True) as mock_binding:
                mock_binding.return_value.network.ingress_address = "127.0.0.1"
                cluster.configure_hacluster()
                cluster.update_dns()
                mock_interface.remove_dnsha.assert_called_once_with(cluster._unit_name, "public")
