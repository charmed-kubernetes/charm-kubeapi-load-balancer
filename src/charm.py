#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service."""

import ipaddress
import itertools
import json
import logging
import os
import pwd
import re
import shutil
import socket
import subprocess
import tarfile
from pathlib import Path
from typing import Dict, List, Set

import charms.contextual_status as status
import ops
import yaml
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.operator_libs_linux.v1.systemd import (
    daemon_reload,
    service_restart,
    service_running,
    service_stop,
)
from charms.reconciler import Reconciler
from hacluster import HACluster
from loadbalancer_interface import LBConsumers
from nginx import NginxConfigurer
from ops.interface_tls_certificates import CertificatesRequires
from ops.model import Binding, BlockedStatus, MaintenanceStatus, ModelError, WaitingStatus
from yaml import YAMLError

log = logging.getLogger(__name__)

VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


TEMPLATES_PATH = Path(Path.cwd() / "templates")
CERT_DIR = Path("/srv/kubernetes")
SERVER_CRT_PATH = CERT_DIR / "server.crt"
SERVER_KEY_PATH = CERT_DIR / "server.key"

NGINX_SERVICE = "nginx"
EXPORTER = "nginx-prometheus-exporter"


class CharmKubeApiLoadBalancer(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)

        self.certificates = CertificatesRequires(self)
        self.cos_agent = COSAgentProvider(
            self,
            metrics_endpoints=[
                {"path": "/metrics", "port": 9113},  # nginx-prometheus-exporter
            ],
        )
        self.load_balancer = LBConsumers(self, "lb-consumers")
        self.load_balancer.follower_perms(read=True)
        self.reconciler = Reconciler(self, self._reconcile)

        self.hacluster = HACluster(self, self.config)
        self.nginx = NginxConfigurer(self, self.config)

        self.framework.observe(self.load_balancer.on.requests_changed, self._provide_lbs)

    def _as_address(self, addr_str: str):
        """Convert a string to an IP address. Returns None if the conversion fails."""
        try:
            return ipaddress.ip_address(addr_str)
        except ValueError:
            return None

    def _change_owner(self, file_path: Path, user_name: str):
        """Change the owner of a file.

        Args:
        ----
            file_path (Path): The path to the file whose owner needs to be changed.
            user_name (str): The name of the user to set as the new owner.

        """
        user = pwd.getpwnam(user_name)
        uid, gid = user.pw_uid, user.pw_gid
        os.chown(path=file_path, uid=uid, gid=gid)

    def _check_certificates(self, event):
        """Check the certificates relation status and updates the status accordingly.

        Returns
        -------
            True if certificates relation is ready, False otherwise.

        """
        evaluation = self.certificates.evaluate_relation(event)
        if evaluation:
            log.info(f"Certificates evaluation: {evaluation}")
            if "Waiting" in evaluation:
                status.add(WaitingStatus(evaluation))
            else:
                status.add(BlockedStatus(evaluation))
            return False
        return True

    def _configure_hacluster(self):
        if self.hacluster.is_ready:
            status.add(MaintenanceStatus("Configuring HACluster"))
            self.hacluster.update_vips()
            self.hacluster.configure_hacluster()
            self.hacluster.add_service("nginx", "nginx")
        else:
            self.hacluster.remove_service("nginx", "nginx")

    def _configure_nginx(self):
        """Configure NGINX based on provided directives.

        This method configures main and events contexts with the directives provided
        in the configuration, removes the default NGINX site, and writes the NGINX log
        rotation configuration.
        """
        contexts = {}
        try:
            contexts["main"] = yaml.safe_load(self.config.get("nginx-main-config")) or {}
            contexts["events"] = yaml.safe_load(self.config.get("nginx-events-config")) or {}
            contexts["http"] = yaml.safe_load(self.config.get("nginx-http-config")) or {}
        except YAMLError:
            log.exception("Encountered juju config parsing error")
            status.add(BlockedStatus("Failed to configure NGINX context. Check config values."))
            return
        try:
            self.nginx.configure_daemon(contexts)
            self.nginx.remove_default_site()
            self._write_nginx_logrotate_config()
        except subprocess.CalledProcessError:
            msg = "Failed to change Nginx.conf"
            log.exception(msg)
            status.add(BlockedStatus(msg))

    def _configure_nginx_sites(self, servers: Dict[int, Set]):
        """Configure NGINX with the server dictionary.

        Args:
        ----
            servers (Dict[int, Set]): A dictionary where the keys are server ports (int) and the values
            are sets containing tuples of backends and their corresponding backend ports.

        """
        self.nginx.configure_site(
            "apilb",
            TEMPLATES_PATH / "apilb.conf",
            servers=servers,
            server_certificate=str(SERVER_CRT_PATH),
            server_key=str(SERVER_KEY_PATH),
            proxy_read_timeout=self.config.get("proxy_read_timeout"),
        )
        self.nginx.configure_site("metrics", TEMPLATES_PATH / "metrics.conf")

    def _create_server_dict(self) -> Dict[int, Set]:
        """Create a dictionary of servers and their backends.

        Returns
        -------
            Dict[int, Set]: A dictionary where the keys are server ports (int) and the values
            are sets containing tuples of backends and their corresponding backend ports.

        """
        servers = {}
        for request in self.load_balancer.all_requests:
            for server_port in request.port_mapping.keys():
                service: set = servers.setdefault(server_port, set())
                service.update(itertools.product(request.backends, request.port_mapping.values()))
        return servers

    def _get_bind_addresses(self, ipv4=True, ipv6=True):
        """Retrieve a list of bind addresses for the current unit.

        Args:
        ----
            ipv4 (bool): Whether to include IPv4 addresses (default is True).
            ipv6 (bool): Whether to include IPv6 addresses (default is True).

        Returns:
        -------
            List[str]: A list of bind addresses available on the unit.

        """
        result = subprocess.check_output(
            ["ip", "-j", "-br", "addr", "show", "scope", "global"],
            text=True,
            timeout=25,
        )
        ignored_ifaces = ("lxdbr", "flannel", "cni", "virbr", "docker")
        accept_versions = {4} if ipv4 else set()
        accept_versions.add(6) if ipv6 else None

        addrs = []
        for addr in json.loads(result.strip()):
            if addr["operstate"].upper() != "UP" or any(
                addr["ifname"].startswith(prefix) for prefix in ignored_ifaces
            ):
                continue
            for ifc in addr["addr_info"]:
                local_addr = self._as_address(ifc.get("local"))
                if local_addr and local_addr.version in accept_versions:
                    addrs.append(str(local_addr))
        return addrs

    def _get_lb_addresses(self) -> List[str]:
        """Return a list of load balancer addresses."""
        if forced_lb_ips := self.config.get("loadbalancer-ips").split():
            return forced_lb_ips
        if self.hacluster.is_ready:
            if vips := self.config.get("ha-cluster-vip").split():
                return vips
            if dns_records := self.config.get("ha-cluster-dns").split():
                return dns_records
        return []

    def _get_public_address(self):
        """Return the unit public-address."""
        result = subprocess.check_output(
            ["unit-get", "public-address"],
            text=True,
            timeout=25,
        )
        return result.strip()

    @status.on_error(status.WaitingStatus("Waiting to restart Nginx"))
    def _install_load_balancer(self):
        """Install and configure the load balancer."""
        status.add(MaintenanceStatus("Installing Load Balancer"))
        if not (SERVER_CRT_PATH.exists() and SERVER_KEY_PATH.exists()):
            log.info("Skipping due to missing certificate.")
            return False
        if not self.load_balancer.all_requests:
            status.add(WaitingStatus("Load Balancer request not ready"))
            log.info("Skipping due to requests not ready.")

        # Change the owner of the certs.
        self._change_owner(SERVER_CRT_PATH, "www-data")
        self._change_owner(SERVER_KEY_PATH, "www-data")

        servers = self._create_server_dict()
        self._configure_nginx_sites(servers)
        self._manage_ports(servers.keys())

        self._restart_nginx()

    def _install_exporter(self) -> bool:
        resource_name = EXPORTER
        try:
            resource_path = self.model.resources.fetch(resource_name)
        except ModelError:
            status.add(BlockedStatus(f"Error claiming {resource_name}"))
            return False
        except NameError:
            status.add(BlockedStatus(f"Resource {resource_name} not found"))
            return
        filesize = resource_path.stat().st_size
        if filesize < 1000000:
            status.add(BlockedStatus(f"Incomplete resource: {resource_name}"))
            return
        status.add(MaintenanceStatus(f"Unpacking {resource_name}"))

        if service_running(EXPORTER):
            service_stop(EXPORTER)

        install_path = Path("/opt", EXPORTER)
        install_path.mkdir(parents=True, exist_ok=True)
        with tarfile.open(resource_path) as tar:
            tar.extractall(install_path)

        path = Path(f"/etc/systemd/system/{EXPORTER}.service")
        if not path.exists():
            template_path = TEMPLATES_PATH / f"{EXPORTER}.service"
            shutil.copy2(template_path, path)

        if not daemon_reload():
            status.add(BlockedStatus(f"Cannot load service: {resource_name}"))
            return

        service_restart(EXPORTER)

    def _manage_ports(self, ports: Set[int]):
        """Open ports on the unit and close the unwanted ones.

        Args:
        ----
            ports (Set[int]): A set of integers representing the server ports to be opened.

        """
        opened_ports = {port.port for port in self.unit.opened_ports()}
        open_ports = ports - opened_ports
        close_ports = opened_ports - ports

        for port in open_ports:
            self.unit.open_port(protocol="tcp", port=port)

        for port in close_ports:
            self.unit.close_port(protocol="tcp", port=port)

    def _provide_lbs(self, _):
        """Provide load balancer addresses to the requests based on their protocol and address type."""
        lb_addresses = self._get_lb_addresses()

        for request in self.load_balancer.new_requests:
            response = request.response
            if request.protocol not in (
                request.protocols.tcp,
                request.protocols.http,
                request.protocols.https,
            ):
                response.error_type = response.error_types.unsupported
                response.error_fields = {"protocol": "Protocol must be one of: tcp, http, https"}
                self.load_balancer.send_response(request)
                continue
            if lb_addresses:
                private_address = lb_addresses[0]
                public_address = lb_addresses[0]
            else:
                network: Binding = self.model.get_binding("lb-consumers")
                private_address = network.network.bind_address
                public_address = self._get_public_address()
            if request.public:
                response.address = public_address
            else:
                response.address = private_address
            self.load_balancer.send_response(request)

    def _reconcile(self, event):
        self._request_server_certificates(event)
        self._write_certificates()
        self._configure_nginx()
        self._install_load_balancer()
        self._install_exporter()
        self._configure_hacluster()
        self._set_nginx_version()

    def _request_server_certificates(self, event):
        """Request the certificates to the CA authority."""
        status.add(MaintenanceStatus("Requesting certificate"))
        if not self._check_certificates(event):
            return

        common_name = self._get_public_address()
        bind_ips = self._get_bind_addresses(ipv4=True, ipv6=True)

        sans = [
            common_name,
            socket.gethostname(),
            socket.getfqdn(),
            *bind_ips,
        ]

        sans.extend(self._get_lb_addresses())
        extra_sans = self.config.get("extra_sans").split()
        if extra_sans:
            sans.extend(extra_sans)

        self.certificates.request_server_cert(cn=common_name, sans=sorted(set(sans)))

    def _restart_nginx(self):
        service_restart(NGINX_SERVICE)

    def _set_nginx_version(self):
        """Get the Nginx version and set the unit workload version accordingly."""
        try:
            output = subprocess.check_output(["nginx", "-v"], stderr=subprocess.STDOUT, text=True)
            log.info(f"Version: {output}")
            version_re = r"nginx\/(\d+\.\d+\.\d+)"
            match = re.search(version_re, output)
            if match:
                log.info(f"Setting unit version to {match.group(1)}")
                self.unit.set_workload_version(match.group(1))
            else:
                log.warning("Failed to extract nginx version from the output.")
        except subprocess.CalledProcessError as e:
            log.error(f"Error while running 'nginx -v': {e.output}")

    def _write_certificates(self):
        """Write the certificates to the appropriate files."""
        status.add(MaintenanceStatus("Writing certificate"))
        common_name = self._get_public_address()
        cert = self.certificates.server_certs_map.get(common_name)

        if not cert:
            msg = "Waiting for certificate"
            status.add(WaitingStatus(msg))
            log.info(msg)
            return

        SERVER_CRT_PATH.parent.mkdir(parents=True, exist_ok=True)

        # Write the certs to tmp files first.
        tmp_crt_path = SERVER_CRT_PATH.parent / (SERVER_CRT_PATH.name + ".tmp")
        tmp_key_path = SERVER_KEY_PATH.parent / (SERVER_KEY_PATH.name + ".tmp")

        try:
            with tmp_crt_path.open("w") as crt_file:
                crt_file.write(cert.cert)

            with tmp_key_path.open("w") as key_file:
                key_file.write(cert.key)

            tmp_crt_path.rename(SERVER_CRT_PATH)
            tmp_key_path.rename(SERVER_KEY_PATH)
        except (IOError, OSError):
            log.exception("Failed to write certificate")

    def _write_nginx_logrotate_config(self):
        """Write Nginx KubeAPI LB logrotate configuration if it doesn't exist."""
        path = Path("/etc/logrotate.d/nginx-apilb")
        if not path.exists():
            template_path = TEMPLATES_PATH / "nginx-apilb"
            shutil.copy2(template_path, path)


if __name__ == "__main__":  # pragma: nocover
    ops.main(CharmKubeApiLoadBalancer)
