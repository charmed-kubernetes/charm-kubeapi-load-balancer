#!/usr/bin/env python

# Copyright 2015 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import itertools
import os
import socket
import subprocess

from pathlib import Path

from charms.reactive import when, when_any, when_not
from charms.reactive import set_flag, is_state
from charms.reactive import hook
from charms.reactive import clear_flag, endpoint_from_flag, endpoint_from_name
from charmhelpers.core import hookenv
from charmhelpers.core import host
from charmhelpers.contrib.charmsupport import nrpe

from charms.layer import nginx
from charms.layer import tls_client
from charms.layer import status
from charms.layer import kubernetes_common
from charms.layer.hacluster import add_service_to_hacluster
from charms.layer.hacluster import remove_service_from_hacluster

from subprocess import Popen
from subprocess import PIPE
from subprocess import STDOUT
from subprocess import CalledProcessError

from typing import List


apilb_nginx = """/var/log/nginx.*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    prerotate
        if [ -d /etc/logrotate.d/httpd-prerotate ]; then \\
            run-parts /etc/logrotate.d/httpd-prerotate; \\
        fi \\
    endscript
    postrotate
        invoke-rc.d nginx rotate >/dev/null 2>&1
    endscript
}"""

cert_dir = Path("/srv/kubernetes/")
server_crt_path = cert_dir / "server.crt"
server_key_path = cert_dir / "server.key"


def _nrpe_external(flagname: str) -> str:
    # wokeignore:rule=master
    return f"nrpe-external-master.{flagname}"


@when("certificates.available")
def request_server_certificates():
    """Send the data that is required to create a server certificate for
    this server."""
    # Use the public ip of this unit as the Common Name for the certificate.
    common_name = hookenv.unit_public_ip()

    bind_ips = kubernetes_common.get_bind_addrs(ipv4=True, ipv6=True)

    # Create SANs that the tls layer will add to the server cert.
    sans = [
        # The CN field is checked as a hostname, so if it's an IP, it
        # won't match unless also included in the SANs as an IP field.
        common_name,
        kubernetes_common.get_ingress_address("website"),
        socket.gethostname(),
        socket.getfqdn(),
    ] + bind_ips
    forced_lb_ips = hookenv.config("loadbalancer-ips").split()
    if forced_lb_ips:
        sans.extend(forced_lb_ips)
    else:
        hacluster = endpoint_from_flag("ha.connected")
        if hacluster:
            vips = hookenv.config("ha-cluster-vip").split()
            dns_record = hookenv.config("ha-cluster-dns")
            if vips:
                sans.extend(vips)
            elif dns_record:
                sans.append(dns_record)

    # maybe they have extra names they want as SANs
    extra_sans = hookenv.config("extra_sans")
    if extra_sans and not extra_sans == "":
        sans.extend(extra_sans.split())
    # Request a server cert with this information.
    tls_client.request_server_cert(
        common_name,
        sorted(set(sans)),
        crt_path=server_crt_path,
        key_path=server_key_path,
    )


@when("certificates.server.cert.available", "nginx.available")
@when_any("tls_client.certs.changed", "tls_client.ca.written")
def kick_nginx(tls):
    # certificate changed, so sighup nginx
    hookenv.log("Certificate information changed, sending SIGHUP to nginx")
    host.service_restart("nginx")
    clear_flag("tls_client.certs.changed")
    clear_flag("tls_client.ca.written")


@when("config.changed.port")
def close_old_port():
    config = hookenv.config()
    old_port = config.previous("port")
    if not old_port:
        return
    try:
        hookenv.close_port(old_port)
    except CalledProcessError:
        hookenv.log("Port %d already closed, skipping." % old_port)


def maybe_write_apilb_logrotate_config():
    filename = "/etc/logrotate.d/apilb_nginx"
    if not os.path.exists(filename):
        # Set log rotation for apilb log file
        with open(filename, "w+") as fp:
            fp.write(apilb_nginx)


def allow_lb_consumers_to_read_requests():
    lb_consumers = endpoint_from_name("lb-consumers")
    lb_consumers.follower_perms(read=True)
    return lb_consumers


@when("nginx.available", "tls_client.certs.saved")
@when_any("endpoint.lb-consumers.joined", "apiserver.available")
@when_not("upgrade.series.in-progress")
def install_load_balancer():
    """Create the default vhost template for load balancing"""
    apiserver = endpoint_from_name("apiserver")
    lb_consumers = allow_lb_consumers_to_read_requests()

    if not (server_crt_path.exists() and server_key_path.exists()):
        hookenv.log("Skipping due to missing cert")
        return
    if not (apiserver.services() or lb_consumers.all_requests):
        hookenv.log("Skipping due to requests not ready")
        return

    # At this point the cert and key exist, and they are owned by root.
    chown = ["chown", "www-data:www-data", str(server_crt_path)]

    # Change the owner to www-data so the nginx process can read the cert.
    subprocess.call(chown)
    chown = ["chown", "www-data:www-data", str(server_key_path)]

    # Change the owner to www-data so the nginx process can read the key.
    subprocess.call(chown)

    servers = {}
    if apiserver and apiserver.services():
        servers[hookenv.config("port")] = {
            (h["hostname"], h["port"])
            for service in apiserver.services()
            for h in service["hosts"]
        }
    for request in lb_consumers.all_requests:
        for server_port in request.port_mapping.keys():
            service = servers.setdefault(server_port, set())
            service.update(
                (backend, backend_port)
                for backend, backend_port in itertools.product(
                    request.backends, request.port_mapping.values()
                )
            )
    nginx.configure_site(
        "apilb",
        "apilb.conf",
        servers=servers,
        server_certificate=str(server_crt_path),
        server_key=str(server_key_path),
        proxy_read_timeout=hookenv.config("proxy_read_timeout"),
    )

    maybe_write_apilb_logrotate_config()
    for listen_port in servers.keys():
        hookenv.open_port(listen_port)
    status.active("Loadbalancer ready.")


@hook("upgrade-charm")
def upgrade_charm():
    if is_state("certificates.available") and is_state("website.available"):
        request_server_certificates()
    maybe_write_apilb_logrotate_config()


@hook("pre-series-upgrade")
def pre_series_upgrade():
    host.service_pause("nginx")
    status.blocked("Series upgrade in progress")


@hook("post-series-upgrade")
def post_series_upgrade():
    host.service_resume("nginx")


@when("nginx.available")
def set_nginx_version():
    """Surface the currently deployed version of nginx to Juju"""
    cmd = "nginx -v"
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    raw = p.stdout.read()
    # The version comes back as:
    # nginx version: nginx/1.10.0 (Ubuntu)
    version = raw.split(b"/")[-1].split(b" ")[0]
    hookenv.application_version_set(version.rstrip())


def _get_lb_addresses() -> List[str]:
    forced_lb_ips = hookenv.config("loadbalancer-ips").split()
    if forced_lb_ips:
        return forced_lb_ips

    if endpoint_from_flag("ha.connected"):
        # in the hacluster world, we dump the vip or the dns
        # on every unit's data. This is because the
        # kubernetes-control-plane charm just grabs the first
        # one it sees and uses that ip/dns.
        vips = hookenv.config("ha-cluster-vip").split()
        if vips:
            return vips

        dns_records = hookenv.config("ha-cluster-dns").split()
        if dns_records:
            return dns_records
    return []


def _get_lb_port(prefer_private=True):
    lb_consumers = endpoint_from_name("lb-consumers")

    # prefer a port from the newer, more explicit relations
    public = filter(lambda r: r.public, lb_consumers.all_requests)
    private = filter(lambda r: not r.public, lb_consumers.all_requests)
    lb_reqs = (private, public) if prefer_private else (public, private)
    for lb_req in itertools.chain(*lb_reqs):
        return list(lb_req.port_mapping)[0]

    # fall back to the config
    return hookenv.config("port")


@when("endpoint.lb-consumers.joined", "leadership.is_leader")
def provide_lb_consumers():
    """Respond to any LB requests via the lb-consumers relation.

    This is used in favor for the more complex two relation setup using the
    website and loadbalancer relations going forward.
    """
    lb_consumers = endpoint_from_name("lb-consumers")
    lb_addresses = _get_lb_addresses()
    for request in lb_consumers.all_requests:
        response = request.response
        if request.protocol not in (
            request.protocols.tcp,
            request.protocols.http,
            request.protocols.https,
        ):
            response.error_type = response.error_types.unsupported
            response.error_fields = {
                "protocol": "Protocol must be one of: tcp, http, https"
            }
            lb_consumers.send_response(request)
            continue
        if lb_addresses:
            private_address = lb_addresses[0]
            public_address = lb_addresses[0]
        else:
            network_info = hookenv.network_get("lb-consumers", str(request.relation.id))
            private_address = network_info["ingress-addresses"][0]
            public_address = hookenv.unit_get("public-address")
        if request.public:
            response.address = public_address
        else:
            response.address = private_address
        lb_consumers.send_response(request)


@when("website.available")
def provide_application_details():
    """re-use the nginx layer website relation to relay the hostname/port
    to any consuming kubernetes-workers, or other units that require the
    kubernetes API"""
    website = endpoint_from_flag("website.available")
    lb_addresses = _get_lb_addresses()
    lb_port = _get_lb_port(prefer_private=True)
    if lb_addresses:
        website.configure(
            port=lb_port, private_address=lb_addresses[0], hostname=lb_addresses[0]
        )
    else:
        website.configure(port=lb_port)


@when("loadbalancer.available")
def provide_loadbalancing():
    """Send the public address and port to the public-address interface, so
    the subordinates can get the public address of this loadbalancer."""
    loadbalancer = endpoint_from_flag("loadbalancer.available")
    lb_addresses = _get_lb_addresses()
    lb_port = _get_lb_port(prefer_private=False)
    if not lb_addresses:
        lb_addresses = [hookenv.unit_get("public-address")]
    loadbalancer.set_address_port(lb_addresses[0], lb_port)


@when(_nrpe_external("available"))
@when_not(_nrpe_external("initial-config"))
def initial_nrpe_config(nagios=None):
    set_flag(_nrpe_external("initial-config"))
    update_nrpe_config(nagios)


@when("nginx.available")
@when(_nrpe_external("available"))
@when_any("config.changed.nagios_context", "config.changed.nagios_servicegroups")
def update_nrpe_config(unused=None):
    services = ("nginx",)

    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.add_init_service_checks(nrpe_setup, services, current_unit)
    nrpe_setup.write()


@when_not(_nrpe_external("available"))
@when(_nrpe_external("initial-config"))
def remove_nrpe_config(nagios=None):
    clear_flag(_nrpe_external("initial-config"))

    # List of systemd services for which the checks will be removed
    services = ("nginx",)

    # use the charm-helpers code for now.
    hostname = nrpe.get_nagios_hostname()
    nrpe_setup = nrpe.NRPE(hostname=hostname)

    for service in services:
        nrpe_setup.remove_check(shortname=service)


@when("nginx.available", "ha.connected")
def configure_hacluster():
    add_service_to_hacluster("nginx", "nginx")
    set_flag("hacluster-configured")


@when_not("ha.connected")
@when("hacluster-configured")
def remove_hacluster():
    remove_service_from_hacluster("nginx", "nginx")
    clear_flag("hacluster-configured")
