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

import os
import socket
import subprocess

from pathlib import Path

from charms.reactive import when, when_any, when_not
from charms.reactive import set_flag, is_state
from charms.reactive import hook
from charms.reactive import clear_flag, endpoint_from_flag
from charmhelpers.core import hookenv
from charmhelpers.core import host
from charmhelpers.contrib.charmsupport import nrpe

from charms.layer import nginx
from charms.layer import tls_client
from charms.layer.kubernetes_common import get_ingress_address
from charms.layer.hacluster import add_service_to_hacluster
from charms.layer.hacluster import remove_service_from_hacluster

from subprocess import Popen
from subprocess import PIPE
from subprocess import STDOUT
from subprocess import CalledProcessError


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

cert_dir = Path('/srv/kubernetes/')
server_crt_path = cert_dir / 'server.crt'
server_key_path = cert_dir / 'server.key'


@when('certificates.available', 'website.available')
def request_server_certificates():
    '''Send the data that is required to create a server certificate for
    this server.'''
    website = endpoint_from_flag('website.available')
    # Use the public ip of this unit as the Common Name for the certificate.
    common_name = hookenv.unit_public_ip()
    # Create SANs that the tls layer will add to the server cert.
    sans = [
        hookenv.unit_public_ip(),
        get_ingress_address(website.endpoint_name),
        socket.gethostname(),
    ]
    hacluster = endpoint_from_flag('ha.connected')
    if hacluster:
        vips = hookenv.config('ha-cluster-vip').split()
        dns_record = hookenv.config('ha-cluster-dns')
        if vips:
            sans.extend(vips)
        elif dns_record:
            sans.append(dns_record)

    # maybe they have extra names they want as SANs
    extra_sans = hookenv.config('extra_sans')
    if extra_sans and not extra_sans == "":
        sans.extend(extra_sans.split())
    # Request a server cert with this information.
    tls_client.request_server_cert(common_name, sans,
                                   crt_path=server_crt_path,
                                   key_path=server_key_path)


@when('config.changed.extra_sans', 'certificates.available',
      'website.available')
def update_certificate():
    # Using the config.changed.extra_sans flag to catch changes.
    # IP changes will take ~5 minutes or so to propagate, but
    # it will update.
    request_server_certificates()


@when('certificates.server.cert.available',
      'nginx.available', 'tls_client.certs.changed')
def kick_nginx(tls):
    # certificate changed, so sighup nginx
    hookenv.log("Certificate information changed, sending SIGHUP to nginx")
    host.service_restart('nginx')
    clear_flag('tls_client.certs.changed')


@when('config.changed.port')
def close_old_port():
    config = hookenv.config()
    old_port = config.previous('port')
    if not old_port:
        return
    try:
        hookenv.close_port(old_port)
    except CalledProcessError:
        hookenv.log('Port %d already closed, skipping.' % old_port)


def maybe_write_apilb_logrotate_config():
    filename = '/etc/logrotate.d/apilb_nginx'
    if not os.path.exists(filename):
        # Set log rotation for apilb log file
        with open(filename, 'w+') as fp:
            fp.write(apilb_nginx)


@when('nginx.available', 'apiserver.available',
      'tls_client.certs.saved')
def install_load_balancer():
    ''' Create the default vhost template for load balancing '''
    apiserver = endpoint_from_flag('apiserver.available')
    # Do both the key and certificate exist?
    if server_crt_path.exists() and server_key_path.exists():
        # At this point the cert and key exist, and they are owned by root.
        chown = ['chown', 'www-data:www-data', str(server_crt_path)]

        # Change the owner to www-data so the nginx process can read the cert.
        subprocess.call(chown)
        chown = ['chown', 'www-data:www-data', str(server_key_path)]

        # Change the owner to www-data so the nginx process can read the key.
        subprocess.call(chown)

        port = hookenv.config('port')
        hookenv.open_port(port)
        services = apiserver.services()
        nginx.configure_site(
                'apilb',
                'apilb.conf',
                server_name='_',
                services=services,
                port=port,
                server_certificate=str(server_crt_path),
                server_key=str(server_key_path),
                proxy_read_timeout=hookenv.config('proxy_read_timeout')
        )

        maybe_write_apilb_logrotate_config()
        hookenv.status_set('active', 'Loadbalancer ready.')


@hook('upgrade-charm')
def upgrade_charm():
    if is_state('certificates.available') and is_state('website.available'):
        request_server_certificates()
    maybe_write_apilb_logrotate_config()


@when('nginx.available')
def set_nginx_version():
    ''' Surface the currently deployed version of nginx to Juju '''
    cmd = 'nginx -v'
    p = Popen(cmd, shell=True,
              stdin=PIPE,
              stdout=PIPE,
              stderr=STDOUT,
              close_fds=True)
    raw = p.stdout.read()
    # The version comes back as:
    # nginx version: nginx/1.10.0 (Ubuntu)
    version = raw.split(b'/')[-1].split(b' ')[0]
    hookenv.application_version_set(version.rstrip())


@when('website.available')
def provide_application_details():
    ''' re-use the nginx layer website relation to relay the hostname/port
    to any consuming kubernetes-workers, or other units that require the
    kubernetes API '''
    website = endpoint_from_flag('website.available')
    hacluster = endpoint_from_flag('ha.connected')
    if hacluster:
        # in the hacluster world, we dump the vip or the dns
        # on every unit's data. This is because the
        # kubernetes-master charm just grabs the first
        # one it sees and uses that ip/dns.
        vips = hookenv.config('ha-cluster-vip').split()
        dns_record = hookenv.config('ha-cluster-dns')
        if vips:
            website.configure(hookenv.config('port'), vips, vips)
        elif dns_record:
            website.configure(hookenv.config('port'), dns_record, dns_record)
        else:
            website.configure(port=hookenv.config('port'))
    else:
        website.configure(port=hookenv.config('port'))


@when('loadbalancer.available')
def provide_loadbalancing():
    '''Send the public address and port to the public-address interface, so
    the subordinates can get the public address of this loadbalancer.'''
    loadbalancer = endpoint_from_flag('loadbalancer.available')
    hacluster = endpoint_from_flag('ha.connected')
    if hacluster:
        # in the hacluster world, we dump the vip or the dns
        # on every unit's data. This is because the
        # kubernetes-master charm just grabs the first
        # one it sees and uses that ip/dns.
        vips = hookenv.config('ha-cluster-vip').split()
        dns_record = hookenv.config('ha-cluster-dns')
        if vips:
            address = vips
        elif dns_record:
            address = dns_record
        else:
            address = hookenv.unit_get('public-address')
    else:
        address = hookenv.unit_get('public-address')
    loadbalancer.set_address_port(address, hookenv.config('port'))


@when('nrpe-external-master.available')
@when_not('nrpe-external-master.initial-config')
def initial_nrpe_config(nagios=None):
    set_flag('nrpe-external-master.initial-config')
    update_nrpe_config(nagios)


@when('nginx.available')
@when('nrpe-external-master.available')
@when_any('config.changed.nagios_context',
          'config.changed.nagios_servicegroups')
def update_nrpe_config(unused=None):
    services = ('nginx',)

    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.add_init_service_checks(nrpe_setup, services, current_unit)
    nrpe_setup.write()


@when_not('nrpe-external-master.available')
@when('nrpe-external-master.initial-config')
def remove_nrpe_config(nagios=None):
    clear_flag('nrpe-external-master.initial-config')

    # List of systemd services for which the checks will be removed
    services = ('nginx',)

    # The current nrpe-external-master interface doesn't handle a lot of logic,
    # use the charm-helpers code for now.
    hostname = nrpe.get_nagios_hostname()
    nrpe_setup = nrpe.NRPE(hostname=hostname)

    for service in services:
        nrpe_setup.remove_check(shortname=service)


@when('nginx.available', 'ha.connected')
def configure_hacluster():
    add_service_to_hacluster('nginx', 'nginx')
    set_flag('hacluster-configured')


@when_not('ha.connected')
@when('hacluster-configured')
def remove_hacluster():
    remove_service_from_hacluster('nginx', 'nginx')
    clear_flag('hacluster-configured')
