"""NGINX helper module."""

import logging
import os
from pathlib import Path

import charms.operator_libs_linux.v0.apt as apt
import ops
import toml
from jinja2 import Template
from ops.framework import Object
from ops.model import MaintenanceStatus

HOST = "127.0.0.1"
PORT = "80"

PACKAGE = "nginx-full"

log = logging.getLogger(__name__)


class NginxConfigurer(Object):
    """A class for managing Nginx configuration for a charm."""

    def __init__(self, charm: ops.CharmBase, config):
        super().__init__(charm, "nginx")
        self.package = apt.add_package(PACKAGE, update_cache=True)
        self.charm = charm
        self.config = config

        self.framework.observe(self.charm.on.upgrade_charm, self._upgrade_nginx)

    def _get_app_path(self):
        site = self._load_site()
        return site.get("app_path", "/srv/app")

    def _load_site(self) -> dict:
        config = {}
        config_file = "site.toml"

        if os.path.isfile(config_file):
            with open(config_file, "r") as f:
                config = toml.load(f)
        return config

    def _render_template(self, template_file: Path, dest: Path, context: dict):
        with open(template_file) as f:
            template = Template(f.read())

        rendered_template = template.render(context)
        with open(dest, "w") as f:
            f.write(rendered_template)

    def _upgrade_nginx(self, _):
        try:
            self.package.ensure(apt.PackageState.Latest)
        except apt.PackageError:
            log.exception(f"Could not install package {PACKAGE}")

    def configure_site(self, site, template, **kwargs):
        """Configure an Nginx site using the specified template and context.

        Args:
            site (str): The name of the site to be configured.
            template (Path): The path to the template file for the Nginx site configuration.
            **kwargs (dict): Additional context variables to be used in the template.
        """
        self.charm.unit.status = MaintenanceStatus(f"Configuring site {site}")

        context = self._load_site()
        context.update(**kwargs)
        conf_path = Path(f"/etc/nginx/sites-available/{site}")
        if conf_path.exists():
            conf_path.unlink()
        self._render_template(template_file=template, dest=conf_path, context=context)
        symlink_path = Path(f"/etc/nginx/sites-enabled/{site}")
        if symlink_path.exists():
            symlink_path.unlink()
        symlink_path.symlink_to(conf_path)
        log.info(f"Site {site} updated. Saved vhost config to nginx config paths.")

    def remove_default_site(self):
        """Remove the default Nginx site configuration if it exists."""
        site_path = Path("/etc/nginx/sites-enabled/default")
        if site_path.exists():
            site_path.unlink()
