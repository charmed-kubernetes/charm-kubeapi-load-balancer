#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import shlex
from pathlib import Path

import pytest
import yaml

log = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test):
    charm = next(Path().glob("kubeapi*.charm"), None)
    if not charm:
        log.info("Build Charm...")
        charm = await ops_test.build_charm(".")

    resource_path = ops_test.tmp_path / "charm-resources"
    resource_path.mkdir()
    resource_build_script = Path("./build-resources.sh").resolve()
    log.info("Building charm resources")
    retcode, stdout, stderr = await ops_test.run(str(resource_build_script), cwd=resource_path)
    if retcode != 0:
        log.error(f"retcode: {retcode}")
        log.error(f"stdout:\n{stdout.strip()}")
        log.error(f"stderr:\n{stderr.strip()}")
        pytest.fail("Failed to build charm resources")

    log.info("Build Bundle...")
    bundle, *overlays = await ops_test.async_render_bundles(
        ops_test.Bundle("kubernetes-core", channel="edge"),
        Path("tests/data/charm.yaml"),
        arch="amd64",
        charm=charm.resolve(),
        resource_path=resource_path,
    )

    log.info("Deploying bundle")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle} " + " ".join(f"--overlay={f}" for f in overlays)
    retcode, stdout, stderr = await ops_test.run(*shlex.split(cmd))

    if retcode != 0:
        log.error(f"retcode: {retcode}")
        log.error(f"stdout:\n{stdout.strip()}")
        log.error(f"stderr:\n{stderr.strip()}")
        pytest.fail("Failed to deploy bundle")

    await ops_test.model.wait_for_idle(status="active", timeout=60 * 60)


async def test_load_balancer_forced_address(ops_test):
    """Validate that the first forced address is passed in lb-consumers relation."""
    api_lb = ops_test.model.applications["kubeapi-load-balancer"]
    address = api_lb.units[0].data["public-address"]
    await api_lb.set_config({"loadbalancer-ips": address})
    await ops_test.model.wait_for_idle(status="active", timeout=10 * 60)

    try:
        worker = ops_test.model.applications["kubernetes-worker"]
        action = await worker.units[0].run("cat /root/cdk/kubeproxyconfig | grep server")
        result = await action.wait()
        assert f"https://{address}" in result.results["stdout"]
    finally:
        await api_lb.reset_config(["loadbalancer-ips"])
        await ops_test.model.wait_for_idle(status="active", timeout=10 * 60)


async def test_load_balancer_metrics(ops_test):
    """Validate that the node metrics are available."""
    api_lb = ops_test.model.applications["kubeapi-load-balancer"]

    action = await api_lb.units[0].run("curl http://localhost:8080/status")
    result = await action.wait()
    assert "Active connections: " in result.results["stdout"], "Nginx Status stub unavailable"

    action = await api_lb.units[0].run("curl http://localhost:9113/metrics")
    result = await action.wait()
    assert "nginx_up 1" in result.results["stdout"], "Prometheus exporter unavailable"
