import logging
import pytest
import shlex


log = logging.getLogger(__name__)


def _check_status_messages(ops_test):
    """Validate that the status messages are correct."""
    expected_messages = {
        "kubernetes-control-plane": "Kubernetes control-plane running.",
        "kubernetes-worker": "Kubernetes worker running.",
        "kubeapi-load-balancer": "Loadbalancer ready.",
    }
    for app, message in expected_messages.items():
        for unit in ops_test.model.applications[app].units:
            assert unit.workload_status_message == message


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    log.info("Build Charm...")
    charm = await ops_test.build_charm(".")

    log.info("Build Bundle...")
    bundle = ops_test.render_bundle("tests/data/bundle.yaml", k8s_lb_charm=charm)

    log.info("Deploy Bundle...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)
    _check_status_messages(ops_test)


async def test_kube_api_endpoint(ops_test):
    """Validate that using the old MITM-style relation works"""
    k8s_cp = ops_test.model.applications["kubernetes-control-plane"]
    worker = ops_test.model.applications["kubernetes-worker"]
    await k8s_cp.remove_relation("loadbalancer-internal", "kubeapi-load-balancer")
    await k8s_cp.remove_relation("loadbalancer-external", "kubeapi-load-balancer")
    await k8s_cp.add_relation("kube-api-endpoint", "kubeapi-load-balancer")
    await k8s_cp.add_relation("loadbalancer", "kubeapi-load-balancer")
    await worker.add_relation("kube-api-endpoint", "kubeapi-load-balancer")
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=30 * 60)
    _check_status_messages(ops_test)
