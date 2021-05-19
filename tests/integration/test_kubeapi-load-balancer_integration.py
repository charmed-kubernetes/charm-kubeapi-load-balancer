import logging

import pytest


log = logging.getLogger(__name__)


def _check_status_messages(ops_test):
    """ Validate that the status messages are correct. """
    expected_messages = {
        "kubernetes-master": "Kubernetes master running.",
        "kubernetes-worker": "Kubernetes worker running.",
        "kubeapi-load-balancer": "Loadbalancer ready.",
    }
    for app, message in expected_messages.items():
        for unit in ops_test.model.applications[app].units:
            assert unit.workload_status_message == message


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml", k8s_lb_charm=await ops_test.build_charm(".")
    )
    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)
    _check_status_messages(ops_test)


async def test_kube_api_endpoint(ops_test):
    """ Validate that using the old MITM-style relation works"""
    master = ops_test.model.applications["kubernetes-master"]
    worker = ops_test.model.applications["kubernetes-worker"]
    await master.remove_relation("loadbalancer-internal", "kubeapi-load-balancer")
    await master.remove_relation("loadbalancer-external", "kubeapi-load-balancer")
    await master.add_relation("kube-api-endpoint", "kubeapi-load-balancer")
    await master.add_relation("loadbalancer", "kubeapi-load-balancer")
    await worker.add_relation("kube-api-endpoint", "kubeapi-load-balancer")
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=30 * 60)
    _check_status_messages(ops_test)
