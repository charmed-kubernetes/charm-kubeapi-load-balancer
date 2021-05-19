from charmhelpers.core import host  # patched

from reactive import load_balancer as handlers


def test_series_upgrade():
    assert host.service_pause.call_count == 0
    assert host.service_resume.call_count == 0
    assert handlers.status.blocked.call_count == 0
    handlers.pre_series_upgrade()
    assert host.service_pause.call_count == 1
    assert host.service_resume.call_count == 0
    assert handlers.status.blocked.call_count == 1
    handlers.post_series_upgrade()
    assert host.service_pause.call_count == 1
    assert host.service_resume.call_count == 1
    assert handlers.status.blocked.call_count == 1
