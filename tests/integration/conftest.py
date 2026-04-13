import logging
from pathlib import Path
import pytest_asyncio

log = logging.getLogger(__name__)


@pytest_asyncio.fixture(scope="module")
async def local_charm_path(ops_test) -> Path:
    """Return the path to the local charm."""
    charm = next(Path().glob("kubeapi*.charm"), None)
    if not charm:
        log.info("Build Charm...")
        charm = await ops_test.build_charm(".")
    else:
        # Move charm to the temp path to avoid permission issues
        dest = ops_test.tmp_path / "charms" / charm.name
        log.info(f"Moving existing charm: {charm} to {dest}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        charm.rename(dest)
        charm = dest

    return charm.resolve()
