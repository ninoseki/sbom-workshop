import json
import os
from typing import cast

import psutil
import pytest
import sh

from sbom_workshop.python.site_packages import site_package_to_components


@pytest.fixture
def pid() -> int:
    return os.getpid()


@pytest.fixture
def process(pid: int) -> psutil.Process:
    return psutil.Process(pid)


@pytest.fixture
def site_packages(process: psutil.Process) -> list[str]:
    command = sh.Command(process.exe())

    output = command(
        "-c", "import site;import json;print(json.dumps(site.getsitepackages()))"
    )
    return cast(list[str], json.loads(str(output)))


def test_site_package_to_components(site_packages: list[str]):
    assert site_package_to_components(site_packages[0])
