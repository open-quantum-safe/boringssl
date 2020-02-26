import os
import pytest
import subprocess

def pytest_addoption(parser):
    parser.addoption("--bssl", action="store", help="bssl: Path to standalone BoringSSL executable.")
    parser.addoption("--bssl-shim", action="store", help="bssl-shim: Path to BoringSSL shim executable.")

@pytest.fixture
def bssl_shim(request):
    return os.path.join(request.config.getoption("--bssl-shim"))

@pytest.fixture
def bssl(request):
    return os.path.join(request.config.getoption("--bssl"))
