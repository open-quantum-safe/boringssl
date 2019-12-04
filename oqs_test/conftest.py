import os
import pytest
import subprocess

def pytest_addoption(parser):
    parser.addoption("--bssl", action="store", help="bssl: Path to standalone BoringSSL executable.")
    parser.addoption("--bssl_shim", action="store", help="bssl_shim: Path to BoringSSL shim executable.")

@pytest.fixture
def bssl_shim(request):
    return os.path.join(request.config.getoption("--bssl_shim"))

@pytest.fixture(scope="session", autouse=True)
def setup_run_teardown(request):
    # Setup: start bssl server
    bssl = os.path.join(request.config.getoption("--bssl"))
    bssl_server = subprocess.Popen([bssl, 'server',
                                          '-accept', '44433',
                                          '-loop'],
                                    stdout=open(os.devnull),
                                    stderr=open(os.devnull))
    # Run tests
    yield
    # Teardown: stop bssl server
    bssl_server.kill()
