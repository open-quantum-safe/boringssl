import oqs_algorithms
import pytest
import sys
import subprocess
import time

# We pass names instead of numbers
# to the tests to make the output
# more comprehensible.

@pytest.fixture()
def bssl_server_port(bssl):
    # Setup: start bssl server
    bssl_server = subprocess.Popen([bssl, 'server',
                                          '-accept', '44433',
                                          '-sig-alg', 'oqs_sigdefault',
                                          '-loop'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
    time.sleep(0.5)
    # Run tests
    yield '44433'
    # Teardown: stop bssl server
    bssl_server.kill()

@pytest.mark.parametrize('kex_name', oqs_algorithms.kex_to_nid.keys())
def test_kem(bssl_server_port, bssl_shim, kex_name):
    result = subprocess.run(
        [bssl_shim, '-port', bssl_server_port,
                    '-expect-version', 'TLSv1.3',
                    '-curves', oqs_algorithms.kex_to_nid[kex_name],
                    '-expect-curve-id', oqs_algorithms.kex_to_nid[kex_name],
                    '-expect-peer-signature-algorithm', oqs_algorithms.sig_to_code_point['oqs_sigdefault'],
                    '-shim-shuts-down'
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        print(result.stdout.decode('utf-8'))
        assert False, "Got unexpected return code {}".format(result.returncode)

@pytest.mark.parametrize('sig_name', oqs_algorithms.sig_to_code_point.keys())
def test_sig(bssl, bssl_shim, sig_name):
    bssl_server = subprocess.Popen([bssl, 'server',
                                         '-accept', '44433',
                                         '-sig-alg', sig_name],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
    time.sleep(0.5)
    result = subprocess.run(
        [bssl_shim, '-port', '44433',
                    '-expect-version', 'TLSv1.3',
                    '-curves', oqs_algorithms.kex_to_nid['oqs_kemdefault'],
                    '-expect-curve-id', oqs_algorithms.kex_to_nid['oqs_kemdefault'],
                    '-expect-peer-signature-algorithm', oqs_algorithms.sig_to_code_point[sig_name],
                    '-shim-shuts-down'

        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        print(result.stdout.decode('utf-8'))
        assert False, "Got unexpected return code {}".format(result.returncode)

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
