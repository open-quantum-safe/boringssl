import oqs_algorithms
import pytest
import sys
import subprocess
import time

# We pass names instead of numbers
# to the tests to make the output
# more comprehensible.

kex_names = oqs_algorithms.kex_to_nid.keys()
sig_names = oqs_algorithms.sig_to_code_point.keys()

@pytest.fixture(params=sig_names)
def bssl_server_sig(bssl, request):
    # Setup: start bssl server
    bssl_server = subprocess.Popen([bssl, 'server',
                                          '-accept', '44433',
                                          '-sig-alg', request.param,
                                          '-loop'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
    time.sleep(0.5)
    # Run tests
    yield request.param
    # Teardown: stop bssl server
    bssl_server.kill()

@pytest.mark.parametrize('kex_name', kex_names)
def test_sig_kem_pair(bssl_shim, bssl_server_sig, kex_name):
    result = subprocess.run(
        [bssl_shim, '-port', '44433',
                    '-expect-version', 'TLSv1.3',
                    '-curves', oqs_algorithms.kex_to_nid[kex_name],
                    '-expect-curve-id', oqs_algorithms.kex_to_nid[kex_name],
                    '-expect-peer-signature-algorithm', oqs_algorithms.sig_to_code_point[bssl_server_sig],
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
