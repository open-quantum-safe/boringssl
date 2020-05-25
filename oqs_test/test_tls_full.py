import oqs_algorithms
import pytest
import psutil
import sys
import subprocess
import time

# We pass names instead of numbers
# to the tests to make the output
# more comprehensible.

@pytest.fixture(params=oqs_algorithms.sig_to_code_point.keys())
def parametrized_sig_server(request, bssl):
    # Setup: start bssl server
    server = subprocess.Popen([bssl, 'server',
                                     '-accept', '0',
                                     '-sig-alg', request.param,
                                     '-loop'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
    time.sleep(2)
    server_conn_info = psutil.Process(server.pid).connections()[0]

    # Run tests
    yield request.param, str(server_conn_info.laddr.port)
    # Teardown: stop bssl server
    server.kill()

@pytest.mark.parametrize('kex_name', oqs_algorithms.kex_to_nid.keys())
def test_sig_kem_pair(parametrized_sig_server, bssl_shim, kex_name):
    server_sig = parametrized_sig_server[0]
    server_port = parametrized_sig_server[1]

    result = subprocess.run(
        [bssl_shim, '-port', server_port,
                    '-expect-version', 'TLSv1.3',
                    '-curves', oqs_algorithms.kex_to_nid[kex_name],
                    '-expect-curve-id', oqs_algorithms.kex_to_nid[kex_name],
                    '-expect-peer-signature-algorithm', oqs_algorithms.sig_to_code_point[server_sig],
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
