import common
import pytest
import sys
import subprocess

# We pass names instead of numbers
# to the tests to make the output
# more comprehensible.

@pytest.fixture(params=common.sig_to_code_point.keys())
def parametrized_sig_server(request, bssl, bssl_shim):
    # Setup
    server, server_port = common.start_server(bssl, bssl_shim, request.param)

    # Run tests
    yield request.param, server_port

    # Teardown: stop bssl server
    server.kill()

@pytest.mark.parametrize('kex_name', common.kex_to_nid.keys())
def test_sig_kem_pair(parametrized_sig_server, bssl_shim, kex_name):
    server_sig = parametrized_sig_server[0]
    server_port = parametrized_sig_server[1]

    result = subprocess.run(
        [bssl_shim, '-port', server_port,
                    '-expect-version', 'TLSv1.3',
                    '-curves', common.kex_to_nid[kex_name],
                    '-expect-curve-id', common.kex_to_nid[kex_name],
                    '-expect-peer-signature-algorithm', common.sig_to_code_point[server_sig],
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
