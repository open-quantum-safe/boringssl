import os
import pytest
import sys
import subprocess

kem_name_to_nid = {
##### OQS_TEMPLATE_FRAGMENT_LIST_KEMS_AND_NIDS_START
        'oqs_kemdefault': '511',
        'p256_oqs_kemdefault': '767',
        'frodo640aes': '512',
        'p256_frodo640aes': '768',
##### OQS_TEMPLATE_FRAGMENT_LIST_KEMS_AND_NIDS_END
}

# We pass kem names instead of
# just NIDs to make the test output
# more comprehensible.
@pytest.mark.parametrize('kem_name', kem_name_to_nid.keys())
def test_kem(bssl_shim, kem_name):
    result = subprocess.run(
        [bssl_shim, '-port', '44433',
                    '-expect-version', 'TLSv1.3',
                    '-curves', kem_name_to_nid[kem_name],
                    '-expect-curve-id', kem_name_to_nid[kem_name],
                    '-shim-shuts-down'
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        print(result.stdout.decode('utf-8'))
        assert False, "Got unexpected return code {}".format(result.returncode)
    return result.stdout.decode('utf-8')

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
