import json
import sys
import subprocess
import os
import pytest
import time
import shutil
import tempfile
import urllib.request

kexs = [
        'prime256v1',
        'x25519',
##### OQS_TEMPLATE_FRAGMENT_LIST_KEMS_START
        'frodo640shake',
        'p256_frodo640shake',
        'frodo976aes',
        'p384_frodo976aes',
        'frodo976shake',
        'p384_frodo976shake',
        'frodo1344aes',
        'p521_frodo1344aes',
        'frodo1344shake',
        'p521_frodo1344shake',
        'bikel1',
        'p256_bikel1',
        'bikel3',
        'p384_bikel3',
        'kyber512',
        'p256_kyber512',
        'kyber768',
        'p384_kyber768',
        'kyber1024',
        'p521_kyber1024',
        'hqc128',
        'p256_hqc128',
        'hqc192',
        'p384_hqc192',
        'hqc256',
        'p521_hqc256',
##### OQS_TEMPLATE_FRAGMENT_LIST_KEMS_END
]

sigs = [
        'ecdsap256',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
        'dilithium2',
        'dilithium3',
        'dilithium5',
        'falcon512',
        'falcon1024',
        'sphincssha2128fsimple',
        'sphincssha2128ssimple',
        'sphincssha2192fsimple',
        'sphincssha2192ssimple',
        'sphincssha2256fsimple',
        'sphincssha2256ssimple',
        'sphincsshake128fsimple',
        'sphincsshake128ssimple',
        'sphincsshake192fsimple',
        'sphincsshake192ssimple',
        'sphincsshake256fsimple',
        'sphincsshake256ssimple',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_END
]

@pytest.fixture(scope="session")
def server_CA_cert(request):
    with urllib.request.urlopen('https://test.openquantumsafe.org/CA.crt') as response:
        with tempfile.NamedTemporaryFile(delete=False) as ca_file:
            shutil.copyfileobj(response, ca_file)
            return ca_file

@pytest.fixture(scope="session")
def server_port_assignments(request):
    with urllib.request.urlopen('https://test.openquantumsafe.org/assignments.json') as response:
       return json.loads(response.read())

@pytest.fixture
def bssl(request):
    return os.path.join('build', 'tool', 'bssl')

@pytest.mark.parametrize('kex', kexs)
@pytest.mark.parametrize('sig', sigs)
def test_sig_kex_pair(sig, kex, bssl, server_CA_cert, server_port_assignments):
    if kex == 'prime256v1':
       server_port = server_port_assignments[sig]["*"]
    elif kex == 'x25519':
       server_port = server_port_assignments[sig]['X25519']
    else:
       server_port = server_port_assignments[sig][kex]

    client = subprocess.Popen([bssl, "client",
                                     "-connect",
                                       "test.openquantumsafe.org:"+str(server_port),
                                     "-curves", kex,
                                     "-root-certs",  server_CA_cert.name],
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    time.sleep(1.5)
    stdout, stderr = client.communicate(input="GET /\n".encode())
    assert client.returncode == 0, stderr.decode("utf-8")
    assert "Successfully connected using".format(sig, kex) in stdout.decode("utf-8"), stdout.decode("utf-8")

