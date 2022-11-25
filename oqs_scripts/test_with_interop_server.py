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
        'ntru_hps2048509',
        'p256_ntru_hps2048509',
        'ntru_hps2048677',
        'p384_ntru_hps2048677',
        'ntru_hps4096821',
        'p521_ntru_hps4096821',
        'ntru_hps40961229',
        'p521_ntru_hps40961229',
        'ntru_hrss701',
        'p384_ntru_hrss701',
        'ntru_hrss1373',
        'p521_ntru_hrss1373',
        'kyber90s512',
        'p256_kyber90s512',
        'kyber90s768',
        'p384_kyber90s768',
        'kyber90s1024',
        'p521_kyber90s1024',
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
        'dilithium2_aes',
        'dilithium3_aes',
        'dilithium5_aes',
        'falcon512',
        'falcon1024',
        'sphincsharaka128frobust',
        'sphincsharaka128fsimple',
        'sphincsharaka128srobust',
        'sphincsharaka128ssimple',
        'sphincsharaka192frobust',
        'sphincsharaka192fsimple',
        'sphincsharaka192srobust',
        'sphincsharaka192ssimple',
        'sphincsharaka256frobust',
        'sphincsharaka256fsimple',
        'sphincsharaka256srobust',
        'sphincsharaka256ssimple',
        'sphincssha256128frobust',
        'sphincssha256128fsimple',
        'sphincssha256128srobust',
        'sphincssha256128ssimple',
        'sphincssha256192frobust',
        'sphincssha256192fsimple',
        'sphincssha256192srobust',
        'sphincssha256192ssimple',
        'sphincssha256256frobust',
        'sphincssha256256fsimple',
        'sphincssha256256srobust',
        'sphincssha256256ssimple',
        'sphincsshake256128frobust',
        'sphincsshake256128fsimple',
        'sphincsshake256128srobust',
        'sphincsshake256128ssimple',
        'sphincsshake256192frobust',
        'sphincsshake256192fsimple',
        'sphincsshake256192srobust',
        'sphincsshake256192ssimple',
        'sphincsshake256256frobust',
        'sphincsshake256256fsimple',
        'sphincsshake256256srobust',
        'sphincsshake256256ssimple',
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

