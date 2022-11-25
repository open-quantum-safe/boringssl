# This script simply picks a random OQS or non-OQS key-exchange
# and signature algorithm, and checks whether the stock BoringSSL
# client and server can establish a handshake with the choices.

import argparse
import psutil
import random
import subprocess
import time

kexs = [
        'prime256v1',
        'x25519',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEMS_START
        'frodo640aes',
        'p256_frodo640aes',
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
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEMS_END
]

sigs = [
        'prime256v1',
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

def try_handshake(bssl):
    random_sig = random.choice(sigs)
    server = subprocess.Popen([bssl, 'server',
                                     '-accept', '0',
                                     '-sig-alg', random_sig],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)

    # The server should (hopefully?) start
    # in 10 seconds.
    time.sleep(10)
    server_port = psutil.Process(server.pid).connections()[0].laddr.port

    # Try to connect to it with the client
    random_kex = random.choice(kexs)
    client = subprocess.run([bssl, 'client',
                                   '-connect', 'localhost:{}'.format(str(server_port)),
                                   '-curves', random_kex],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             input=''.encode())
    print("---bssl server output---")
    print(server.communicate(timeout=5)[0].decode())

    print("---bssl client output---")
    print(client.stdout.decode())

    if client.returncode != 0 or server.returncode != 0:
        raise Exception('Cannot establish a connection with {} and {}'.format(random_kex, random_sig))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test handshake between bssl client and server using a random OQS key-exchange and signature algorithm.')
    parser.add_argument('bssl', type=str,
                                nargs='?',
                                const='1',
                                default='build/tool/bssl',
                                help='Path to the bssl executable')

    args = parser.parse_args()
    try_handshake(args.bssl)
