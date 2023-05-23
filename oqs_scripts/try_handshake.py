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
