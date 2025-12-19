# This script simply picks a random OQS or non-OQS key-exchange
# and signature algorithm, and checks whether the stock BoringSSL
# client and server can establish a handshake with the choices.

import argparse
import random
import subprocess
import time

kexs = [
        'prime256v1',
        'x25519',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEMS_START
        'bikel3',
        'p384_bikel3',
        'bikel5',
        'p521_bikel5',
        'frodo1344aes',
        'p521_frodo1344aes',
        'frodo1344shake',
        'p521_frodo1344shake',
        'frodo640aes',
        'p256_frodo640aes',
        'x25519_frodo640aes',
        'frodo640shake',
        'p256_frodo640shake',
        'x25519_frodo640shake',
        'frodo976aes',
        'p384_frodo976aes',
        'frodo976shake',
        'p384_frodo976shake',
        'p384_mlkem1024',
        'p521_mlkem1024',
        'mlkem512',
        'p256_mlkem512',
        'mlkem768',
        'p256_mlkem768',
        'p384_mlkem768',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEMS_END
]

sigs = [
        'prime256v1',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
        'CROSSrsdp128balanced',
        'OV_Ip_pkc',
        'OV_Ip_pkc_skc',
        'falcon1024',
        'falcon512',
        'rsa3072_falcon512',
        'falconpadded1024',
        'falconpadded512',
        'mayo1',
        'mayo2',
        'mayo3',
        'mayo5',
        'mldsa44',
        'p256_mldsa44',
        'mldsa65',
        'p384_mldsa65',
        'mldsa87',
        'p521_mldsa87',
        'snova2454',
        'snova2454esk',
        'snova37172',
        'snova2455',
        'snova2965',
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
        'slhdsapuresha2128s',
        'slhdsapuresha2128f',
        'slhdsapuresha2192s',
        'slhdsapuresha2192f',
        'slhdsapuresha2256s',
        'slhdsapuresha2256f',
        'slhdsapureshake128s',
        'slhdsapureshake128f',
        'slhdsapureshake192s',
        'slhdsapureshake192f',
        'slhdsapureshake256s',
        'slhdsapureshake256f',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_END
]

def try_handshake(bssl):
    random_sig = random.choice(sigs)
    random_kex = random.choice(kexs)
    server = subprocess.Popen([bssl, 'server',
                                     '-accept', '26150',
                                     '-curves', random_kex,
                                     '-sig-alg', random_sig],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)

    # The server should (hopefully?) start
    # in 10 seconds.
    time.sleep(10)

    # Try to connect to it with the client
    client = subprocess.run([bssl, 'client',
                                   '-connect', 'localhost:26150',
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
                                default='build/bssl',
                                help='Path to the bssl executable')

    args = parser.parse_args()
    try_handshake(args.bssl)
