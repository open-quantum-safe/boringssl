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
        'oqs_kem_default',
        'bike1l1cpa',
        'bike1l3cpa',
        'bike1l1fo',
        'bike1l3fo',
        'frodo640aes',
        'frodo640shake',
        'frodo976aes',
        'frodo976shake',
        'frodo1344aes',
        'frodo1344shake',
        'kyber512',
        'kyber768',
        'kyber1024',
        'kyber90s512',
        'kyber90s768',
        'kyber90s1024',
        'ntru_hps2048509',
        'ntru_hps2048677',
        'ntru_hps4096821',
        'ntru_hrss701',
        'lightsaber',
        'saber',
        'firesaber',
        'sidhp434',
        'sidhp503',
        'sidhp610',
        'sidhp751',
        'sikep434',
        'sikep503',
        'sikep610',
        'sikep751',
        'hqc128_1_cca2',
        'hqc192_1_cca2',
        'hqc192_2_cca2',
        'hqc256_1_cca2',
        'hqc256_2_cca2',
        'hqc256_3_cca2',
        'ntrulpr653',
        'ntrulpr761',
        'ntrulpr857',
        'sntrup653',
        'sntrup761',
        'sntrup857',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEMS_END
]

sigs = [
        'prime256v1',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
        'oqs_sig_default',
        'dilithium2',
        'dilithium3',
        'dilithium4',
        'falcon512',
        'falcon1024',
        'picnicl1fs',
        'picnicl1ur',
        'picnicl1full',
        'picnic3l1',
        'picnic3l3',
        'picnic3l5',
        'rainbowIaclassic',
        'rainbowIacyclic',
        'rainbowIacycliccompressed',
        'rainbowIIIcclassic',
        'rainbowIIIccyclic',
        'rainbowIIIccycliccompressed',
        'rainbowVcclassic',
        'rainbowVccyclic',
        'rainbowVccycliccompressed',
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
