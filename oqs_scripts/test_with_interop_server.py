#!/usr/bin/env python3
# -*- coding: utf-8 -*

import os, re
import urllib.request
from tempfile import NamedTemporaryFile

kexs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_KEMS_START
        'mlkem768',
        'p256_mlkem768',
        'p384_mlkem768',
        'mlkem1024',
        'p384_mlkem1024',
        'p521_mlkem1024',
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
        'frodo1344aes',
        'p521_frodo1344aes',
        'frodo1344shake',
        'p521_frodo1344shake',
        'kyber512',
        'p256_kyber512',
        'x25519_kyber512',
        'kyber768',
        'p256_kyber768',
        'p384_kyber768',
        'kyber1024',
        'p521_kyber1024',
        'bikel1',
        'p256_bikel1',
        'x25519_bikel1',
        'bikel3',
        'p384_bikel3',
        'bikel5',
        'p521_bikel5',
        'hqc128',
        'p256_hqc128',
        'x25519_hqc128',
        'hqc192',
        'p384_hqc192',
        'hqc256',
        'p521_hqc256',
##### OQS_TEMPLATE_FRAGMENT_LIST_KEMS_END
]

sigs = [
        'ecdsap256',
        'rsa3072',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
        'mldsa44',
        'p256_mldsa44',
        'mldsa65',
        'p384_mldsa65',
        'mldsa87',
        'p521_mldsa87',
        'dilithium2',
        'dilithium3',
        'dilithium5',
        'falcon512',
        'rsa3072_falcon512',
        'falconpadded512',
        'falcon1024',
        'falconpadded1024',
        'mayo1',
        'mayo2',
        'mayo3',
        'mayo5',
        'CROSSrsdp128balanced',
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

rootCert = NamedTemporaryFile().name + ".pem"
urllib.request.urlretrieve("https://test.openquantumsafe.org/CA.crt", rootCert)

linePattern = re.compile(r'<tr>(.*?)</tr>', re.DOTALL)
cellPattern = re.compile(r'<td>(.*?)</td>', re.DOTALL)

with urllib.request.urlopen("https://test.openquantumsafe.org/") as response:
    htmlContent = response.read().decode('utf-8')

lineMatches = linePattern.findall(htmlContent)

errorPorts = []

for lines in lineMatches:
    cellMatches = cellPattern.findall(lines)
    if len(cellMatches) > 2 and cellMatches[0] in sigs and cellMatches[1] in kexs:
        if os.system("../build/tool/bssl client -root-certs " + rootCert + " -curves " + cellMatches[1] + " -connect test.openquantumsafe.org:" + cellMatches[2] + " </dev/null\n") != 0:
            errorPorts.append(cellMatches[2])

os.unlink(rootCert)

if len(errorPorts) > 0:
    print("Following ports are NOT working: ")
    for errorPort in errorPorts:
        print("test.openquantumsafe.org:" + errorPort)
    raise SystemExit(1)
