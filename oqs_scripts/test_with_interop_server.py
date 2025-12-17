#!/usr/bin/env python3
# -*- coding: utf-8 -*

import os, re
import urllib.request
from tempfile import NamedTemporaryFile

kexs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_KEMS_START
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
##### OQS_TEMPLATE_FRAGMENT_LIST_KEMS_END
]

sigs = [
        'ecdsap256',
        'rsa3072',
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
        if os.system("../build/bssl client -root-certs " + rootCert + " -curves " + cellMatches[1] + " -connect test.openquantumsafe.org:" + cellMatches[2] + " </dev/null\n") != 0:
            errorPorts.append(cellMatches[2])

os.unlink(rootCert)

if len(errorPorts) > 0:
    print("Following ports are NOT working: ")
    for errorPort in errorPorts:
        print("test.openquantumsafe.org:" + errorPort)
    raise SystemExit(1)
