import psutil
import subprocess
import time

SERVER_START_ATTEMPTS = 60

kex_to_nid = {
##### OQS_TEMPLATE_FRAGMENT_MAP_KEM_TO_NID_START
        'oqs_kem_default': '511',
        'p256_oqs_kem_default': '12287',
        'bike1l1cpa': '518',
        'p256_bike1l1cpa': '12038',
        'bike1l3cpa': '519',
        'p384_bike1l3cpa': '12039',
        'bike1l1fo': '547',
        'p256_bike1l1fo': '12067',
        'bike1l3fo': '548',
        'p384_bike1l3fo': '12068',
        'frodo640aes': '512',
        'p256_frodo640aes': '12032',
        'frodo640shake': '513',
        'p256_frodo640shake': '12033',
        'frodo976aes': '514',
        'p384_frodo976aes': '12034',
        'frodo976shake': '515',
        'p384_frodo976shake': '12035',
        'frodo1344aes': '516',
        'p521_frodo1344aes': '12036',
        'frodo1344shake': '517',
        'p521_frodo1344shake': '12037',
        'kyber512': '527',
        'p256_kyber512': '12047',
        'kyber768': '528',
        'p384_kyber768': '12048',
        'kyber1024': '529',
        'p521_kyber1024': '12049',
        'kyber90s512': '553',
        'p256_kyber90s512': '12073',
        'kyber90s768': '554',
        'p384_kyber90s768': '12074',
        'kyber90s1024': '555',
        'p521_kyber90s1024': '12075',
        'newhope512cca': '530',
        'p256_newhope512cca': '12050',
        'newhope1024cca': '531',
        'p521_newhope1024cca': '12051',
        'ntru_hps2048509': '532',
        'p256_ntru_hps2048509': '12052',
        'ntru_hps2048677': '533',
        'p384_ntru_hps2048677': '12053',
        'ntru_hps4096821': '534',
        'p521_ntru_hps4096821': '12054',
        'ntru_hrss701': '535',
        'p384_ntru_hrss701': '12055',
        'lightsaber': '536',
        'p256_lightsaber': '12056',
        'saber': '537',
        'p384_saber': '12057',
        'firesaber': '538',
        'p521_firesaber': '12058',
        'sidhp434': '539',
        'p256_sidhp434': '12059',
        'sidhp503': '540',
        'p256_sidhp503': '12060',
        'sidhp610': '541',
        'p384_sidhp610': '12061',
        'sidhp751': '542',
        'p521_sidhp751': '12062',
        'sikep434': '543',
        'p256_sikep434': '12063',
        'sikep503': '544',
        'p256_sikep503': '12064',
        'sikep610': '545',
        'p384_sikep610': '12065',
        'sikep751': '546',
        'p521_sikep751': '12066',
        'babybear': '556',
        'p256_babybear': '12076',
        'mamabear': '557',
        'p384_mamabear': '12077',
        'papabear': '558',
        'p521_papabear': '12078',
        'babybearephem': '559',
        'p256_babybearephem': '12079',
        'mamabearephem': '560',
        'p384_mamabearephem': '12080',
        'papabearephem': '561',
        'p521_papabearephem': '12081',
        'hqc128_1_cca2': '562',
        'p256_hqc128_1_cca2': '12082',
        'hqc192_1_cca2': '563',
        'p384_hqc192_1_cca2': '12083',
        'hqc192_2_cca2': '564',
        'p384_hqc192_2_cca2': '12084',
        'hqc256_1_cca2': '565',
        'p521_hqc256_1_cca2': '12085',
        'hqc256_2_cca2': '566',
        'p521_hqc256_2_cca2': '12086',
        'hqc256_3_cca2': '567',
        'p521_hqc256_3_cca2': '12087',
##### OQS_TEMPLATE_FRAGMENT_MAP_KEM_TO_NID_END
}

sig_to_code_point = {
##### OQS_TEMPLATE_FRAGMENT_MAP_SIG_TO_CODEPOINT_START
        'oqs_sig_default': '65024',
        'dilithium2': '65027',
        'dilithium3': '65030',
        'dilithium4': '65033',
        'falcon512': '65035',
        'falcon1024': '65038',
        'mqdss3148': '65040',
        'mqdss3164': '65043',
        'picnicl1fs': '65045',
        'picnicl1ur': '65048',
        'picnicl1full': '65174',
        'picnic3l1': '65051',
        'picnic3l3': '65054',
        'picnic3l5': '65056',
        'qteslapi': '65058',
        'qteslapiii': '65061',
        'rainbowIaclassic': '65063',
        'rainbowIacyclic': '65072',
        'rainbowIacycliccompressed': '65075',
        'rainbowIIIcclassic': '65078',
        'rainbowIIIccyclic': '65080',
        'rainbowIIIccycliccompressed': '65082',
        'rainbowVcclassic': '65084',
        'rainbowVccyclic': '65086',
        'rainbowVccycliccompressed': '65088',
        'sphincsharaka128frobust': '65090',
        'sphincsharaka128fsimple': '65093',
        'sphincsharaka128srobust': '65096',
        'sphincsharaka128ssimple': '65099',
        'sphincsharaka192frobust': '65102',
        'sphincsharaka192fsimple': '65104',
        'sphincsharaka192srobust': '65106',
        'sphincsharaka192ssimple': '65108',
        'sphincsharaka256frobust': '65110',
        'sphincsharaka256fsimple': '65112',
        'sphincsharaka256srobust': '65114',
        'sphincsharaka256ssimple': '65116',
        'sphincssha256128frobust': '65118',
        'sphincssha256128fsimple': '65121',
        'sphincssha256128srobust': '65124',
        'sphincssha256128ssimple': '65127',
        'sphincssha256192frobust': '65130',
        'sphincssha256192fsimple': '65132',
        'sphincssha256192srobust': '65134',
        'sphincssha256192ssimple': '65136',
        'sphincssha256256frobust': '65138',
        'sphincssha256256fsimple': '65140',
        'sphincssha256256srobust': '65142',
        'sphincssha256256ssimple': '65144',
        'sphincsshake256128frobust': '65146',
        'sphincsshake256128fsimple': '65149',
        'sphincsshake256128srobust': '65152',
        'sphincsshake256128ssimple': '65155',
        'sphincsshake256192frobust': '65158',
        'sphincsshake256192fsimple': '65160',
        'sphincsshake256192srobust': '65162',
        'sphincsshake256192ssimple': '65164',
        'sphincsshake256256frobust': '65166',
        'sphincsshake256256fsimple': '65168',
        'sphincsshake256256srobust': '65170',
        'sphincsshake256256ssimple': '65172',
##### OQS_TEMPLATE_FRAGMENT_MAP_SIG_TO_CODEPOINT_END
}

def start_server(bssl, bssl_shim, sig_alg):
    server = subprocess.Popen([bssl, 'server',
                                     '-accept', '0',
                                     '-sig-alg', sig_alg,
                                     '-loop'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)

    server_info = psutil.Process(server.pid)

    # Try SERVER_START_ATTEMPTS times to see
    # what port the server is bound to.
    server_start_attempt = 1
    while server_start_attempt <= SERVER_START_ATTEMPTS:
        if server_info.connections():
            break
        else:
            server_start_attempt += 1
            time.sleep(2)
    server_port = str(server_info.connections()[0].laddr.port)

    # Check SERVER_START_ATTEMPTS times to see
    # if the server is responsive.
    server_start_attempt = 1
    while server_start_attempt <= SERVER_START_ATTEMPTS:
        result = subprocess.run([bssl_shim, '-port', server_port, '-shim-shuts-down'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        if result.returncode == 0:
            break
        else:
            server_start_attempt += 1
            time.sleep(2)

    if server_start_attempt > SERVER_START_ATTEMPTS:
        raise Exception('Cannot start OpenSSL server')

    return server, server_port

