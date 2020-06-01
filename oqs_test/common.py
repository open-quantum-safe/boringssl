import psutil
import subprocess
import time

SERVER_START_TIMEOUT = 100

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
        'p256_ntru_hrss701': '12055',
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
        'mqdss3164': '65249',
        'picnicl1fs': '65043',
        'picnicl1ur': '65250',
        'picnic2l1fs': '65046',
        'picnic2l3fs': '65251',
        'picnic2l5fs': '65252',
        'qteslapi': '65049',
        'qteslapiii': '65052',
        'rainbowIaclassic': '65253',
        'rainbowIacyclic': '65254',
        'rainbowIacycliccompressed': '65255',
        'rainbowIIIcclassic': '65256',
        'rainbowIIIccyclic': '65257',
        'rainbowIIIccycliccompressed': '65258',
        'rainbowVcclassic': '65259',
        'rainbowVccyclic': '65260',
        'rainbowVccycliccompressed': '65261',
        'sphincsharaka128frobust': '65262',
        'sphincsharaka128fsimple': '65263',
        'sphincsharaka128srobust': '65264',
        'sphincsharaka128ssimple': '65265',
        'sphincsharaka192frobust': '65266',
        'sphincsharaka192fsimple': '65267',
        'sphincsharaka192srobust': '65268',
        'sphincsharaka192ssimple': '65269',
        'sphincsharaka256frobust': '65270',
        'sphincsharaka256fsimple': '65271',
        'sphincsharaka256srobust': '65272',
        'sphincsharaka256ssimple': '65273',
        'sphincssha256128frobust': '65274',
        'sphincssha256128fsimple': '65275',
        'sphincssha256128srobust': '65276',
        'sphincssha256128ssimple': '65277',
        'sphincssha256192frobust': '65278',
        'sphincssha256192fsimple': '65279',
        'sphincssha256192srobust': '65280',
        'sphincssha256192ssimple': '61697',
        'sphincssha256256frobust': '65282',
        'sphincssha256256fsimple': '65283',
        'sphincssha256256srobust': '65284',
        'sphincssha256256ssimple': '65285',
        'sphincsshake256128frobust': '65286',
        'sphincsshake256128fsimple': '65287',
        'sphincsshake256128srobust': '65288',
        'sphincsshake256128ssimple': '65289',
        'sphincsshake256192frobust': '65290',
        'sphincsshake256192fsimple': '65291',
        'sphincsshake256192srobust': '65292',
        'sphincsshake256192ssimple': '65293',
        'sphincsshake256256frobust': '65294',
        'sphincsshake256256fsimple': '65295',
        'sphincsshake256256srobust': '65296',
        'sphincsshake256256ssimple': '65297',
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

    # Wait SERVER_START_TIMEOUT seconds
    # for server to bind to port.
    timeout_start = time.time()
    while time.time() < timeout_start + SERVER_START_TIMEOUT:
        if server_info.connections():
            break
    server_port = str(server_info.connections()[0].laddr.port)

    # Wait SERVER_START_TIMEOUT seconds
    # for server to be responsive.
    server_up = False
    timeout_start = time.time()
    while time.time() < timeout_start + SERVER_START_TIMEOUT:
        result = subprocess.run([bssl_shim, '-port', server_port, '-shim-shuts-down'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        if result.returncode == 0: #Server should be responsive now
            server_up = True
            break

    if not server_up:
        raise Exception('Cannot start bssl server')

    return server, server_port

