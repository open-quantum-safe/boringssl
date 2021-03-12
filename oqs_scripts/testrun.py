import json
import sys
import subprocess
import os
import time
import shutil
import tempfile
import urllib.request

sixs = [
       'rsa3072',
       'ecdsap256',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
        'oqs_sig_default',
        'dilithium2',
        'dilithium3',
        'dilithium5',
        'dilithium2_aes',
        'dilithium3_aes',
        'dilithium5_aes',
        'falcon512',
        'falcon1024',
        'picnicl1fs',
        'picnicl1ur',
        'picnicl1full',
        'picnic3l1',
        'picnic3l3',
        'picnic3l5',
        'rainbowIclassic',
        'rainbowIcircumzenithal',
        'rainbowIcompressed',
        'rainbowIIIclassic',
        'rainbowIIIcircumzenithal',
        'rainbowIIIcompressed',
        'rainbowVclassic',
        'rainbowVcircumzenithal',
        'rainbowVcompressed',
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

kexs = [
        'prime256v1',
        'x25519',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEMS_START
        'oqs_kem_default',
        'frodo640aes',
        'frodo640shake',
        'frodo976aes',
        'frodo976shake',
        'frodo1344aes',
        'frodo1344shake',
        'bike1l1cpa',
        'bike1l3cpa',
        'kyber512',
        'kyber768',
        'kyber1024',
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
        'bike1l1fo',
        'bike1l3fo',
        'kyber90s512',
        'kyber90s768',
        'kyber90s1024',
        'hqc128',
        'hqc192',
        'hqc256',
        'ntrulpr653',
        'ntrulpr761',
        'ntrulpr857',
        'sntrup653',
        'sntrup761',
        'sntrup857',
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEMS_END
      ]

with urllib.request.urlopen('https://test.openquantumsafe.org/CA.crt') as response:
    with tempfile.NamedTemporaryFile(delete=False) as ca_file:
        shutil.copyfileobj(response, ca_file)

with urllib.request.urlopen('https://test.openquantumsafe.org/assignments.json') as response:
   jsoncontents = response.read()

onlysigoutput = False
if len(sys.argv)>1:
   onlysigoutput=True

assignments = json.loads(jsoncontents)
for sig in assignments:
  if sig in sixs:
    print("Testing %s:" % (sig))
    for kem in assignments[sig]:
     if kem in kexs:
       # assemble testing command
       cmd = "(echo \'GET /\'; sleep 0.2) | build/tool/bssl client -connect test.openquantumsafe.org:"+str(assignments[sig][kem]) + " -root-certs "+ca_file.name+" 2>&1"
       if kem!="*": # don't prescribe KEM
          cmd=cmd+" -curves "+kem
       output = os.popen(cmd).read()
#       proc = subprocess.Popen([os.path.join("build", "tool", "bssl"), "client", 
#                                     "-connect", "test.openquantumsafe.org:"+str(assignments[sig][kem]),
#                                     "-curves", kem,
#                                     "-root-certs",  ca_file.name])
#       time.sleep(1)
#       output, stderr = proc.communicate(input="GET /\n\n")
       if not ("Successfully" in output):
           print("Error with command '%s': \n%s\n" % (cmd, output))
           if (not onlysigoutput):
               exit(-1)
       else:
          if (not onlysigoutput):
             print("    Tested KEM %s successfully." % (kem))
          else:
             sys.stdout.buffer.write(b".")
             sys.stdout.flush()
    print("\n  Successfully concluded testing "+sig) 
print("All available tests successfully passed.")

