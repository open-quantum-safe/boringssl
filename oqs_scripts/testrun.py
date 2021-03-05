import json
import sys
import subprocess
import os
import time

# Parameter checks already done in shellscript

with open("assignments.json", "r") as f:
   jsoncontents = f.read();

onlysigoutput = False
if len(sys.argv)>1:
   onlysigoutput=True

assignments = json.loads(jsoncontents)
for sig in assignments:
    print("Testing %s:" % (sig))
    for kem in assignments[sig]:
       # assemble testing command
       cmd = "(echo \'GET /\'; sleep 0.2) | ../build/tool/bssl client -connect test.openquantumsafe.org:"+str(assignments[sig][kem]) + " -root-certs CA.crt 2>&1"
       if kem!="*": # don't prescribe KEM
          cmd=cmd+" -curves "+kem
       output = os.popen(cmd).read()
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


