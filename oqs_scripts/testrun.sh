#!/bin/bash

if [ ! -f build/tool/bssl ]; then
   echo "Test executable not available at 'build/tool/bssl'. Exiting."
   exit 1
fi

rm -rf testrun && mkdir testrun && cd testrun

# pull current CA cert
wget https://test.openquantumsafe.org/CA.crt

# pull list of algs/ports
wget https://test.openquantumsafe.org/assignments.json

# execute test
python3 ../oqs_scripts/testrun.py ${1}
