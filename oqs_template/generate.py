#!/usr/bin/env python3

import copy
import glob
import jinja2
import jinja2.ext
import os
import shutil
import subprocess
import yaml

# For list.append in Jinja templates
Jinja2 = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."),extensions=['jinja2.ext.do'])

def file_get_contents(filename, encoding=None):
    with open(filename, mode='r', encoding=encoding) as fh:
        return fh.read()

def file_put_contents(filename, s, encoding=None):
    with open(filename, mode='w', encoding=encoding) as fh:
        fh.write(s)

def populate(filename, config, delimiter):
    fragments = glob.glob(os.path.join('oqs_template', filename, '*.fragment'))
    contents = file_get_contents(filename)

    for fragment in fragments:
        identifier = os.path.splitext(os.path.basename(fragment))[0]

        if filename == 'README.md':
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START -->'.format(delimiter, identifier.upper())
        else:
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START'.format(delimiter, identifier.upper())

        identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END'.format(delimiter, identifier.upper())

        preamble = contents[:contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end):]

        contents = preamble + identifier_start + Jinja2.get_template(fragment).render({'config': config}) + postamble

    file_put_contents(filename, contents)

def load_config():
    config = file_get_contents(os.path.join('oqs_template', 'generate.yml'), encoding='utf-8')
    config = yaml.safe_load(config)
    return config

config = load_config()

# kems
populate('ssl/s3_both.cc', config, '/////')
populate('ssl/ssl_key_share.cc', config, '/////')
populate('ssl/test/fuzzer.h', config, '/////')
populate('ssl/test/test_config.cc', config, '/////')

# sigs
populate('crypto/evp/p_oqs_asn1.c', config, '/////')
populate('crypto/evp/evp_ctx.c', config, '/////')
populate('crypto/evp/evp.c', config, '/////')
populate('crypto/evp/internal.h', config, '/////')
populate('crypto/evp/evp_asn1.c', config, '/////')
populate('crypto/evp/p_oqs.c', config, '/////')
populate('crypto/x509/algorithm.c', config, '/////')
populate('ssl/ssl_privkey.cc', config, '/////')
populate('include/openssl/evp.h', config, '/////')

# both
populate('crypto/obj/objects.txt', config, '#####')
populate('ssl/ssl_test.cc', config, '/////')
populate('ssl/t1_lib.cc', config, '/////')
populate('include/openssl/ssl.h', config, '/////')
populate('oqs_scripts/try_handshake.py', config, '#####')
populate('oqs_scripts/test_with_interop_server.py', config, '#####')

populate('README.md', config, '<!---')
