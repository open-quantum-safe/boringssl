[![CircleCI](https://circleci.com/gh/open-quantum-safe/boringssl/tree/master.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/boringssl/tree/master)

OQS-BoringSSL
==================================

[BoringSSL](https://boringssl.googlesource.com/boringssl/) is a fork, maintained by Google, of the [OpenSSL](https://www.openssl.org/) cryptographic library. ([View the original README](README).)

OQS-BoringSSL is a fork of BoringSSL that adds quantum-safe key exchange and authentication algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by the BoringSSL project or Google.

- [Overview](#overview)
- [Status](#status)
  * [Limitations and Security](#limitations-and-security)
  * [Supported Algorithms](#supported-algorithms)
- [Quickstart](#quickstart)
  * [Building](#building)
    * [Linux](#linux)
  * [Running](#running)
- [API Stability](#api-stability)
- [Team](#team)
- [Acknowledgements](#acknowledgements)

## Overview

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms. See [here](https://github.com/open-quantum-safe/liboqs/) for more information.

**OQS-BoringSSL** is a fork that integrates liboqs into BoringSSL.  The goal of this integration is to provide easy prototyping of quantum-safe cryptography in the TLS 1.3 protocol. (For TLS 1.2, see the [OQS-OpenSSL\_1\_0\_2-stable](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_0_2-stable) branch.)

Both liboqs and this fork are part of the **Open Quantum Safe (OQS) project**, which aims to develop and prototype quantum-safe cryptography. More information about the project can be found [here](https://openquantumsafe.org/).

## Status

This fork is built on top of [commit do41f11](https://github.com/open-quantum-safe/boringssl/commit/d041f11134951ea34c549032d20d041112697e4c), and adds the following:

- quantum-safe key exchange in TLS 1.3
- hybrid (quantum-safe + elliptic curve) key exchange in TLS 1.3

**This fork is at an experimental stage**. The BoringSSL project also does not guarantee API or ABI stability. See the [Limitations and Security](#limitations-and-security) section below for more information.

**We do not recommend relying on this fork in a production environment or to protect any sensitive data.**

liboqs and this integration are provided "as is", without warranty of any kind.  See the [LICENSE](https://github.com/open-quantum-safe/liboqs/blob/master/LICENSE.txt) for the full disclaimer.

### Limitations and security
As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms, and strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying quantum-safe cryptography.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this fork, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project.

We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the standardization project.  We strongly recommend such attempts make use of so-called **hybrid cryptography**, in which quantum-safe public-key algorithms are combined with traditional public key algorithms (like RSA or elliptic curves) such that the solution is at least no less secure than existing traditional cryptography. This fork provides the ability to use hybrid cryptography.

Proofs of TLS such as [[JKSS12]](https://eprint.iacr.org/2011/219) and [[KPW13]](https://eprint.iacr.org/2013/339) require a key exchange mechanism that has a form of active security, either in the form of the PRF-ODH assumption, or an IND-CCA KEM.
Some of the KEMs provided in liboqs do provide IND-CCA security; others do not ([these datasheets](https://github.com/open-quantum-safe/liboqs/tree/master/docs/algorithms) specify which provide what security), in which case existing proofs of security of TLS against active attackers do not apply.

### Supported Algorithms

If an algorithm is provided by liboqs but is not listed below, it can still be used in the fork through [either one of two ways](https://github.com/open-quantum-safe/boringssl/wiki/Using-liboqs-algorithms-not-in-the-fork).

#### Key Exchange

The following quantum-safe algorithms from liboqs are supported (assuming they have been enabled in liboqs):

- `oqs_kem_default` (see [here](https://github.com/open-quantum-safe/boringssl/wiki/Using-liboqs-algorithms-not-in-the-fork#oqsdefault) for what this denotes)
- **FrodoKEM**: `frodo640aes`, `frodo640shake`, `frodo976aes`, `frodo976shake`, `frodo1344aes`, `frodo1344shake`
- **BIKE**: `bike1l1cpa`, `bike1l3cpa`, `bikel1fo`, `bike1l3fo`
- **CRYSTALS-Kyber**: `kyber512`, `kyber768`, `kyber1024`, `kyber90s512`, `kyber90s768`, `kyber90s1024`
- **NewHope**: `newhope512cca`, `newhope1024cca`
- **NTRU**: `ntru_hps2048509`, `ntru_hps2048677`, `ntru_hps4096821`, `ntru_hrss701`
- **SABER**: `lightsaber`, `saber`, `firesaber`
- **SIDH**: `sidhp434`, `sidhp503`, `sidhp610`, `sidhp751`
- **SIKE**: `sikep434`, `sikep503`, `sikep610`, `sikep751`
- **ThreeBears**: `babybear`, `babybear_ephem`, `mamabear`, `mamabear_ephem`, `papabear`, `papabear_ephem`

The following hybrid algorithms are supported depending on the security of each scheme above, denoted by `<KEX>`:

- If `<KEX>` has L1 security, the method `p256_<KEX>` is available, which combines `<KEX>`  with ECDH using NIST's P256 curve:
- If `<KEX>` has L3 security, the method `p384_<KEX>` is available, which combines `<KEX>`  with ECDH using NIST's P384 curve:
- If `<KEX>` has L5 security, the method `p521_<KEX>` is available, which combines `<KEX>`  with ECDH using NIST's P521 curve:

#### Signatures

The following quantum-safe algorithms from liboqs are supported (assuming they have been enabled in liboqs):

- `oqs_sig_default` (see [here](https://github.com/open-quantum-safe/boringssl/wiki/Using-liboqs-algorithms-not-in-the-fork#oqsdefault) for what this denotes)
- `dilithium2`
- `dilithium3`
- `dilithium4`
- `qteslapi`
- `qteslapiii`
- `picnicl1fs`
- `picnic2l1fs`
- `picnic2l1fs`
- `sphincs_haraka_128f_robust`

## Quickstart

The steps below have been confirmed to work on Ubuntu 19.10 (gcc-8.3.0).

### Building

#### Linux

#### Step 0: Get pre-requisites

On **Ubuntu**, you need to install the following packages:

	sudo apt install gcc golang-go cmake ninja python3-pytest python3-pytest-xdist

Then, get source code of this fork (`<BORINGSSL_DIR>` is a directory of your choosing):

	git clone --branch master https://github.com/open-quantum-safe/boringssl.git <BORINGSSL_DIR>

#### Step 1: Build and install liboqs

The following instructions will download and build liboqs, then install it to `<BORINGSSL_DIR>/oqs`.

	git clone --branch master https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	mkdir build && cd build
	cmake -G"Ninja" -DCMAKE_INSTALL_PREFIX=<BORINGSSL_DIR>/oqs -DOQS_USE_OPENSSL=OFF ..
	ninja
	ninja install

#### Step 2: Build the fork

Now we follow the standard instructions for building BoringSSL. Navigate to `<BORINGSSL_DIR>`, and:

on **Ubuntu**, run:

	mkdir build
	cd build
	cmake -GNinja ..
	ninja

The fork can also be built with shared libraries, to do so, run `cmake -DBUILD_SHARED_LIBRARIES=ON -GNinja ..`.

To execute the white-box and black-box tests, run `ninja run_tests` from the `build` directory. These exclude the OQS key-exchange and digital signature algorithms, which can be tested using `ninja run_basic_oqs_tests` and `ninja run_full_oqs_tests`:

- `ninja run_basic_oqs_tests` first tests all key-exchanges with the signature set to `oqs_sigdefault`, and then tests all signatures with the key-exchange algorithm set to `oqs_kemdefault`.
- `ninja run_full_oqs_tests` tests all possible combinations of OQS key-exchange and signature schemes.

### Running

#### TLS demo

BoringSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test TLS connections.

To run a basic TLS server with all libOQS ciphersuites enabled, from the `build` directory, run (where `<SIG>` = one of the quantum-safe or hybrid signature algorithms listed in the [Supported Algorithms](#supported-algorithms) section above; if the `sig-alg` option is omitted, the default classical algorithm `ecdhe` with prime curve `X9_62_prime256v1` is used):

	tool/bssl server -accept 4433 -sig-alg <SIG> -loop

In another terminal window, you can run a TLS client requesting one of the supported ciphersuites (where `<KEX>` = one of the quantum-safe or hybrid key exchange algorithms listed in the [Supported Algorithms](#supported-algorithms) section above):

	tool/bssl client -curves <KEX> -connect localhost:4433

## API Stability

As previously noted, the BoringSSL project does not guarantee API or ABI stability; this fork is maintained primarily to enable the use of quantum-safe cryptography in the [Chromium](https://www.chromium.org/) and [quiche](https://github.com/cloudflare/quiche) projects, both of which rely on BoringSSL's TLS implementation.

This fork is currently based on commit hash `d041f11134951ea34c549032d20d041112697e4c`. If we do decide to update, we will do so to the most recent BoringSSL commit that is supported by the desired commits at which we would like Chromium and quiche to be. We consequently also cannot guarantee API or ABI stability for this fork.

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to this fork include:

- Christian Paquin (Microsoft Research)
- Goutam Tamvada (University of Waterloo)

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, Cisco Systems, evolutionQ, and Microsoft Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
