[![CircleCI](https://circleci.com/gh/open-quantum-safe/boringssl/tree/master.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/boringssl/tree/master)

OQS-BoringSSL
==================================

[BoringSSL](https://boringssl.googlesource.com/boringssl/) is a fork, maintained by Google, of the [OpenSSL](https://www.openssl.org/) cryptographic library. ([View the original README](README).)

OQS-BoringSSL is a fork of BoringSSL that adds quantum-safe key exchange and authentication algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by Google.

- [Overview](#overview)
- [Status](#status)
  * [Limitations and Security](#limitations-and-security)
  * [Supported Algorithms](#supported-algorithms)
- [Quickstart](#quickstart)
  * [Building](#building)
    * [Linux](#linux)
  * [Running](#running)
- [Team](#team)
- [Acknowledgements](#acknowledgements)

## Overview

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms. See [here](https://github.com/open-quantum-safe/liboqs/) for more information.

**OQS-BoringSSL** is a fork that integrates liboqs into BoringSSL so as to facilitate the evaluation of quantum-safe cryptography in the TLS 1.3 protocol.
Both liboqs and this fork are part of the **Open Quantum Safe (OQS) project**, which aims to develop and prototype quantum-safe cryptography. More information about the project can be found [here](https://openquantumsafe.org/).

## Status

This fork is built on top of [commit 4df6f97](https://github.com/google/boringssl/commit/4df6f97cf9a32770b2a6ffb8da7d97845743ffb7), and adds:

- quantum-safe key exchange to TLS 1.3
- hybrid (quantum-safe + elliptic curve) key exchange to TLS 1.3
- quantum-safe digital signatures to TLS 1.3

**WE DO NOT RECOMMEND RELYING ON THIS FORK IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA.** This fork is at an experimental stage, and BoringSSL does not guarantee API or ABI stability. See the [Limitations and Security](#limitations-and-security) section below for more information.

liboqs and this integration are provided "as is", without warranty of any kind.  See the [LICENSE](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt) for the full disclaimer.

**N.B.: WE DO NOT REGULARLY TEST INTEROPERABILITY WITH [OQS-OPENSSL](https://github.com/open-quantum-safe/openssl), INSTEAD ONLY DOING SO AS AND WHEN THE NEED MIGHT ARISE. AS A CONSEQUENCE, THIS PROJECT, AS WELL AS THE CHROMIUM DEMO THAT IS BUILT ON TOP OF IT, MAY NOT INTEROPERATE WITH OTHER COMPONENTS IN THE OQS INFRASTRUCTURE SUCH AS THE [OQS PROVIDER](https://github.com/open-quantum-safe/oqs-provider) AND THE [OQS TEST SERVER](http://test.openquantumsafe.org/).**

### Limitations and security

As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms, and strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying quantum-safe cryptography.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this fork, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project.

We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the standardization project.  We strongly recommend such attempts make use of so-called **hybrid cryptography**, in which quantum-safe public-key algorithms are combined with traditional public key algorithms (like RSA or elliptic curves) such that the solution is at least no less secure than existing traditional cryptography. This fork provides the ability to use hybrid cryptography.

Proofs of TLS such as [[JKSS12]](https://eprint.iacr.org/2011/219) and [[KPW13]](https://eprint.iacr.org/2013/339) require a key exchange mechanism that has a form of active security, either in the form of the PRF-ODH assumption, or an IND-CCA KEM.
Some of the KEMs provided in liboqs do provide IND-CCA security; others do not ([these datasheets](https://github.com/open-quantum-safe/liboqs/tree/main/docs/algorithms) specify which provide what security), in which case existing proofs of security of TLS against active attackers do not apply.

Furthermore, the BoringSSL project does not guarantee API or ABI stability; this fork is maintained primarily to enable the use of quantum-safe cryptography in the [Chromium](https://www.chromium.org/) web browser, which relies on BoringSSL's TLS implementation.

The fork is currently based on commit hash `ae88f198a49d77993e9c44b017d0e69c810dc668` which has been verified to work with Chromium tag `117.0.5863.0`. If we do decide to update BoringSSL, we will do so to the most recent commit that is supported by the desired tag at which we would like Chromium to be. **We consequently also cannot guarantee API or ABI stability for this fork.**

### Supported Algorithms

If an algorithm is provided by liboqs but is not listed below, it might still be possible to use it in the fork through the build mechanism described [here](https://github.com/open-quantum-safe/boringssl/wiki/Using-liboqs-algorithms-not-in-the-fork).

#### Key Exchange

The following quantum-safe algorithms from liboqs are supported (assuming they have been enabled in liboqs):

<!--- OQS_TEMPLATE_FRAGMENT_LIST_KEXS_START -->
- **BIKE**: `bikel1`, `bikel3`
- **CRYSTALS-Kyber**: `kyber512`, `kyber768`, `kyber1024`
- **FrodoKEM**: `frodo640shake`, `frodo976aes`, `frodo976shake`, `frodo1344aes`, `frodo1344shake`
- **HQC**: `hqc128`, `hqc192`, `hqc256`†
<!--- OQS_TEMPLATE_FRAGMENT_LIST_KEXS_END -->

For each `<KEX>` listed above, the following hybrid algorithms are made available as follows:

- If `<KEX>` has L1 security, the method `p256_<KEX>` is available, which combines `<KEX>` with ECDH using NIST's P256 curve
- If `<KEX>` has L3 security, the method `p384_<KEX>` is available, which combines `<KEX>` with ECDH using NIST's P384 curve
- If `<KEX>` has L5 security, the method `p521_<KEX>` is available, which combines `<KEX>` with ECDH using NIST's P521 curve

For example, since `kyber768` claims L3 security, the hybrid `p384_kyber768` is available.

Note that algorithms marked with a dagger (†) have large stack usage and may cause failures when run on threads or in constrained environments.

#### Signatures

The following quantum-safe digital signature algorithms from liboqs are supported (assuming they have been enabled in liboqs):

<!--- OQS_TEMPLATE_FRAGMENT_LIST_SIGS_START -->
- **CRYSTALS-DILITHIUM**: `dilithium3`, `dilithium5`
- **Falcon**: `falcon512`, `falcon1024`
- **SPHINCS-SHA2**: `sphincssha2128fsimple`, `sphincssha2128ssimple`, `sphincssha2192fsimple`, `sphincssha2192ssimple`, `sphincssha2256fsimple`, `sphincssha2256ssimple`
- **SPHINCS-SHAKE**: `sphincsshake128fsimple`, `sphincsshake128ssimple`, `sphincsshake192fsimple`, `sphincsshake192ssimple`, `sphincsshake256fsimple`, `sphincsshake256ssimple`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END -->

No hybrid signature algorithms are currently implemented. If those are needed for a project please use [OQS-OpenSSL](https://github.com/open-quantum-safe/openssl) which supports them out of the box, or implement them and create a pull request, or [create an issue](https://github.com/open-quantum-safe/boringssl/issues).

## Quickstart

We regularly test the fork on Ubuntu 18.04 and above. Support for other platforms and operating systems, as well as for old versions of GCC (< 8) and Clang (< 8), is not guaranteed.

### Building

#### Linux

#### Step 0: Get pre-requisites

On **Ubuntu**, you need to install the following packages:

```
sudo apt install cmake gcc ninja-build libunwind-dev pkg-config python3 python3-psutil golang-go
```

You will also need the latest version of the toolchain for the Go programming language, available [here](https://golang.org/dl/)

Then, get the source code for this fork (`<BORINGSSL_DIR>` is a directory of your choosing):

```
git clone --branch master https://github.com/open-quantum-safe/boringssl.git <BORINGSSL_DIR>
```

#### Step 1: Build and install liboqs

The following instructions will download and build liboqs, then install it to `<BORINGSSL_DIR>/oqs`.

```
git clone --branch main --single-branch --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -G"Ninja" -DCMAKE_INSTALL_PREFIX=<BORINGSSL_DIR>/oqs -DOQS_USE_OPENSSL=OFF ..
ninja
ninja install
```

#### Step 2: Build the fork

Now we follow the standard instructions for building BoringSSL. Navigate to `<BORINGSSL_DIR>`, and:

on **Ubuntu**, run:

```
mkdir build
cd build
cmake -GNinja ..
ninja
```

The fork can also be built with shared libraries, to do so, run `cmake -DBUILD_SHARED_LIBRARIES=ON -GNinja ..`.


#### Step 3: Run tests

To execute the white-box and black-box tests that come with BoringSSL as well the tests for OQS key-exchange and digital signature algorithms, execute `ninja run_tests` from the `build` directory.

### Running

#### TLS demo

BoringSSL contains a basic TLS server (`server`) and TLS client (`client`) which can be used to demonstrate and test TLS connections.

To run a basic TLS server with all liboqs algorithms enabled, from the `build` directory, run:

```
tool/bssl server -accept 4433 -sig-alg <SIG> -loop
```

where `<SIG>` is one of the quantum-safe or hybrid signature algorithms listed in the [Supported Algorithms](#supported-algorithms) section above; if the `sig-alg` option is omitted, the default classical algorithm `ecdhe` with prime curve `X9_62_prime256v1` is used.

In another terminal window, you can run a TLS client requesting one of the supported key-exchange algorithms:

```
tool/bssl client -curves <KEX> -connect localhost:4433
```

where `<KEX>` is one of the quantum-safe or hybrid key exchange algorithms listed in the [Supported Algorithms](#supported-algorithms) section above.

You can also simply run `python3 oqs_scripts/try_handshake.py`, which will pick a random key-exchange and signature algorithm and will attempt a handshake between the TLS server and client with the chosen algorithms.

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to this fork include:

- Christian Paquin (Microsoft Research)
- Goutam Tamvada (University of Waterloo)
- JT (Henan Raytonne Trading Company)

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Canadian Centre for Cyber Security.
We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
