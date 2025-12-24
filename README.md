[![OQS-BoringSSL (Static)](https://github.com/open-quantum-safe/boringssl/actions/workflows/static.yml/badge.svg)](https://github.com/open-quantum-safe/boringssl/actions/workflows/static.yml)
[![OQS-BoringSSL (Shared)](https://github.com/open-quantum-safe/boringssl/actions/workflows/shared.yml/badge.svg)](https://github.com/open-quantum-safe/boringssl/actions/workflows/shared.yml)

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

This fork is built on top of [commit 52b1463](https://github.com/google/boringssl/tree/52b1463b45712c747a810be819a9cd41ab33fc46), and adds:

- quantum-safe key exchange
- hybrid (quantum-safe + elliptic curve) key exchange
- quantum-safe digital signatures
- hybrid (quantum-safe + RSA / elliptic curve) digital signatures

For cryptographic algorithms that are supported natively by BoringSSL, Google's implementation is used; otherwise, the implementation from liboqs is used.

**WE DO NOT RECOMMEND RELYING ON THIS FORK IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA.** This fork is at an experimental stage, and BoringSSL does not guarantee API or ABI stability. See the [Limitations and Security](#limitations-and-security) section below for more information.

liboqs and this integration are provided "as is", without warranty of any kind.  See the [LICENSE](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt) for the full disclaimer.

**N.B.: THIS PROJECT, AS WELL AS THE CHROMIUM DEMO THAT IS BUILT ON TOP OF IT, MAY NOT INTEROPERATE WITH OTHER COMPONENTS IN THE OQS INFRASTRUCTURE SUCH AS THE [OQS PROVIDER](https://github.com/open-quantum-safe/oqs-provider) AND THE [OQS TEST SERVER](http://test.openquantumsafe.org/).**

### Limitations and security

As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms, and strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying quantum-safe cryptography.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this fork, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project.

We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the standardization project.  We strongly recommend such attempts make use of so-called **hybrid cryptography**, in which quantum-safe public-key algorithms are combined with traditional public key algorithms (like RSA or elliptic curves) such that the solution is at least no less secure than existing traditional cryptography. This fork provides the ability to use hybrid cryptography.

Proofs of TLS such as [[JKSS12]](https://eprint.iacr.org/2011/219) and [[KPW13]](https://eprint.iacr.org/2013/339) require a key exchange mechanism that has a form of active security, either in the form of the PRF-ODH assumption, or an IND-CCA KEM.
Some of the KEMs provided in liboqs do provide IND-CCA security; others do not ([these datasheets](https://github.com/open-quantum-safe/liboqs/tree/main/docs/algorithms) specify which provide what security), in which case existing proofs of security of TLS against active attackers do not apply.

Furthermore, the BoringSSL project does not guarantee API or ABI stability; this fork is maintained primarily to enable the use of quantum-safe cryptography in the [Chromium](https://www.chromium.org/) web browser, which relies on BoringSSL's TLS implementation.

If we do decide to update BoringSSL, we will do so to the most recent commit that is supported by the desired tag at which we would like Chromium to be. **We consequently also cannot guarantee API or ABI stability for this fork.**

### Supported Algorithms

If an algorithm is provided by liboqs but is not listed below, it might still be possible to use it in the fork through the build mechanism described [here](https://github.com/open-quantum-safe/boringssl/wiki/Using-liboqs-algorithms-not-in-the-fork).

#### Key Exchange

Along with `X25519MLKEM768` and `MLKEM1024` supported by BoringSSL through Google's implementations, this fork also incorporates support for additional quantum-safe algorithms from liboqs (provided they have been enabled in liboqs):

<!--- OQS_TEMPLATE_FRAGMENT_LIST_KEXS_START -->
- **BIKE**: `bikel3`, `p384_bikel3`, `bikel5`, `p521_bikel5`
- **FrodoKEM**: `frodo1344aes`, `p521_frodo1344aes`, `frodo1344shake`, `p521_frodo1344shake`, `frodo640aes`, `p256_frodo640aes`, `x25519_frodo640aes`, `frodo640shake`, `p256_frodo640shake`, `x25519_frodo640shake`, `frodo976aes`, `p384_frodo976aes`, `frodo976shake`, `p384_frodo976shake`
- **ML-KEM**: `p384_mlkem1024`, `p521_mlkem1024`, `mlkem512`, `p256_mlkem512`, `mlkem768`, `p256_mlkem768`, `p384_mlkem768`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_KEXS_END -->

Be aware that hybrid algorithms utlizing `X448` are not supported. If those are needed for a project please use [OQS-provider](https://github.com/open-quantum-safe/oqs-provider) which supports them out of the box, or implement them and create a pull request, or [create an issue](https://github.com/open-quantum-safe/boringssl/issues).

Note that algorithms marked with a dagger (†) have large stack usage and may cause failures when run on threads or in constrained environments.

#### Signatures

The following quantum-safe digital signature algorithms from liboqs are supported (assuming they have been enabled in liboqs):

<!--- OQS_TEMPLATE_FRAGMENT_LIST_SIGS_START -->
- **CROSS**: `CROSSrsdp128balanced`
- **Falcon**: `falcon1024`, `falcon512`, `rsa3072_falcon512`, `falconpadded1024`, `falconpadded512`
- **MAYO**: `mayo1`, `mayo2`, `mayo3`, `mayo5`
- **ML-DSA**: `mldsa44`, `p256_mldsa44`, `mldsa65`, `p384_mldsa65`, `mldsa87`, `p521_mldsa87`
- **SLH-DSA**: `slhdsasha2128s`, `slhdsasha2128f`, `slhdsasha2192s`, `slhdsasha2192f`, `slhdsasha2256s`, `slhdsasha2256f`, `slhdsashake128s`, `slhdsashake128f`, `slhdsashake192s`, `slhdsashake192f`, `slhdsashake256s`, `slhdsashake256f`
- **SNOVA**: `snova2454`, `snova2454esk`, `snova37172`, `snova2455`, `snova2965`
- **SPHINCS-SHA2**: `sphincssha2128fsimple`, `sphincssha2128ssimple`, `sphincssha2192fsimple`, `sphincssha2192ssimple`, `sphincssha2256fsimple`, `sphincssha2256ssimple`
- **SPHINCS-SHAKE**: `sphincsshake128fsimple`, `sphincsshake128ssimple`, `sphincsshake192fsimple`, `sphincsshake192ssimple`, `sphincsshake256fsimple`, `sphincsshake256ssimple`
- **UOV**: `OV_Ip_pkc`, `OV_Ip_pkc_skc`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END -->

## Quickstart

We've only tested the fork on the latest Ubuntu LTS and Windows. This fork has limited support for other platforms and may not function properly.

### Building

#### Linux

#### Step 0: Get pre-requisites

On **Ubuntu**, you need to install the following packages:

```
sudo apt install cmake g++ ninja-build
```

Then, get the source code for this fork (`<BORINGSSL_DIR>` is a directory of your choosing):

```
git clone --branch main --single-branch --depth 1 https://github.com/open-quantum-safe/boringssl.git <BORINGSSL_DIR>
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

For additional build instructions, such as how to build OQS-BoringSSL as a shared library, please refer to [BUILDING.md](https://github.com/open-quantum-safe/boringssl/blob/main/BUILDING.md).

#### Step 3: Run tests

To execute the white-box and black-box tests that come with BoringSSL as well the tests for OQS key-exchange and digital signature algorithms, execute `ninja run_tests` from the `build` directory. You will need the latest version of the toolchain for the [Go](https://golang.org/dl/).

### Running

#### TLS demo

BoringSSL contains a basic TLS server (`server`) and TLS client (`client`) which can be used to demonstrate and test TLS connections.

To run a basic TLS server with all liboqs algorithms enabled, from the `build` directory, run:

```
./bssl server -accept 4433 -sig-alg <SIG> -loop
```

where `<SIG>` is one of the quantum-safe or hybrid signature algorithms listed in the [Supported Algorithms](#supported-algorithms) section above; if the `sig-alg` option is omitted, the default classical algorithm `ecdhe` with prime curve `X9_62_prime256v1` is used.

In another terminal window, you can run a TLS client requesting one of the supported key-exchange algorithms:

```
./bssl client -curves <KEX> -connect localhost:4433
```

where `<KEX>` is one of the quantum-safe or hybrid key exchange algorithms listed in the [Supported Algorithms](#supported-algorithms) section above.

You can also simply run `python3 oqs_scripts/try_handshake.py`, which will pick a random key-exchange and signature algorithm and will attempt a handshake between the TLS server and client with the chosen algorithms.

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to this fork include:

- Christian Paquin (Microsoft Research)
- Goutam Tamvada (University of Waterloo)
- JT

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Canadian Centre for Cyber Security.
We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
