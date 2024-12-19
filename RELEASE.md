OQS-BoringSSL snapshot 2024-10
==============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/boringssl** is an integration of liboqs into (a fork of) BoringSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in HTTP/3.  The integration should not be considered "production quality".

Release notes
=============

This is the 2024-10 snapshot release of OQS-BoringSSL, released on October 10, 2024. This release is intended to be used with [liboqs v0.11.0](https://github.com/open-quantum-safe/liboqs/releases/tag/0.11.0).

What's New
----------

This is the eighth snapshot release of OQS-BoringSSL.  It is based on BoringSSL commit [f10c1dc37174843c504a80e94c252e35b7b1eb61](https://github.com/google/boringssl/commit/f10c1dc37174843c504a80e94c252e35b7b1eb61).

- Adds support for hybrid signature algorithms
- Adds support for X25519 hybrid key exchange algorithms
- Adds support for [ML-KEM](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- Adds support for [ML-DSA-ipd](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf)
- Updates HQC
- Updates Falcon
- Adds support for MAYO from Round 1 of [NIST’s Post-Quantum Signature On-Ramp process](https://csrc.nist.gov/projects/pqc-dig-sig/round-1-additional-signatures)
- Adds support for CROSS from Round 1 of [NIST’s Post-Quantum Signature On-Ramp process](https://csrc.nist.gov/projects/pqc-dig-sig/round-1-additional-signatures)
- Upstream update

Previous release notes
----------------------

- [OQS-BoringSSL snapshot 2023-06](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2023-06) aligned with liboqs 0.8.0 (July 4, 2023)
- [OQS-BoringSSL snapshot 2022-08](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2022-08) aligned with liboqs 0.7.2 (August 24, 2022)
- [OQS-BoringSSL snapshot 2021-08](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2021-08) aligned with liboqs 0.7.0 (August 11, 2021)
- [OQS-BoringSSL snapshot 2021-03](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2021-03) aligned with liboqs 0.5.0 (March 26, 2021)
- [OQS-BoringSSL snapshot 2020-08](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2020-08) aligned with liboqs 0.4.0 (August 11, 2020)
- [OQS-BoringSSL snapshot 2020-07](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2020-07) aligned with liboqs 0.3.0 (July 10, 2020)

## What's Changed
* Update for Chromium 117.0.5863.0 by @Raytonne in https://github.com/open-quantum-safe/boringssl/pull/103
* Update to upstream 4df6f97 by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/105
* HQC Update 20230430 by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/106
* Update oqs_template by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/107
* Update to upstream df3b58e by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/109
* Add X25519 hybrid key exchange algorithms support by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/110
* Add Module-Lattice-Based Algorithms (ML-*) Support by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/112
* Allow libpki to verify quantum safe signatures by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/113
* Falcon Update April 2024 by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/114
* Update to upstream 783ae72 by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/115
* Update to upstream 369fe28 by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/116
* Fix CI & Add MAYO by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/117
* Add support for hybrid signature algorithms by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/118
* Drop CircleCI and switch to GitHub Actions by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/120
* Trigger CI on repository_dispatch event by @SWilson4 in https://github.com/open-quantum-safe/boringssl/pull/121
* Update to upstream f10c1dc by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/122
* Update README.md by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/123
* Sync algs with liboqs and oqs-provider by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/124
* Generate `oqs_headers` by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/126

## New Contributors
* @pi-314159 made their first contribution in https://github.com/open-quantum-safe/boringssl/pull/105
* @SWilson4 made their first contribution in https://github.com/open-quantum-safe/boringssl/pull/121

**Full Changelog**: https://github.com/open-quantum-safe/boringssl/compare/OQS-BoringSSL-snapshot-2023-06...OQS-BoringSSL-snapshot-2024-10
