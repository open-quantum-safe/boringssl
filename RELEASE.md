OQS-BoringSSL snapshot 2021-03
==============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/boringssl** is an integration of liboqs into (a fork of) BoringSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in TLS 1.3.  The integration should not be considered "production quality".

Release notes
=============

This is the 2021-03 snapshot release of OQS-BoringSSL, released on March 26, 2021. Its release page on GitHub is https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2021-03. This release is intended to be used with liboqs version 0.5.0.

What's New
----------

This is the third snapshot release of OQS-BoringSSL.  It is based on BoringSSL commit [78b3337a10a7f7b3495b6cb8140a74e265290898](https://github.com/google/boringssl/commit/78b3337).

- Removes algorithms from NIST PQC Round 2 that did not advance to Round 3: NewHope, ThreeBears, MQDSS, qTesla.
- Updates algorithms to those used in liboqs 0.5.0, as described in the [liboqs release notes](https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md).
- Change format of hybrid key exchange in TLS 1.3 to follow https://tools.ietf.org/html/draft-ietf-tls-hybrid-design-01

Previous release notes
----------------------

- [OQS-BoringSSL snapshot 2020-08](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2020-08) aligned with liboqs 0.4.0 (August 11, 2020)
- [OQS-BoringSSL snapshot 2020-07](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2020-07) aligned with liboqs 0.3.0 (July 10, 2020)
