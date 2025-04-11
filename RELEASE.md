OQS-BoringSSL snapshot 2025-01
==============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/boringssl** is an integration of liboqs into (a fork of) BoringSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in HTTP/3.  The integration should not be considered "production quality".

Release notes
=============

This is the 2025-01 snapshot release of OQS-BoringSSL, released on January 21, 2025. This release is intended to be used with [liboqs v0.12.0](https://github.com/open-quantum-safe/liboqs/releases/tag/0.12.0).

What's New
----------

This is the ninth snapshot release of OQS-BoringSSL.  It is based on BoringSSL commit [d3f26f8af0853b4d337d2405281f91fdfbe64465](https://github.com/google/boringssl/commit/d3f26f8af0853b4d337d2405281f91fdfbe64465).

- Updates ML-DSA-ipd to ML-DSA
- Updates ML-KEM OIDs
- Upstream update

Previous release notes
----------------------

- [OQS-BoringSSL snapshot 2024-10](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2024-10) aligned with liboqs 0.11.0 (October 10, 2024)
- [OQS-BoringSSL snapshot 2023-06](https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2023-06) aligned with liboqs 0.8.0 (July 4, 2023)

## What's Changed
* Update lattice-based algorithms by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/130
* Update to upstream be21ef7 by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/131
* Various Updates by @pi-314159 in https://github.com/open-quantum-safe/boringssl/pull/132


**Full Changelog**: https://github.com/open-quantum-safe/boringssl/compare/OQS-BoringSSL-snapshot-2024-10...OQS-BoringSSL-snapshot-2025-01
