OQS-BoringSSL snapshot 2021-03
==============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/boringssl** is an integration of liboqs into (a fork of) BoringSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in TLS 1.3.  The integration should not be considered "production quality".

Release notes
=============

This is the 2021-03 snapshot release of OQS-BoringSSL, released on March XX, 2021. Its release page on GitHub is https://github.com/open-quantum-safe/boringssl/releases/tag/OQS-BoringSSL-snapshot-2021-03. This release is intended to be used with liboqs version 0.5.0.

What's New
----------

This is the third snapshot release of OQS-BoringSSL.  It is based on BoringSSL commit [78b3337a10a7f7b3495b6cb8140a74e265290898](https://github.com/google/boringssl/commit/78b3337).

- Uses the updated NIST Round 2 submissions added to liboqs 0.4.0, as described in the [liboqs release notes](https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md).

Deprecations
------------

As a result of NIST's announcement of Round 3 of the Post-Quantum Cryptography Standardization Project, this is the last release of OQS-BoringSSL that contain algorithms from Round 2 that are not Round 3 finalists or alternate candidates. Those algorithms will be removed in the next release. The algorithms in question are: NewHope, ThreeBears, MQDSS, and qTesla. These algorithms are considered deprecated within OQS-BoringSSL will receive no updates after this release.
