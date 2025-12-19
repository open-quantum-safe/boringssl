// Copyright 2015 The Chromium Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "signature_algorithm.h"

#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/nid.h>

#include "input.h"
#include "parse_values.h"
#include "parser.h"

BSSL_NAMESPACE_BEGIN

namespace {

// These OIDs do not reference libcrypto's OBJ table, as that table is very
// large and includes many more OIDs than we need. However, where OIDs are
// already in the table, we reuse the |OBJ_ENC_*| constants to avoid needing to
// specify them a second time.

// From RFC 5912:
//
//     sha1WithRSAEncryption OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
//      pkcs-1(1) 5 }
//
// In dotted notation: 1.2.840.113549.1.1.5
const uint8_t kOidSha1WithRsaEncryption[] = {OBJ_ENC_sha1WithRSAEncryption};

// sha1WithRSASignature is a deprecated equivalent of
// sha1WithRSAEncryption.
//
// It originates from the NIST Open Systems Environment (OSE)
// Implementor's Workshop (OIW).
//
// It is supported for compatibility with Microsoft's certificate APIs and
// tools, particularly makecert.exe, which default(ed/s) to this OID for SHA-1.
//
// See also: https://bugzilla.mozilla.org/show_bug.cgi?id=1042479
//
// In dotted notation: 1.3.14.3.2.29
const uint8_t kOidSha1WithRsaSignature[] = {OBJ_ENC_sha1WithRSA};

// From RFC 5912:
//
//     pkcs-1  OBJECT IDENTIFIER  ::=
//         { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }

// From RFC 5912:
//
//     sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 11 }
//
// In dotted notation: 1.2.840.113549.1.1.11
const uint8_t kOidSha256WithRsaEncryption[] = {OBJ_ENC_sha256WithRSAEncryption};

// From RFC 5912:
//
//     sha384WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 12 }
//
// In dotted notation: 1.2.840.113549.1.1.11
const uint8_t kOidSha384WithRsaEncryption[] = {OBJ_ENC_sha384WithRSAEncryption};

// From RFC 5912:
//
//     sha512WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 13 }
//
// In dotted notation: 1.2.840.113549.1.1.13
const uint8_t kOidSha512WithRsaEncryption[] = {OBJ_ENC_sha512WithRSAEncryption};

// From RFC 5912:
//
//     ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) ansi-X9-62(10045)
//      signatures(4) 1 }
//
// In dotted notation: 1.2.840.10045.4.1
const uint8_t kOidEcdsaWithSha1[] = {OBJ_ENC_ecdsa_with_SHA1};

// From RFC 5912:
//
//     ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
//      ecdsa-with-SHA2(3) 2 }
//
// In dotted notation: 1.2.840.10045.4.3.2
const uint8_t kOidEcdsaWithSha256[] = {OBJ_ENC_ecdsa_with_SHA256};

// From RFC 5912:
//
//     ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
//      ecdsa-with-SHA2(3) 3 }
//
// In dotted notation: 1.2.840.10045.4.3.3
const uint8_t kOidEcdsaWithSha384[] = {OBJ_ENC_ecdsa_with_SHA384};

// From RFC 5912:
//
//     ecdsa-with-SHA512 OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
//      ecdsa-with-SHA2(3) 4 }
//
// In dotted notation: 1.2.840.10045.4.3.4
const uint8_t kOidEcdsaWithSha512[] = {OBJ_ENC_ecdsa_with_SHA512};

// From RFC 5912:
//
//     id-RSASSA-PSS  OBJECT IDENTIFIER  ::=  { pkcs-1 10 }
//
// In dotted notation: 1.2.840.113549.1.1.10
const uint8_t kOidRsaSsaPss[] = {OBJ_ENC_rsassaPss};

// From RFC 5912:
//
//     id-mgf1  OBJECT IDENTIFIER  ::=  { pkcs-1 8 }
//
// In dotted notation: 1.2.840.113549.1.1.8
const uint8_t kOidMgf1[] = {OBJ_ENC_mgf1};

// From draft-davidben-tls-merkle-tree-certs-08:
//
//   id-alg-mtcProof OBJECT IDENTIFIER ::= {
//       iso(1) identified-organization(3) dod(6) internet(1) security(5)
//       mechanisms(5) pkix(7) algorithms(6) TBD}
//
// Also from said draft:
//   For initial experimentation, early implementations of this design will use
//   the OID 1.3.6.1.4.1.44363.47.0 instead of id-alg-mtcProof.
const uint8_t kOidAlgMtcProofDraftDavidben08[] = {0x2b, 0x06, 0x01, 0x04, 0x01,
                                                  0x82, 0xda, 0x4b, 0x2f, 0x00};

///// OQS_TEMPLATE_FRAGMENT_LIST_SIG_OIDS_START
const uint8_t kOidCrossrsdp128balanced[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xe6, 0x25, 0x02, 0x01, 0x01, 0x02, 0x02};
const uint8_t kOidOv_ip_pkc[] = {0x2b, 0xce, 0x0f, 0x09, 0x06, 0x01};
const uint8_t kOidOv_ip_pkc_skc[] = {0x2b, 0xce, 0x0f, 0x09, 0x0a, 0x01};
const uint8_t kOidFalcon1024[] = {0x2b, 0xce, 0x0f, 0x03, 0x0e};
const uint8_t kOidFalcon512[] = {0x2b, 0xce, 0x0f, 0x03, 0x0b};
const uint8_t kOidRsa3072_falcon512[] = {0x2b, 0xce, 0x0f, 0x03, 0x0d};
const uint8_t kOidFalconpadded1024[] = {0x2b, 0xce, 0x0f, 0x03, 0x13};
const uint8_t kOidFalconpadded512[] = {0x2b, 0xce, 0x0f, 0x03, 0x10};
const uint8_t kOidMayo1[] = {0x2b, 0xce, 0x0f, 0x08, 0x01, 0x03};
const uint8_t kOidMayo2[] = {0x2b, 0xce, 0x0f, 0x08, 0x02, 0x03};
const uint8_t kOidMayo3[] = {0x2b, 0xce, 0x0f, 0x08, 0x03, 0x03};
const uint8_t kOidMayo5[] = {0x2b, 0xce, 0x0f, 0x08, 0x05, 0x03};
const uint8_t kOidMldsa44[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};
const uint8_t kOidP256_mldsa44[] = {0x2b, 0xce, 0x0f, 0x07, 0x05};
const uint8_t kOidMldsa65[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
const uint8_t kOidP384_mldsa65[] = {0x2b, 0xce, 0x0f, 0x07, 0x07};
const uint8_t kOidMldsa87[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};
const uint8_t kOidP521_mldsa87[] = {0x2b, 0xce, 0x0f, 0x07, 0x08};
const uint8_t kOidSnova2454[] = {0x2b, 0xce, 0x0f, 0x0a, 0x01, 0x01};
const uint8_t kOidSnova2454esk[] = {0x2b, 0xce, 0x0f, 0x0a, 0x03, 0x01};
const uint8_t kOidSnova37172[] = {0x2b, 0xce, 0x0f, 0x0a, 0x05, 0x01};
const uint8_t kOidSnova2455[] = {0x2b, 0xce, 0x0f, 0x0a, 0x0a, 0x01};
const uint8_t kOidSnova2965[] = {0x2b, 0xce, 0x0f, 0x0a, 0x0c, 0x01};
const uint8_t kOidSphincssha2128fsimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x04, 0x0d};
const uint8_t kOidSphincssha2128ssimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x04, 0x10};
const uint8_t kOidSphincssha2192fsimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x05, 0x0a};
const uint8_t kOidSphincssha2192ssimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x05, 0x0c};
const uint8_t kOidSphincssha2256fsimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x06, 0x0a};
const uint8_t kOidSphincssha2256ssimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x06, 0x0c};
const uint8_t kOidSphincsshake128fsimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x07, 0x0d};
const uint8_t kOidSphincsshake128ssimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x07, 0x10};
const uint8_t kOidSphincsshake192fsimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x08, 0x0a};
const uint8_t kOidSphincsshake192ssimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x08, 0x0c};
const uint8_t kOidSphincsshake256fsimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x09, 0x0a};
const uint8_t kOidSphincsshake256ssimple[] = {0x2b, 0xce, 0x0f, 0x06, 0x09, 0x0c};
const uint8_t kOidSlhdsapuresha2128s[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14};
const uint8_t kOidSlhdsapuresha2128f[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x15};
const uint8_t kOidSlhdsapuresha2192s[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16};
const uint8_t kOidSlhdsapuresha2192f[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x17};
const uint8_t kOidSlhdsapuresha2256s[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18};
const uint8_t kOidSlhdsapuresha2256f[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x19};
const uint8_t kOidSlhdsapureshake128s[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1a};
const uint8_t kOidSlhdsapureshake128f[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1b};
const uint8_t kOidSlhdsapureshake192s[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1c};
const uint8_t kOidSlhdsapureshake192f[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1d};
const uint8_t kOidSlhdsapureshake256s[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1e};
const uint8_t kOidSlhdsapureshake256f[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1f};
///// OQS_TEMPLATE_FRAGMENT_LIST_SIG_OIDS_END

// Returns true if the entirety of the input is a NULL value.
[[nodiscard]] bool IsNull(der::Input input) {
  der::Parser parser(input);
  der::Input null_value;
  if (!parser.ReadTag(CBS_ASN1_NULL, &null_value)) {
    return false;
  }

  // NULL values are TLV encoded; the value is expected to be empty.
  if (!null_value.empty()) {
    return false;
  }

  // By definition of this function, the entire input must be a NULL.
  return !parser.HasMore();
}

[[nodiscard]] bool IsNullOrEmpty(der::Input input) {
  return IsNull(input) || input.empty();
}

// Parses a MaskGenAlgorithm as defined by RFC 5912:
//
//     MaskGenAlgorithm ::= AlgorithmIdentifier{ALGORITHM,
//                             {PKCS1MGFAlgorithms}}
//
//     mgf1SHA1 MaskGenAlgorithm ::= {
//         algorithm id-mgf1,
//         parameters HashAlgorithm : sha1Identifier
//     }
//
//     --
//     --  Define the set of mask generation functions
//     --
//     --  If the identifier is id-mgf1, any of the listed hash
//     --    algorithms may be used.
//     --
//
//     PKCS1MGFAlgorithms ALGORITHM ::= {
//         { IDENTIFIER id-mgf1 PARAMS TYPE HashAlgorithm ARE required },
//         ...
//     }
//
// Note that the possible mask gen algorithms is extensible. However at present
// the only function supported is MGF1, as that is the singular mask gen
// function defined by RFC 4055 / RFC 5912.
[[nodiscard]] bool ParseMaskGenAlgorithm(const der::Input input,
                                         DigestAlgorithm *mgf1_hash) {
  der::Input oid;
  der::Input params;
  if (!ParseAlgorithmIdentifier(input, &oid, &params)) {
    return false;
  }

  // MGF1 is the only supported mask generation algorithm.
  if (oid != der::Input(kOidMgf1)) {
    return false;
  }

  return ParseHashAlgorithm(params, mgf1_hash);
}

// Parses the parameters for an RSASSA-PSS signature algorithm, as defined by
// RFC 5912:
//
//     sa-rsaSSA-PSS SIGNATURE-ALGORITHM ::= {
//         IDENTIFIER id-RSASSA-PSS
//         PARAMS TYPE RSASSA-PSS-params ARE required
//         HASHES { mda-sha1 | mda-sha224 | mda-sha256 | mda-sha384
//                      | mda-sha512 }
//         PUBLIC-KEYS { pk-rsa | pk-rsaSSA-PSS }
//         SMIME-CAPS { IDENTIFIED BY id-RSASSA-PSS }
//     }
//
//     RSASSA-PSS-params  ::=  SEQUENCE  {
//         hashAlgorithm     [0] HashAlgorithm DEFAULT sha1Identifier,
//         maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
//         saltLength        [2] INTEGER DEFAULT 20,
//         trailerField      [3] INTEGER DEFAULT 1
//     }
//
// Which is to say the parameters MUST be present, and of type
// RSASSA-PSS-params. Additionally, we only support the RSA-PSS parameter
// combinations representable by TLS 1.3 (RFC 8446).
//
// Note also that DER encoding (ITU-T X.690 section 11.5) prohibits
// specifying default values explicitly. The parameter should instead be
// omitted to indicate a default value.
std::optional<SignatureAlgorithm> ParseRsaPss(der::Input params) {
  der::Parser parser(params);
  der::Parser params_parser;
  if (!parser.ReadSequence(&params_parser)) {
    return std::nullopt;
  }

  // There shouldn't be anything after the sequence (by definition the
  // parameters is a single sequence).
  if (parser.HasMore()) {
    return std::nullopt;
  }

  // The default values for hashAlgorithm, maskGenAlgorithm, and saltLength
  // correspond to SHA-1, which we do not support with RSA-PSS, so treat them as
  // required fields. Explicitly-specified defaults will be rejected later, when
  // we limit combinations. Additionally, as the trailerField is required to be
  // the default, we simply ignore it and reject it as any other trailing data.
  //
  //     hashAlgorithm     [0] HashAlgorithm DEFAULT sha1Identifier,
  //     maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
  //     saltLength        [2] INTEGER DEFAULT 20,
  //     trailerField      [3] INTEGER DEFAULT 1
  der::Input field;
  DigestAlgorithm hash, mgf1_hash;
  der::Parser salt_length_parser;
  uint64_t salt_length;
  if (!params_parser.ReadTag(
          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0, &field) ||
      !ParseHashAlgorithm(field, &hash) ||
      !params_parser.ReadTag(
          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1, &field) ||
      !ParseMaskGenAlgorithm(field, &mgf1_hash) ||
      !params_parser.ReadConstructed(
          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 2,
          &salt_length_parser) ||
      !salt_length_parser.ReadUint64(&salt_length) ||
      salt_length_parser.HasMore() || params_parser.HasMore()) {
    return std::nullopt;
  }

  // Only combinations of RSASSA-PSS-params specified by TLS 1.3 (RFC 8446) are
  // supported.
  if (hash != mgf1_hash) {
    return std::nullopt;  // TLS 1.3 always matches MGF-1 and message hash.
  }
  if (hash == DigestAlgorithm::Sha256 && salt_length == 32) {
    return SignatureAlgorithm::kRsaPssSha256;
  }
  if (hash == DigestAlgorithm::Sha384 && salt_length == 48) {
    return SignatureAlgorithm::kRsaPssSha384;
  }
  if (hash == DigestAlgorithm::Sha512 && salt_length == 64) {
    return SignatureAlgorithm::kRsaPssSha512;
  }

  return std::nullopt;
}

}  // namespace

[[nodiscard]] bool ParseAlgorithmIdentifier(der::Input input,
                                            der::Input *algorithm,
                                            der::Input *parameters) {
  der::Parser parser(input);

  der::Parser algorithm_identifier_parser;
  if (!parser.ReadSequence(&algorithm_identifier_parser)) {
    return false;
  }

  // There shouldn't be anything after the sequence. This is by definition,
  // as the input to this function is expected to be a single
  // AlgorithmIdentifier.
  if (parser.HasMore()) {
    return false;
  }

  if (!algorithm_identifier_parser.ReadTag(CBS_ASN1_OBJECT, algorithm)) {
    return false;
  }

  // Read the optional parameters to a der::Input. The parameters can be at
  // most one TLV (for instance NULL or a sequence).
  //
  // Note that nothing is allowed after the single optional "parameters" TLV.
  // This is because RFC 5912's notation for AlgorithmIdentifier doesn't
  // explicitly list an extension point after "parameters".
  *parameters = der::Input();
  if (algorithm_identifier_parser.HasMore() &&
      !algorithm_identifier_parser.ReadRawTLV(parameters)) {
    return false;
  }
  return !algorithm_identifier_parser.HasMore();
}

[[nodiscard]] bool ParseHashAlgorithm(der::Input input, DigestAlgorithm *out) {
  CBS cbs;
  CBS_init(&cbs, input.data(), input.size());
  const EVP_MD *md = EVP_parse_digest_algorithm(&cbs);

  if (md == EVP_sha1()) {
    *out = DigestAlgorithm::Sha1;
  } else if (md == EVP_sha256()) {
    *out = DigestAlgorithm::Sha256;
  } else if (md == EVP_sha384()) {
    *out = DigestAlgorithm::Sha384;
  } else if (md == EVP_sha512()) {
    *out = DigestAlgorithm::Sha512;
  } else {
    // TODO(eroman): Support MD2, MD4, MD5 for completeness?
    // Unsupported digest algorithm.
    return false;
  }

  return true;
}

std::optional<SignatureAlgorithm> ParseSignatureAlgorithm(
    der::Input algorithm_identifier) {
  der::Input oid;
  der::Input params;
  if (!ParseAlgorithmIdentifier(algorithm_identifier, &oid, &params)) {
    return std::nullopt;
  }

  // TODO(eroman): Each OID is tested for equality in order, which is not
  // particularly efficient.

  // RFC 5912 requires that the parameters for RSA PKCS#1 v1.5 algorithms be
  // NULL ("PARAMS TYPE NULL ARE required"), however an empty parameter is also
  // allowed for compatibility with non-compliant OCSP responders.
  //
  // TODO(svaldez): Add warning about non-strict parsing.
  if (oid == der::Input(kOidSha1WithRsaEncryption) && IsNullOrEmpty(params)) {
    return SignatureAlgorithm::kRsaPkcs1Sha1;
  }
  if (oid == der::Input(kOidSha256WithRsaEncryption) && IsNullOrEmpty(params)) {
    return SignatureAlgorithm::kRsaPkcs1Sha256;
  }
  if (oid == der::Input(kOidSha384WithRsaEncryption) && IsNullOrEmpty(params)) {
    return SignatureAlgorithm::kRsaPkcs1Sha384;
  }
  if (oid == der::Input(kOidSha512WithRsaEncryption) && IsNullOrEmpty(params)) {
    return SignatureAlgorithm::kRsaPkcs1Sha512;
  }
  if (oid == der::Input(kOidSha1WithRsaSignature) && IsNullOrEmpty(params)) {
    return SignatureAlgorithm::kRsaPkcs1Sha1;
  }

  // RFC 5912 requires that the parameters for ECDSA algorithms be absent
  // ("PARAMS TYPE NULL ARE absent"):
  if (oid == der::Input(kOidEcdsaWithSha1) && params.empty()) {
    return SignatureAlgorithm::kEcdsaSha1;
  }
  if (oid == der::Input(kOidEcdsaWithSha256) && params.empty()) {
    return SignatureAlgorithm::kEcdsaSha256;
  }
  if (oid == der::Input(kOidEcdsaWithSha384) && params.empty()) {
    return SignatureAlgorithm::kEcdsaSha384;
  }
  if (oid == der::Input(kOidEcdsaWithSha512) && params.empty()) {
    return SignatureAlgorithm::kEcdsaSha512;
  }

///// OQS_TEMPLATE_FRAGMENT_PARSE_SIG_OIDS_START
  if (oid == der::Input(kOidCrossrsdp128balanced)) {
    return SignatureAlgorithm::kCrossrsdp128balanced;
  }
  if (oid == der::Input(kOidOv_ip_pkc)) {
    return SignatureAlgorithm::kOv_ip_pkc;
  }
  if (oid == der::Input(kOidOv_ip_pkc_skc)) {
    return SignatureAlgorithm::kOv_ip_pkc_skc;
  }
  if (oid == der::Input(kOidFalcon1024)) {
    return SignatureAlgorithm::kFalcon1024;
  }
  if (oid == der::Input(kOidFalcon512)) {
    return SignatureAlgorithm::kFalcon512;
  }
  if (oid == der::Input(kOidRsa3072_falcon512)) {
    return SignatureAlgorithm::kRsa3072_falcon512;
  }
  if (oid == der::Input(kOidFalconpadded1024)) {
    return SignatureAlgorithm::kFalconpadded1024;
  }
  if (oid == der::Input(kOidFalconpadded512)) {
    return SignatureAlgorithm::kFalconpadded512;
  }
  if (oid == der::Input(kOidMayo1)) {
    return SignatureAlgorithm::kMayo1;
  }
  if (oid == der::Input(kOidMayo2)) {
    return SignatureAlgorithm::kMayo2;
  }
  if (oid == der::Input(kOidMayo3)) {
    return SignatureAlgorithm::kMayo3;
  }
  if (oid == der::Input(kOidMayo5)) {
    return SignatureAlgorithm::kMayo5;
  }
  if (oid == der::Input(kOidMldsa44)) {
    return SignatureAlgorithm::kMldsa44;
  }
  if (oid == der::Input(kOidP256_mldsa44)) {
    return SignatureAlgorithm::kP256_mldsa44;
  }
  if (oid == der::Input(kOidMldsa65)) {
    return SignatureAlgorithm::kMldsa65;
  }
  if (oid == der::Input(kOidP384_mldsa65)) {
    return SignatureAlgorithm::kP384_mldsa65;
  }
  if (oid == der::Input(kOidMldsa87)) {
    return SignatureAlgorithm::kMldsa87;
  }
  if (oid == der::Input(kOidP521_mldsa87)) {
    return SignatureAlgorithm::kP521_mldsa87;
  }
  if (oid == der::Input(kOidSnova2454)) {
    return SignatureAlgorithm::kSnova2454;
  }
  if (oid == der::Input(kOidSnova2454esk)) {
    return SignatureAlgorithm::kSnova2454esk;
  }
  if (oid == der::Input(kOidSnova37172)) {
    return SignatureAlgorithm::kSnova37172;
  }
  if (oid == der::Input(kOidSnova2455)) {
    return SignatureAlgorithm::kSnova2455;
  }
  if (oid == der::Input(kOidSnova2965)) {
    return SignatureAlgorithm::kSnova2965;
  }
  if (oid == der::Input(kOidSphincssha2128fsimple)) {
    return SignatureAlgorithm::kSphincssha2128fsimple;
  }
  if (oid == der::Input(kOidSphincssha2128ssimple)) {
    return SignatureAlgorithm::kSphincssha2128ssimple;
  }
  if (oid == der::Input(kOidSphincssha2192fsimple)) {
    return SignatureAlgorithm::kSphincssha2192fsimple;
  }
  if (oid == der::Input(kOidSphincssha2192ssimple)) {
    return SignatureAlgorithm::kSphincssha2192ssimple;
  }
  if (oid == der::Input(kOidSphincssha2256fsimple)) {
    return SignatureAlgorithm::kSphincssha2256fsimple;
  }
  if (oid == der::Input(kOidSphincssha2256ssimple)) {
    return SignatureAlgorithm::kSphincssha2256ssimple;
  }
  if (oid == der::Input(kOidSphincsshake128fsimple)) {
    return SignatureAlgorithm::kSphincsshake128fsimple;
  }
  if (oid == der::Input(kOidSphincsshake128ssimple)) {
    return SignatureAlgorithm::kSphincsshake128ssimple;
  }
  if (oid == der::Input(kOidSphincsshake192fsimple)) {
    return SignatureAlgorithm::kSphincsshake192fsimple;
  }
  if (oid == der::Input(kOidSphincsshake192ssimple)) {
    return SignatureAlgorithm::kSphincsshake192ssimple;
  }
  if (oid == der::Input(kOidSphincsshake256fsimple)) {
    return SignatureAlgorithm::kSphincsshake256fsimple;
  }
  if (oid == der::Input(kOidSphincsshake256ssimple)) {
    return SignatureAlgorithm::kSphincsshake256ssimple;
  }
  if (oid == der::Input(kOidSlhdsapuresha2128s)) {
    return SignatureAlgorithm::kSlhdsapuresha2128s;
  }
  if (oid == der::Input(kOidSlhdsapuresha2128f)) {
    return SignatureAlgorithm::kSlhdsapuresha2128f;
  }
  if (oid == der::Input(kOidSlhdsapuresha2192s)) {
    return SignatureAlgorithm::kSlhdsapuresha2192s;
  }
  if (oid == der::Input(kOidSlhdsapuresha2192f)) {
    return SignatureAlgorithm::kSlhdsapuresha2192f;
  }
  if (oid == der::Input(kOidSlhdsapuresha2256s)) {
    return SignatureAlgorithm::kSlhdsapuresha2256s;
  }
  if (oid == der::Input(kOidSlhdsapuresha2256f)) {
    return SignatureAlgorithm::kSlhdsapuresha2256f;
  }
  if (oid == der::Input(kOidSlhdsapureshake128s)) {
    return SignatureAlgorithm::kSlhdsapureshake128s;
  }
  if (oid == der::Input(kOidSlhdsapureshake128f)) {
    return SignatureAlgorithm::kSlhdsapureshake128f;
  }
  if (oid == der::Input(kOidSlhdsapureshake192s)) {
    return SignatureAlgorithm::kSlhdsapureshake192s;
  }
  if (oid == der::Input(kOidSlhdsapureshake192f)) {
    return SignatureAlgorithm::kSlhdsapureshake192f;
  }
  if (oid == der::Input(kOidSlhdsapureshake256s)) {
    return SignatureAlgorithm::kSlhdsapureshake256s;
  }
  if (oid == der::Input(kOidSlhdsapureshake256f)) {
    return SignatureAlgorithm::kSlhdsapureshake256f;
  }
///// OQS_TEMPLATE_FRAGMENT_PARSE_SIG_OIDS_END

  if (oid == der::Input(kOidRsaSsaPss)) {
    return ParseRsaPss(params);
  }

  if (oid == der::Input(kOidAlgMtcProofDraftDavidben08) && params.empty()) {
    return SignatureAlgorithm::kMtcProofDraftDavidben08;
  }

  // Unknown signature algorithm.
  return std::nullopt;
}

std::optional<DigestAlgorithm> GetTlsServerEndpointDigestAlgorithm(
    SignatureAlgorithm alg) {
  // See RFC 5929, section 4.1. RFC 5929 breaks the signature algorithm
  // abstraction by trying to extract individual digest algorithms. (While
  // common, this is not a universal property of signature algorithms.) We
  // implement this within the library, so callers do not need to condition over
  // all algorithms.
  switch (alg) {
    // If the single digest algorithm is SHA-1, use SHA-256.
    case SignatureAlgorithm::kRsaPkcs1Sha1:
    case SignatureAlgorithm::kEcdsaSha1:
      return DigestAlgorithm::Sha256;

    case SignatureAlgorithm::kRsaPkcs1Sha256:
    case SignatureAlgorithm::kEcdsaSha256:
      return DigestAlgorithm::Sha256;

    case SignatureAlgorithm::kRsaPkcs1Sha384:
    case SignatureAlgorithm::kEcdsaSha384:
      return DigestAlgorithm::Sha384;

    case SignatureAlgorithm::kRsaPkcs1Sha512:
    case SignatureAlgorithm::kEcdsaSha512:
      return DigestAlgorithm::Sha512;

///// OQS_TEMPLATE_FRAGMENT_PAIR_SIGS_WITH_DIGESTS_START
    case SignatureAlgorithm::kCrossrsdp128balanced:
    case SignatureAlgorithm::kOv_ip_pkc:
    case SignatureAlgorithm::kOv_ip_pkc_skc:
    case SignatureAlgorithm::kFalcon512:
    case SignatureAlgorithm::kRsa3072_falcon512:
    case SignatureAlgorithm::kFalconpadded512:
    case SignatureAlgorithm::kMayo1:
    case SignatureAlgorithm::kMayo2:
    case SignatureAlgorithm::kMldsa44:
    case SignatureAlgorithm::kP256_mldsa44:
    case SignatureAlgorithm::kSnova2454:
    case SignatureAlgorithm::kSnova2454esk:
    case SignatureAlgorithm::kSnova37172:
    case SignatureAlgorithm::kSphincssha2128fsimple:
    case SignatureAlgorithm::kSphincssha2128ssimple:
    case SignatureAlgorithm::kSphincsshake128fsimple:
    case SignatureAlgorithm::kSphincsshake128ssimple:
    case SignatureAlgorithm::kSlhdsapuresha2128s:
    case SignatureAlgorithm::kSlhdsapuresha2128f:
    case SignatureAlgorithm::kSlhdsapureshake128s:
    case SignatureAlgorithm::kSlhdsapureshake128f:
      return DigestAlgorithm::Sha256;

    case SignatureAlgorithm::kMayo3:
    case SignatureAlgorithm::kMldsa65:
    case SignatureAlgorithm::kP384_mldsa65:
    case SignatureAlgorithm::kSnova2455:
    case SignatureAlgorithm::kSphincssha2192fsimple:
    case SignatureAlgorithm::kSphincssha2192ssimple:
    case SignatureAlgorithm::kSphincsshake192fsimple:
    case SignatureAlgorithm::kSphincsshake192ssimple:
    case SignatureAlgorithm::kSlhdsapuresha2192s:
    case SignatureAlgorithm::kSlhdsapuresha2192f:
    case SignatureAlgorithm::kSlhdsapureshake192s:
    case SignatureAlgorithm::kSlhdsapureshake192f:
      return DigestAlgorithm::Sha384;

    case SignatureAlgorithm::kFalcon1024:
    case SignatureAlgorithm::kFalconpadded1024:
    case SignatureAlgorithm::kMayo5:
    case SignatureAlgorithm::kMldsa87:
    case SignatureAlgorithm::kP521_mldsa87:
    case SignatureAlgorithm::kSnova2965:
    case SignatureAlgorithm::kSphincssha2256fsimple:
    case SignatureAlgorithm::kSphincssha2256ssimple:
    case SignatureAlgorithm::kSphincsshake256fsimple:
    case SignatureAlgorithm::kSphincsshake256ssimple:
    case SignatureAlgorithm::kSlhdsapuresha2256s:
    case SignatureAlgorithm::kSlhdsapuresha2256f:
    case SignatureAlgorithm::kSlhdsapureshake256s:
    case SignatureAlgorithm::kSlhdsapureshake256f:
      return DigestAlgorithm::Sha512;
///// OQS_TEMPLATE_FRAGMENT_PAIR_SIGS_WITH_DIGESTS_END

    // It is ambiguous whether hash-matching RSASSA-PSS instantiations count as
    // using one or multiple digests, but the corresponding digest is the only
    // reasonable interpretation.
    case SignatureAlgorithm::kRsaPssSha256:
      return DigestAlgorithm::Sha256;
    case SignatureAlgorithm::kRsaPssSha384:
      return DigestAlgorithm::Sha384;
    case SignatureAlgorithm::kRsaPssSha512:
      return DigestAlgorithm::Sha512;

    // This is not implemented for MTCs.
    case SignatureAlgorithm::kMtcProofDraftDavidben08:
      return std::nullopt;
  }
  return std::nullopt;
}

BSSL_NAMESPACE_END
