// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "verify_signed_data.h"

#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pki/signature_verify_cache.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "cert_errors.h"
#include "input.h"
#include "parse_values.h"
#include "parser.h"
#include "signature_algorithm.h"

namespace bssl {

namespace {

bool SHA256UpdateWithLengthPrefixedData(SHA256_CTX *s_ctx, const uint8_t *data,
                                        uint64_t length) {
  return (SHA256_Update(s_ctx, reinterpret_cast<uint8_t *>(&length),
                        sizeof(length)) &&
          SHA256_Update(s_ctx, data, length));
}

// Increase to make incompatible changes in the computation of the
// cache key.
constexpr uint32_t VerifyCacheKeyVersion = 1;

std::string SignatureVerifyCacheKey(std::string_view algorithm_name,
                                    der::Input signed_data,
                                    der::Input signature_value_bytes,
                                    EVP_PKEY *public_key) {
  SHA256_CTX s_ctx;
  bssl::ScopedCBB public_key_cbb;
  uint8_t digest[SHA256_DIGEST_LENGTH];
  uint32_t version = VerifyCacheKeyVersion;
  if (CBB_init(public_key_cbb.get(), 128) &&
      EVP_marshal_public_key(public_key_cbb.get(), public_key) &&
      SHA256_Init(&s_ctx) &&
      SHA256_Update(&s_ctx, reinterpret_cast<uint8_t *>(&version),
                    sizeof(version)) &&
      SHA256UpdateWithLengthPrefixedData(
          &s_ctx, reinterpret_cast<const uint8_t *>(algorithm_name.data()),
          algorithm_name.length()) &&
      SHA256UpdateWithLengthPrefixedData(&s_ctx, CBB_data(public_key_cbb.get()),
                                         CBB_len(public_key_cbb.get())) &&
      SHA256UpdateWithLengthPrefixedData(&s_ctx, signature_value_bytes.data(),
                                         signature_value_bytes.size()) &&
      SHA256UpdateWithLengthPrefixedData(&s_ctx, signed_data.data(),
                                         signed_data.size()) &&
      SHA256_Final(digest, &s_ctx)) {
    return std::string(reinterpret_cast<char *>(digest), sizeof(digest));
  }
  return std::string();
}

// Place an instance of this class on the call stack to automatically clear
// the OpenSSL error stack on function exit.
// TODO(crbug.com/boringssl/38): Remove this when the library is more robust to
// leaving things in the error queue.
class OpenSSLErrStackTracer {
 public:
  ~OpenSSLErrStackTracer() { ERR_clear_error(); };
};

}  // namespace

// Parses an RSA public key or EC public key from SPKI to an EVP_PKEY. Returns
// true on success.
//
// This function only recognizes the "pk-rsa" (rsaEncryption) flavor of RSA
// public key from RFC 5912.
//
//     pk-rsa PUBLIC-KEY ::= {
//      IDENTIFIER rsaEncryption
//      KEY RSAPublicKey
//      PARAMS TYPE NULL ARE absent
//      -- Private key format not in this module --
//      CERT-KEY-USAGE {digitalSignature, nonRepudiation,
//      keyEncipherment, dataEncipherment, keyCertSign, cRLSign}
//     }
//
// COMPATIBILITY NOTE: RFC 5912 and RFC 3279 are in disagreement on the value
// of parameters for rsaEncryption. Whereas RFC 5912 says they must be absent,
// RFC 3279 says they must be NULL:
//
//     The rsaEncryption OID is intended to be used in the algorithm field
//     of a value of type AlgorithmIdentifier.  The parameters field MUST
//     have ASN.1 type NULL for this algorithm identifier.
//
// Following RFC 3279 in this case.
//
// In the case of parsing EC keys, RFC 5912 describes all the ECDSA
// signature algorithms as requiring a public key of type "pk-ec":
//
//     pk-ec PUBLIC-KEY ::= {
//      IDENTIFIER id-ecPublicKey
//      KEY ECPoint
//      PARAMS TYPE ECParameters ARE required
//      -- Private key format not in this module --
//      CERT-KEY-USAGE { digitalSignature, nonRepudiation, keyAgreement,
//                           keyCertSign, cRLSign }
//     }
//
// Moreover RFC 5912 stipulates what curves are allowed. The ECParameters
// MUST NOT use an implicitCurve or specificCurve for PKIX:
//
//     ECParameters ::= CHOICE {
//      namedCurve      CURVE.&id({NamedCurve})
//      -- implicitCurve   NULL
//        -- implicitCurve MUST NOT be used in PKIX
//      -- specifiedCurve  SpecifiedCurve
//        -- specifiedCurve MUST NOT be used in PKIX
//        -- Details for specifiedCurve can be found in [X9.62]
//        -- Any future additions to this CHOICE should be coordinated
//        -- with ANSI X.9.
//     }
//     -- If you need to be able to decode ANSI X.9 parameter structures,
//     -- uncomment the implicitCurve and specifiedCurve above, and also
//     -- uncomment the following:
//     --(WITH COMPONENTS {namedCurve PRESENT})
//
// The namedCurves are extensible. The ones described by RFC 5912 are:
//
//     NamedCurve CURVE ::= {
//     { ID secp192r1 } | { ID sect163k1 } | { ID sect163r2 } |
//     { ID secp224r1 } | { ID sect233k1 } | { ID sect233r1 } |
//     { ID secp256r1 } | { ID sect283k1 } | { ID sect283r1 } |
//     { ID secp384r1 } | { ID sect409k1 } | { ID sect409r1 } |
//     { ID secp521r1 } | { ID sect571k1 } | { ID sect571r1 },
//     ... -- Extensible
//     }
bool ParsePublicKey(der::Input public_key_spki,
                    bssl::UniquePtr<EVP_PKEY> *public_key) {
  // Parse the SPKI to an EVP_PKEY.
  OpenSSLErrStackTracer err_tracer;

  CBS cbs;
  CBS_init(&cbs, public_key_spki.data(), public_key_spki.size());
  public_key->reset(EVP_parse_public_key(&cbs));
  if (!*public_key || CBS_len(&cbs) != 0) {
    public_key->reset();
    return false;
  }
  return true;
}

bool VerifySignedData(SignatureAlgorithm algorithm, der::Input signed_data,
                      const der::BitString &signature_value,
                      EVP_PKEY *public_key, SignatureVerifyCache *cache) {
  int expected_pkey_id = 1;
  const EVP_MD *digest = nullptr;
  bool is_rsa_pss = false;
  std::string_view cache_algorithm_name;
  switch (algorithm) {
    case SignatureAlgorithm::kRsaPkcs1Sha1:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha1();
      cache_algorithm_name = "RsaPkcs1Sha1";
      break;
    case SignatureAlgorithm::kRsaPkcs1Sha256:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha256();
      cache_algorithm_name = "RsaPkcs1Sha256";
      break;
    case SignatureAlgorithm::kRsaPkcs1Sha384:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha384();
      cache_algorithm_name = "RsaPkcs1Sha384";
      break;
    case SignatureAlgorithm::kRsaPkcs1Sha512:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha512();
      cache_algorithm_name = "RsaPkcs1Sha512";
      break;

    case SignatureAlgorithm::kEcdsaSha1:
      expected_pkey_id = EVP_PKEY_EC;
      digest = EVP_sha1();
      cache_algorithm_name = "EcdsaSha1";
      break;
    case SignatureAlgorithm::kEcdsaSha256:
      expected_pkey_id = EVP_PKEY_EC;
      digest = EVP_sha256();
      cache_algorithm_name = "EcdsaSha256";
      break;
    case SignatureAlgorithm::kEcdsaSha384:
      expected_pkey_id = EVP_PKEY_EC;
      digest = EVP_sha384();
      cache_algorithm_name = "EcdsaSha384";
      break;
    case SignatureAlgorithm::kEcdsaSha512:
      expected_pkey_id = EVP_PKEY_EC;
      digest = EVP_sha512();
      cache_algorithm_name = "EcdsaSha512";
      break;

///// OQS_TEMPLATE_FRAGMENT_LIST_SIGS_START
    case SignatureAlgorithm::kMldsa44:
      expected_pkey_id = EVP_PKEY_MLDSA44;
      digest = EVP_sha256();
      cache_algorithm_name = "Mldsa44";
      break;
    case SignatureAlgorithm::kMldsa65:
      expected_pkey_id = EVP_PKEY_MLDSA65;
      digest = EVP_sha384();
      cache_algorithm_name = "Mldsa65";
      break;
    case SignatureAlgorithm::kMldsa87:
      expected_pkey_id = EVP_PKEY_MLDSA87;
      digest = EVP_sha512();
      cache_algorithm_name = "Mldsa87";
      break;
    case SignatureAlgorithm::kDilithium2:
      expected_pkey_id = EVP_PKEY_DILITHIUM2;
      digest = EVP_sha256();
      cache_algorithm_name = "Dilithium2";
      break;
    case SignatureAlgorithm::kDilithium3:
      expected_pkey_id = EVP_PKEY_DILITHIUM3;
      digest = EVP_sha384();
      cache_algorithm_name = "Dilithium3";
      break;
    case SignatureAlgorithm::kDilithium5:
      expected_pkey_id = EVP_PKEY_DILITHIUM5;
      digest = EVP_sha512();
      cache_algorithm_name = "Dilithium5";
      break;
    case SignatureAlgorithm::kFalcon512:
      expected_pkey_id = EVP_PKEY_FALCON512;
      digest = EVP_sha256();
      cache_algorithm_name = "Falcon512";
      break;
    case SignatureAlgorithm::kFalconpadded512:
      expected_pkey_id = EVP_PKEY_FALCONPADDED512;
      digest = EVP_sha256();
      cache_algorithm_name = "Falconpadded512";
      break;
    case SignatureAlgorithm::kFalcon1024:
      expected_pkey_id = EVP_PKEY_FALCON1024;
      digest = EVP_sha512();
      cache_algorithm_name = "Falcon1024";
      break;
    case SignatureAlgorithm::kFalconpadded1024:
      expected_pkey_id = EVP_PKEY_FALCONPADDED1024;
      digest = EVP_sha512();
      cache_algorithm_name = "Falconpadded1024";
      break;
    case SignatureAlgorithm::kSphincssha2128fsimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHA2128FSIMPLE;
      digest = EVP_sha256();
      cache_algorithm_name = "Sphincssha2128fsimple";
      break;
    case SignatureAlgorithm::kSphincssha2128ssimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHA2128SSIMPLE;
      digest = EVP_sha256();
      cache_algorithm_name = "Sphincssha2128ssimple";
      break;
    case SignatureAlgorithm::kSphincssha2192fsimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHA2192FSIMPLE;
      digest = EVP_sha384();
      cache_algorithm_name = "Sphincssha2192fsimple";
      break;
    case SignatureAlgorithm::kSphincssha2192ssimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHA2192SSIMPLE;
      digest = EVP_sha384();
      cache_algorithm_name = "Sphincssha2192ssimple";
      break;
    case SignatureAlgorithm::kSphincssha2256fsimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHA2256FSIMPLE;
      digest = EVP_sha512();
      cache_algorithm_name = "Sphincssha2256fsimple";
      break;
    case SignatureAlgorithm::kSphincssha2256ssimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHA2256SSIMPLE;
      digest = EVP_sha512();
      cache_algorithm_name = "Sphincssha2256ssimple";
      break;
    case SignatureAlgorithm::kSphincsshake128fsimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHAKE128FSIMPLE;
      digest = EVP_sha256();
      cache_algorithm_name = "Sphincsshake128fsimple";
      break;
    case SignatureAlgorithm::kSphincsshake128ssimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHAKE128SSIMPLE;
      digest = EVP_sha256();
      cache_algorithm_name = "Sphincsshake128ssimple";
      break;
    case SignatureAlgorithm::kSphincsshake192fsimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHAKE192FSIMPLE;
      digest = EVP_sha384();
      cache_algorithm_name = "Sphincsshake192fsimple";
      break;
    case SignatureAlgorithm::kSphincsshake192ssimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHAKE192SSIMPLE;
      digest = EVP_sha384();
      cache_algorithm_name = "Sphincsshake192ssimple";
      break;
    case SignatureAlgorithm::kSphincsshake256fsimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHAKE256FSIMPLE;
      digest = EVP_sha512();
      cache_algorithm_name = "Sphincsshake256fsimple";
      break;
    case SignatureAlgorithm::kSphincsshake256ssimple:
      expected_pkey_id = EVP_PKEY_SPHINCSSHAKE256SSIMPLE;
      digest = EVP_sha512();
      cache_algorithm_name = "Sphincsshake256ssimple";
      break;
///// OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END

    case SignatureAlgorithm::kRsaPssSha256:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha256();
      cache_algorithm_name = "RsaPssSha256";
      is_rsa_pss = true;
      break;
    case SignatureAlgorithm::kRsaPssSha384:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha384();
      cache_algorithm_name = "RsaPssSha384";
      is_rsa_pss = true;
      break;
    case SignatureAlgorithm::kRsaPssSha512:
      expected_pkey_id = EVP_PKEY_RSA;
      digest = EVP_sha512();
      cache_algorithm_name = "RsaPssSha512";
      is_rsa_pss = true;
      break;
  }

  if (expected_pkey_id != EVP_PKEY_id(public_key)) {
    return false;
  }

  // For the supported algorithms the signature value must be a whole
  // number of bytes.
  if (signature_value.unused_bits() != 0) {
    return false;
  }
  der::Input signature_value_bytes = signature_value.bytes();

  std::string cache_key;
  if (cache) {
    cache_key = SignatureVerifyCacheKey(cache_algorithm_name, signed_data,
                                        signature_value_bytes, public_key);
    if (!cache_key.empty()) {
      switch (cache->Check(cache_key)) {
        case SignatureVerifyCache::Value::kValid:
          return true;
        case SignatureVerifyCache::Value::kInvalid:
          return false;
        case SignatureVerifyCache::Value::kUnknown:
          break;
      }
    }
  }

  bool ret;
  if (IS_OQS_PKEY(expected_pkey_id)) {
    ret = oqs_verify_sig(public_key, signature_value_bytes.data(), signature_value_bytes.size(), signed_data.data(), signed_data.size()) ? true : false;
  } else {
  OpenSSLErrStackTracer err_tracer;

  bssl::ScopedEVP_MD_CTX ctx;
  EVP_PKEY_CTX *pctx = nullptr;  // Owned by |ctx|.

  if (!EVP_DigestVerifyInit(ctx.get(), &pctx, digest, nullptr, public_key)) {
    return false;
  }

  if (is_rsa_pss) {
    // All supported RSASSA-PSS algorithms match signing and MGF-1 digest. They
    // also use the digest length as the salt length, which is specified with -1
    // in OpenSSL's API.
    if (!EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) ||
        !EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1)) {
      return false;
    }
  }

  ret = 1 == EVP_DigestVerify(ctx.get(), signature_value_bytes.data(),
                              signature_value_bytes.size(),
                              signed_data.data(), signed_data.size());
  }
  if (!cache_key.empty()) {
    cache->Store(cache_key, ret ? SignatureVerifyCache::Value::kValid
                                : SignatureVerifyCache::Value::kInvalid);
  }

  return ret;
}

bool VerifySignedData(SignatureAlgorithm algorithm, der::Input signed_data,
                      const der::BitString &signature_value,
                      der::Input public_key_spki, SignatureVerifyCache *cache) {
  bssl::UniquePtr<EVP_PKEY> public_key;
  if (!ParsePublicKey(public_key_spki, &public_key)) {
    return false;
  }
  return VerifySignedData(algorithm, signed_data, signature_value,
                          public_key.get(), cache);
}

}  // namespace bssl
