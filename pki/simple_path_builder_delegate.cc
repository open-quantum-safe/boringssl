// Copyright 2017 The Chromium Authors
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

#include "simple_path_builder_delegate.h"

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/pki/signature_verify_cache.h>
#include <openssl/rsa.h>

#include "cert_error_params.h"
#include "cert_errors.h"
#include "signature_algorithm.h"
#include "verify_signed_data.h"

BSSL_NAMESPACE_BEGIN

DEFINE_CERT_ERROR_ID(SimplePathBuilderDelegate::kRsaModulusTooSmall,
                     "RSA modulus too small");

namespace {

DEFINE_CERT_ERROR_ID(kUnacceptableCurveForEcdsa,
                     "Only P-256, P-384, P-521 are supported for ECDSA");

bool IsAcceptableCurveForEcdsa(int curve_nid) {
  switch (curve_nid) {
    case NID_X9_62_prime256v1:
    case NID_secp384r1:
    case NID_secp521r1:
      return true;
  }

  return false;
}

}  // namespace

SimplePathBuilderDelegate::SimplePathBuilderDelegate(
    size_t min_rsa_modulus_length_bits, DigestPolicy digest_policy)
    : min_rsa_modulus_length_bits_(min_rsa_modulus_length_bits),
      digest_policy_(digest_policy) {}

void SimplePathBuilderDelegate::CheckPathAfterVerification(
    const CertPathBuilder &path_builder, CertPathBuilderResultPath *path) {
  // Do nothing - consider all candidate paths valid.
}

bool SimplePathBuilderDelegate::IsDeadlineExpired() { return false; }

bool SimplePathBuilderDelegate::IsDebugLogEnabled() { return false; }

bool SimplePathBuilderDelegate::AcceptPreCertificates() { return false; }

void SimplePathBuilderDelegate::DebugLog(std::string_view msg) {}

SignatureVerifyCache *SimplePathBuilderDelegate::GetVerifyCache() {
  return nullptr;
}

bool SimplePathBuilderDelegate::IsSignatureAlgorithmAcceptable(
    SignatureAlgorithm algorithm, CertErrors *errors) {
  switch (algorithm) {
    case SignatureAlgorithm::kRsaPkcs1Sha1:
    case SignatureAlgorithm::kEcdsaSha1:
      return digest_policy_ == DigestPolicy::kWeakAllowSha1;

    case SignatureAlgorithm::kRsaPkcs1Sha256:
    case SignatureAlgorithm::kRsaPkcs1Sha384:
    case SignatureAlgorithm::kRsaPkcs1Sha512:
    case SignatureAlgorithm::kEcdsaSha256:
    case SignatureAlgorithm::kEcdsaSha384:
    case SignatureAlgorithm::kEcdsaSha512:
///// OQS_TEMPLATE_FRAGMENT_LIST_SIGS_START
    case SignatureAlgorithm::kMldsa44:
    case SignatureAlgorithm::kP256_mldsa44:
    case SignatureAlgorithm::kMldsa65:
    case SignatureAlgorithm::kP384_mldsa65:
    case SignatureAlgorithm::kMldsa87:
    case SignatureAlgorithm::kP521_mldsa87:
    case SignatureAlgorithm::kFalcon512:
    case SignatureAlgorithm::kRsa3072_falcon512:
    case SignatureAlgorithm::kFalconpadded512:
    case SignatureAlgorithm::kFalcon1024:
    case SignatureAlgorithm::kFalconpadded1024:
    case SignatureAlgorithm::kMayo1:
    case SignatureAlgorithm::kMayo2:
    case SignatureAlgorithm::kMayo3:
    case SignatureAlgorithm::kMayo5:
    case SignatureAlgorithm::kOv_ip_pkc:
    case SignatureAlgorithm::kOv_ip_pkc_skc:
    case SignatureAlgorithm::kCrossrsdp128balanced:
    case SignatureAlgorithm::kSnova2454:
    case SignatureAlgorithm::kSnova2454esk:
    case SignatureAlgorithm::kSnova37172:
    case SignatureAlgorithm::kSnova2455:
    case SignatureAlgorithm::kSnova2965:
    case SignatureAlgorithm::kSphincssha2128fsimple:
    case SignatureAlgorithm::kSphincssha2128ssimple:
    case SignatureAlgorithm::kSphincssha2192fsimple:
    case SignatureAlgorithm::kSphincssha2192ssimple:
    case SignatureAlgorithm::kSphincssha2256fsimple:
    case SignatureAlgorithm::kSphincssha2256ssimple:
    case SignatureAlgorithm::kSphincsshake128fsimple:
    case SignatureAlgorithm::kSphincsshake128ssimple:
    case SignatureAlgorithm::kSphincsshake192fsimple:
    case SignatureAlgorithm::kSphincsshake192ssimple:
    case SignatureAlgorithm::kSphincsshake256fsimple:
    case SignatureAlgorithm::kSphincsshake256ssimple:
///// OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END
    case SignatureAlgorithm::kRsaPssSha256:
    case SignatureAlgorithm::kRsaPssSha384:
    case SignatureAlgorithm::kRsaPssSha512:
      return true;
  }
  return false;
}

bool SimplePathBuilderDelegate::IsPublicKeyAcceptable(EVP_PKEY *public_key,
                                                      CertErrors *errors) {
  int pkey_id = EVP_PKEY_id(public_key);
  if (pkey_id == EVP_PKEY_RSA) {
    // Extract the modulus length from the key.
    RSA *rsa = EVP_PKEY_get0_RSA(public_key);
    if (!rsa) {
      return false;
    }
    unsigned int modulus_length_bits = RSA_bits(rsa);

    if (modulus_length_bits < min_rsa_modulus_length_bits_) {
      errors->AddWarning(
          kRsaModulusTooSmall,
          CreateCertErrorParams2SizeT("actual", modulus_length_bits, "minimum",
                                      min_rsa_modulus_length_bits_));
      return false;
    }

    return true;
  }

  if (pkey_id == EVP_PKEY_EC) {
    // Extract the curve name.
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(public_key);
    if (!ec) {
      return false;  // Unexpected.
    }
    int curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));

    if (!IsAcceptableCurveForEcdsa(curve_nid)) {
      errors->AddWarning(kUnacceptableCurveForEcdsa);
      return false;
    }

    return true;
  }

  if (IS_OQS_PKEY(pkey_id)) {
    return true;
  }

  // Unexpected key type.
  return false;
}

BSSL_NAMESPACE_END
