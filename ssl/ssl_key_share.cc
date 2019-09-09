/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <utility>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/hrss.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>

#include "internal.h"
#include "../crypto/internal.h"
#include "../third_party/sike/sike.h"

#include <oqs/oqs.h>

BSSL_NAMESPACE_BEGIN

namespace {

class ECKeyShare : public SSLKeyShare {
 public:
  ECKeyShare(int nid, uint16_t group_id) : nid_(nid), group_id_(group_id) {}

  uint16_t GroupID() const override { return group_id_; }

  bool Offer(CBB *out) override {
    assert(!private_key_);
    // Set up a shared |BN_CTX| for all operations.
    UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
    if (!bn_ctx) {
      return false;
    }
    BN_CTXScope scope(bn_ctx.get());

    // Generate a private key.
    UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid_));
    private_key_.reset(BN_new());
    if (!group || !private_key_ ||
        !BN_rand_range_ex(private_key_.get(), 1,
                          EC_GROUP_get0_order(group.get()))) {
      return false;
    }

    // Compute the corresponding public key and serialize it.
    UniquePtr<EC_POINT> public_key(EC_POINT_new(group.get()));
    if (!public_key ||
        !EC_POINT_mul(group.get(), public_key.get(), private_key_.get(), NULL,
                      NULL, bn_ctx.get()) ||
        !EC_POINT_point2cbb(out, group.get(), public_key.get(),
                            POINT_CONVERSION_UNCOMPRESSED, bn_ctx.get())) {
      return false;
    }

    return true;
  }

  bool Finish(Array<uint8_t> *out_secret, uint8_t *out_alert,
              Span<const uint8_t> peer_key) override {
    assert(private_key_);
    *out_alert = SSL_AD_INTERNAL_ERROR;

    // Set up a shared |BN_CTX| for all operations.
    UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
    if (!bn_ctx) {
      return false;
    }
    BN_CTXScope scope(bn_ctx.get());

    UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid_));
    if (!group) {
      return false;
    }

    UniquePtr<EC_POINT> peer_point(EC_POINT_new(group.get()));
    UniquePtr<EC_POINT> result(EC_POINT_new(group.get()));
    BIGNUM *x = BN_CTX_get(bn_ctx.get());
    if (!peer_point || !result || !x) {
      return false;
    }

    if (peer_key.empty() || peer_key[0] != POINT_CONVERSION_UNCOMPRESSED ||
        !EC_POINT_oct2point(group.get(), peer_point.get(), peer_key.data(),
                            peer_key.size(), bn_ctx.get())) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      *out_alert = SSL_AD_DECODE_ERROR;
      return false;
    }

    // Compute the x-coordinate of |peer_key| * |private_key_|.
    if (!EC_POINT_mul(group.get(), result.get(), NULL, peer_point.get(),
                      private_key_.get(), bn_ctx.get()) ||
        !EC_POINT_get_affine_coordinates_GFp(group.get(), result.get(), x, NULL,
                                             bn_ctx.get())) {
      return false;
    }

    // Encode the x-coordinate left-padded with zeros.
    Array<uint8_t> secret;
    if (!secret.Init((EC_GROUP_get_degree(group.get()) + 7) / 8) ||
        !BN_bn2bin_padded(secret.data(), secret.size(), x)) {
      return false;
    }

    *out_secret = std::move(secret);
    return true;
  }

  bool Serialize(CBB *out) override {
    assert(private_key_);
    CBB cbb;
    UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid_));
    // Padding is added to avoid leaking the length.
    size_t len = BN_num_bytes(EC_GROUP_get0_order(group.get()));
    if (!CBB_add_asn1_uint64(out, group_id_) ||
        !CBB_add_asn1(out, &cbb, CBS_ASN1_OCTETSTRING) ||
        !BN_bn2cbb_padded(&cbb, len, private_key_.get()) ||
        !CBB_flush(out)) {
      return false;
    }
    return true;
  }

  bool Deserialize(CBS *in) override {
    assert(!private_key_);
    CBS private_key;
    if (!CBS_get_asn1(in, &private_key, CBS_ASN1_OCTETSTRING)) {
      return false;
    }
    private_key_.reset(BN_bin2bn(CBS_data(&private_key),
                                 CBS_len(&private_key), nullptr));
    return private_key_ != nullptr;
  }

 private:
  UniquePtr<BIGNUM> private_key_;
  int nid_;
  uint16_t group_id_;
};

class X25519KeyShare : public SSLKeyShare {
 public:
  X25519KeyShare() {}

  uint16_t GroupID() const override { return SSL_CURVE_X25519; }

  bool Offer(CBB *out) override {
    uint8_t public_key[32];
    X25519_keypair(public_key, private_key_);
    return !!CBB_add_bytes(out, public_key, sizeof(public_key));
  }

  bool Finish(Array<uint8_t> *out_secret, uint8_t *out_alert,
              Span<const uint8_t> peer_key) override {
    *out_alert = SSL_AD_INTERNAL_ERROR;

    Array<uint8_t> secret;
    if (!secret.Init(32)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    if (peer_key.size() != 32 ||
        !X25519(secret.data(), private_key_, peer_key.data())) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    *out_secret = std::move(secret);
    return true;
  }

  bool Serialize(CBB *out) override {
    return (CBB_add_asn1_uint64(out, GroupID()) &&
            CBB_add_asn1_octet_string(out, private_key_, sizeof(private_key_)));
  }

  bool Deserialize(CBS *in) override {
    CBS key;
    if (!CBS_get_asn1(in, &key, CBS_ASN1_OCTETSTRING) ||
        CBS_len(&key) != sizeof(private_key_) ||
        !CBS_copy_bytes(&key, private_key_, sizeof(private_key_))) {
      return false;
    }
    return true;
  }

 private:
  uint8_t private_key_[32];
};

class CECPQ2KeyShare : public SSLKeyShare {
 public:
  CECPQ2KeyShare() {}

  uint16_t GroupID() const override { return SSL_CURVE_CECPQ2; }

  bool Offer(CBB *out) override {
    uint8_t x25519_public_key[32];
    X25519_keypair(x25519_public_key, x25519_private_key_);

    uint8_t hrss_entropy[HRSS_GENERATE_KEY_BYTES];
    HRSS_public_key hrss_public_key;
    RAND_bytes(hrss_entropy, sizeof(hrss_entropy));
    HRSS_generate_key(&hrss_public_key, &hrss_private_key_, hrss_entropy);

    uint8_t hrss_public_key_bytes[HRSS_PUBLIC_KEY_BYTES];
    HRSS_marshal_public_key(hrss_public_key_bytes, &hrss_public_key);

    if (!CBB_add_bytes(out, x25519_public_key, sizeof(x25519_public_key)) ||
        !CBB_add_bytes(out, hrss_public_key_bytes,
                       sizeof(hrss_public_key_bytes))) {
      return false;
    }

    return true;
  }

  bool Accept(CBB *out_public_key, Array<uint8_t> *out_secret,
              uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    Array<uint8_t> secret;
    if (!secret.Init(32 + HRSS_KEY_BYTES)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    uint8_t x25519_public_key[32];
    X25519_keypair(x25519_public_key, x25519_private_key_);

    HRSS_public_key peer_public_key;
    if (peer_key.size() != 32 + HRSS_PUBLIC_KEY_BYTES ||
        !HRSS_parse_public_key(&peer_public_key, peer_key.data() + 32) ||
        !X25519(secret.data(), x25519_private_key_, peer_key.data())) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    uint8_t ciphertext[HRSS_CIPHERTEXT_BYTES];
    uint8_t entropy[HRSS_ENCAP_BYTES];
    RAND_bytes(entropy, sizeof(entropy));
    HRSS_encap(ciphertext, secret.data() + 32, &peer_public_key, entropy);

    if (!CBB_add_bytes(out_public_key, x25519_public_key,
                       sizeof(x25519_public_key)) ||
        !CBB_add_bytes(out_public_key, ciphertext, sizeof(ciphertext))) {
      return false;
    }

    *out_secret = std::move(secret);
    return true;
  }

  bool Finish(Array<uint8_t> *out_secret, uint8_t *out_alert,
              Span<const uint8_t> peer_key) override {
    *out_alert = SSL_AD_INTERNAL_ERROR;

    Array<uint8_t> secret;
    if (!secret.Init(32 + HRSS_KEY_BYTES)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    if (peer_key.size() != 32 + HRSS_CIPHERTEXT_BYTES ||
        !X25519(secret.data(), x25519_private_key_, peer_key.data())) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    HRSS_decap(secret.data() + 32, &hrss_private_key_, peer_key.data() + 32,
               peer_key.size() - 32);

    *out_secret = std::move(secret);
    return true;
  }

 private:
  uint8_t x25519_private_key_[32];
  HRSS_private_key hrss_private_key_;
};

class CECPQ2bKeyShare : public SSLKeyShare {
 public:
  uint16_t GroupID() const override { return SSL_CURVE_CECPQ2b; }

  bool Offer(CBB *out) override {
    uint8_t public_x25519[32] = {0};
    X25519_keypair(public_x25519, private_x25519_);
    if (!SIKE_keypair(private_sike_, public_sike_)) {
      return false;
    }

    return CBB_add_bytes(out, public_x25519, sizeof(public_x25519)) &&
           CBB_add_bytes(out, public_sike_, sizeof(public_sike_));
  }

  bool Accept(CBB *out_public_key, Array<uint8_t> *out_secret,
              uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    uint8_t public_x25519[32];
    uint8_t private_x25519[32];
    uint8_t sike_ciphertext[SIKE_CT_BYTESZ] = {0};

    *out_alert = SSL_AD_INTERNAL_ERROR;

    if (peer_key.size() != sizeof(public_x25519) + SIKE_PUB_BYTESZ) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    Array<uint8_t> secret;
    if (!secret.Init(sizeof(private_x25519_) + SIKE_SS_BYTESZ)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    X25519_keypair(public_x25519, private_x25519);
    if (!X25519(secret.data(), private_x25519, peer_key.data())) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    SIKE_encaps(secret.data() + sizeof(private_x25519_), sike_ciphertext,
                peer_key.data() + sizeof(public_x25519));
    *out_secret = std::move(secret);

    return CBB_add_bytes(out_public_key, public_x25519,
                         sizeof(public_x25519)) &&
           CBB_add_bytes(out_public_key, sike_ciphertext,
                         sizeof(sike_ciphertext));
  }

  bool Finish(Array<uint8_t> *out_secret, uint8_t *out_alert,
              Span<const uint8_t> peer_key) override {
    *out_alert = SSL_AD_INTERNAL_ERROR;

    Array<uint8_t> secret;
    if (!secret.Init(sizeof(private_x25519_) + SIKE_SS_BYTESZ)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    if (peer_key.size() != 32 + SIKE_CT_BYTESZ ||
        !X25519(secret.data(), private_x25519_, peer_key.data())) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    SIKE_decaps(secret.data() + sizeof(private_x25519_), peer_key.data() + 32,
                public_sike_, private_sike_);
    *out_secret = std::move(secret);
    return true;
  }

 private:
  uint8_t private_x25519_[32];
  uint8_t private_sike_[SIKE_PRV_BYTESZ];
  uint8_t public_sike_[SIKE_PUB_BYTESZ];
};

// KeyShare class for OQS supplied hybrid and post-quantum crypto algs
// Hybrid messages are encoded as follows: classical_len | classical_artifact | pq_len | pq_artifact
// TODOs (FIXMEOQS):
// * make sure the format is the same as in the OpenSSL fork, i.e., put length of key, etc.
class OQSKeyShare : public SSLKeyShare {
 public:
  // Although oqs_meth can be determined from the group_id,
  // we pass both in as the translation from group_id to
  // oqs_meth is already done by SLKeyShare::Create
  // to determine whether oqs_meth is enabled in liboqs
  // and return nullptr if not. It is easier to handle
  // the error in there as opposed to in this constructor.
  OQSKeyShare(uint16_t group_id, const char *oqs_meth, bool is_hybrid) : group_id_(group_id), is_hybrid_(is_hybrid) {
    pq_kex_= OQS_KEM_new(oqs_meth);
    if (is_hybrid_) {
      classical_kex_ = SSLKeyShare::Create(SSL_CURVE_SECP256R1);
    }
  }

  uint16_t GroupID() const override { return group_id_; }

  bool Offer(CBB *out) override {
    Array<uint8_t> classical_public_key;
    Array<uint8_t> pq_public_key;

    // For a hybrid KEX, generate the classical keys first
    if (is_hybrid_) {
      ScopedCBB classical_offer;
      if (!CBB_init(classical_offer.get(), p256_public_key_size_) ||
          !classical_kex_->Offer(classical_offer.get()) ||
          !CBBFinishArray(classical_offer.get(), &classical_public_key)) {
        // the classical code will set the appropriate error on failure
        return false;
      }
    }
    // Generate the PQ key pair.
    if (!pq_public_key.Init(pq_kex_->length_public_key) ||
        !pq_private_key_.Init(pq_kex_->length_secret_key)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }
    if (OQS_KEM_keypair(pq_kex_, pq_public_key.data(), pq_private_key_.data()) != OQS_SUCCESS) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_PRIVATE_KEY_OPERATION_FAILED);
      return false;
    }
    if (is_hybrid_) {
      if (!CBB_add_u32(out, classical_public_key.size()) ||
          !CBB_add_bytes(out, classical_public_key.data(), classical_public_key.size()) ||
          !CBB_add_u32(out, pq_kex_->length_public_key)) {
        return false;
      }
    }
    // Serialize the PQ public key.
    if (!CBB_add_bytes(out, pq_public_key.data(), pq_kex_->length_public_key)) {
      return false;
    }

    return true;
  }

  bool Accept(CBB *out_public_key, Array<uint8_t> *out_secret,
              uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    Array<uint8_t> classical_public_key;
    Array<uint8_t> classical_secret;
    Array<uint8_t> secret;
    Array<uint8_t> ciphertext;

    // Validate peer key size.
    if (peer_key.size() != pq_kex_->length_public_key + (is_hybrid_ ? 8 + p256_public_key_size_ : 0)) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    // OQS note: in hybrid case, we allocate space for both the classical and PQ secret. Since we
    // currently only support P-256, we can hardcode the classical secret size of 32; more generally
    // this might not work. We prefer this now because there are no concat Array method to make this simple.
    size_t classical_secret_size = is_hybrid_ ? 32 : 0;
    if (!secret.Init(classical_secret_size + pq_kex_->length_shared_secret) ||
        !ciphertext.Init(pq_kex_->length_ciphertext)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    // In the hybrid case, first handle the classical Accept
    if (is_hybrid_) {
      ScopedCBB out_classical_public_key;
      if (!CBB_init(out_classical_public_key.get(), p256_public_key_size_) ||
          !classical_kex_->Accept(out_classical_public_key.get(), &classical_secret, out_alert, peer_key.subspan(4, p256_public_key_size_)) ||
          !CBBFinishArray(out_classical_public_key.get(), &classical_public_key)) {
        // the classical code will set the appropriate alert and error on failure
        return false;
      }
      OPENSSL_memcpy(secret.data(), classical_secret.data(), classical_secret.size());
    }

    // compute the servers's shared secret and message (encoded in encoded_point)
    const uint8_t *public_key = is_hybrid_ ? peer_key.subspan(8 + p256_public_key_size_, pq_kex_->length_ciphertext).data() : peer_key.data();
    if (OQS_KEM_encaps(pq_kex_, ciphertext.data(), secret.data() + classical_secret_size, public_key) != OQS_SUCCESS) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    if (is_hybrid_) {
      if (!CBB_add_u32(out_public_key, classical_public_key.size()) ||
          !CBB_add_bytes(out_public_key, classical_public_key.data(), classical_public_key.size()) ||
          !CBB_add_u32(out_public_key, pq_kex_->length_ciphertext)) {
        return false;
      }
    }
    if (!CBB_add_bytes(out_public_key, ciphertext.data(), pq_kex_->length_ciphertext)) {
      return false;
    }

    *out_secret = std::move(secret);

    return true;
  }

  bool Finish(Array<uint8_t> *out_secret, uint8_t *out_alert,
              Span<const uint8_t> peer_key) override {
    Array<uint8_t> classical_secret;
    Array<uint8_t> secret;
    *out_alert = SSL_AD_INTERNAL_ERROR;

    // Validate peer key size.
    if (peer_key.size() != pq_kex_->length_ciphertext + (is_hybrid_ ? 8 + p256_public_key_size_ : 0)) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    // OQS note: in hybrid case, we allocate space for both the classical and PQ secret. Since we
    // currently only support P-256, we can hardcode the classical secret size of 32; more generally
    // this might not work. We prefer this now because there are no concat Array method to make this simple.
    int classical_secret_size = is_hybrid_ ? 32 : 0;
    if (!secret.Init(classical_secret_size + pq_kex_->length_shared_secret)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    // In the hybrid case, first handle the classical Finish
    if (is_hybrid_) {
      if (!classical_kex_->Finish(&classical_secret, out_alert, peer_key.subspan(4, p256_public_key_size_))) {
return false;
     }
      OPENSSL_memcpy(secret.data(), classical_secret.data(), classical_secret.size());
    }

    const uint8_t *public_key = is_hybrid_ ? peer_key.subspan(8 + p256_public_key_size_, pq_kex_->length_ciphertext).data() : peer_key.data();
    if (OQS_KEM_decaps(pq_kex_, secret.data() + classical_secret_size, public_key, pq_private_key_.data()) != OQS_SUCCESS) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    *out_secret = std::move(secret);

    return true;
  }

 private:
  uint16_t group_id_;

  OQS_KEM* pq_kex_;
  Array<uint8_t> pq_private_key_;

  bool is_hybrid_;
  UniquePtr<SSLKeyShare> classical_kex_;

  const int p256_public_key_size_ = 65;
};

CONSTEXPR_ARRAY NamedGroup kNamedGroups[] = {
    {NID_secp224r1, SSL_CURVE_SECP224R1, "P-224", "secp224r1"},
    {NID_X9_62_prime256v1, SSL_CURVE_SECP256R1, "P-256", "prime256v1"},
    {NID_secp384r1, SSL_CURVE_SECP384R1, "P-384", "secp384r1"},
    {NID_secp521r1, SSL_CURVE_SECP521R1, "P-521", "secp521r1"},
    {NID_X25519, SSL_CURVE_X25519, "X25519", "x25519"},
    {NID_CECPQ2, SSL_CURVE_CECPQ2, "CECPQ2", "CECPQ2"},
    {NID_CECPQ2b, SSL_CURVE_CECPQ2b, "CECPQ2b", "CECPQ2b"},
///// OQS_TEMPLATE_FRAGMENT_DEF_NAMEDGROUPS_START
    {NID_oqs_kemdefault, SSL_CURVE_OQS_KEMDEFAULT, "oqs_kemdefault", "oqs_kemdefault"},
    {NID_oqs_p256_kemdefault, SSL_CURVE_OQS_P256_KEMDEFAULT, "oqs_p256_kemdefault", "oqs_p256_kemdefault"},
///// OQS_TEMPLATE_FRAGMENT_DEF_NAMEDGROUPS_END
};

}  // namespace

Span<const NamedGroup> NamedGroups() {
  return MakeConstSpan(kNamedGroups, OPENSSL_ARRAY_SIZE(kNamedGroups));
}

UniquePtr<SSLKeyShare> SSLKeyShare::Create(uint16_t group_id) {
  switch (group_id) {
    case SSL_CURVE_SECP224R1:
      return UniquePtr<SSLKeyShare>(
          New<ECKeyShare>(NID_secp224r1, SSL_CURVE_SECP224R1));
    case SSL_CURVE_SECP256R1:
      return UniquePtr<SSLKeyShare>(
          New<ECKeyShare>(NID_X9_62_prime256v1, SSL_CURVE_SECP256R1));
    case SSL_CURVE_SECP384R1:
      return UniquePtr<SSLKeyShare>(
          New<ECKeyShare>(NID_secp384r1, SSL_CURVE_SECP384R1));
    case SSL_CURVE_SECP521R1:
      return UniquePtr<SSLKeyShare>(
          New<ECKeyShare>(NID_secp521r1, SSL_CURVE_SECP521R1));
    case SSL_CURVE_X25519:
      return UniquePtr<SSLKeyShare>(New<X25519KeyShare>());
    case SSL_CURVE_CECPQ2:
      return UniquePtr<SSLKeyShare>(New<CECPQ2KeyShare>());
    case SSL_CURVE_CECPQ2b:
      return UniquePtr<SSLKeyShare>(New<CECPQ2bKeyShare>());
///// OQS_TEMPLATE_FRAGMENT_HANDLE_GROUP_IDS_START
    case SSL_CURVE_OQS_KEMDEFAULT:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_default))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_OQS_KEMDEFAULT, OQS_KEM_alg_default, false));
      else
          return nullptr;
    case SSL_CURVE_OQS_P256_KEMDEFAULT:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_default))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_OQS_P256_KEMDEFAULT, OQS_KEM_alg_default, true));
      else
          return nullptr;
///// OQS_TEMPLATE_FRAGMENT_HANDLE_GROUP_IDS_START
    default:
      return nullptr;
  }
}

UniquePtr<SSLKeyShare> SSLKeyShare::Create(CBS *in) {
  uint64_t group;
  if (!CBS_get_asn1_uint64(in, &group) || group > 0xffff) {
    return nullptr;
  }
  UniquePtr<SSLKeyShare> key_share = Create(static_cast<uint16_t>(group));
  if (!key_share || !key_share->Deserialize(in)) {
    return nullptr;
  }
  return key_share;
}


bool SSLKeyShare::Accept(CBB *out_public_key, Array<uint8_t> *out_secret,
                         uint8_t *out_alert, Span<const uint8_t> peer_key) {
  *out_alert = SSL_AD_INTERNAL_ERROR;
  return Offer(out_public_key) &&
         Finish(out_secret, out_alert, peer_key);
}

bool ssl_nid_to_group_id(uint16_t *out_group_id, int nid) {
  for (const auto &group : kNamedGroups) {
    if (group.nid == nid) {
      *out_group_id = group.group_id;
      return true;
    }
  }
  return false;
}

bool ssl_name_to_group_id(uint16_t *out_group_id, const char *name, size_t len) {
  for (const auto &group : kNamedGroups) {
    if (len == strlen(group.name) &&
        !strncmp(group.name, name, len)) {
      *out_group_id = group.group_id;
      return true;
    }
    if (len == strlen(group.alias) &&
        !strncmp(group.alias, name, len)) {
      *out_group_id = group.group_id;
      return true;
    }
  }
  return false;
}

BSSL_NAMESPACE_END

using namespace bssl;

const char* SSL_get_curve_name(uint16_t group_id) {
  for (const auto &group : kNamedGroups) {
    if (group.group_id == group_id) {
      return group.name;
    }
  }
  return nullptr;
}
