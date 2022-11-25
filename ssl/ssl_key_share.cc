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

  bool SerializePrivateKey(CBB *out) override {
    assert(private_key_);
    UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid_));
    // Padding is added to avoid leaking the length.
    size_t len = BN_num_bytes(EC_GROUP_get0_order(group.get()));
    return BN_bn2cbb_padded(out, len, private_key_.get());
  }

  bool DeserializePrivateKey(CBS *in) override {
    assert(!private_key_);
    private_key_.reset(BN_bin2bn(CBS_data(in), CBS_len(in), nullptr));
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

  bool SerializePrivateKey(CBB *out) override {
    return CBB_add_bytes(out, private_key_, sizeof(private_key_));
  }

  bool DeserializePrivateKey(CBS *in) override {
    if (CBS_len(in) != sizeof(private_key_) ||
        !CBS_copy_bytes(in, private_key_, sizeof(private_key_))) {
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
    if (!HRSS_generate_key(&hrss_public_key, &hrss_private_key_,
                           hrss_entropy)) {
      return false;
    }

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

    if (!HRSS_encap(ciphertext, secret.data() + 32, &peer_public_key,
                    entropy) ||
        !CBB_add_bytes(out_public_key, x25519_public_key,
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

    if (!HRSS_decap(secret.data() + 32, &hrss_private_key_,
                    peer_key.data() + 32, peer_key.size() - 32)) {
      return false;
    }

    *out_secret = std::move(secret);
    return true;
  }

 private:
  uint8_t x25519_private_key_[32];
  HRSS_private_key hrss_private_key_;
};

// Class for key-exchange using OQS supplied
// post-quantum algorithms.
class OQSKeyShare : public SSLKeyShare {
 public:
  // While oqs_meth can be determined from the group_id,
  // we pass both in as the translation from group_id to
  // oqs_meth is already done by SSLKeyShare::Create to
  // to determine if oqs_meth is enabled in liboqs and
  // and return nullptr if not. It is easier to handle
  // the error in there as opposed to in this constructor.
  OQSKeyShare(uint16_t group_id, const char *oqs_meth) : group_id_(group_id) {
    oqs_kex_ = OQS_KEM_new(oqs_meth);
  }

  uint16_t GroupID() const override { return group_id_; }

  size_t length_public_key() {
    return oqs_kex_->length_public_key;
  }

  size_t length_ciphertext() {
    return oqs_kex_->length_ciphertext;
  }

  // Client sends its public key to server
  bool Offer(CBB *out) override {
    Array<uint8_t> public_key;

    if (!public_key.Init(oqs_kex_->length_public_key) ||
        !private_key_.Init(oqs_kex_->length_secret_key)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }
    if (OQS_KEM_keypair(oqs_kex_, public_key.data(), private_key_.data()) != OQS_SUCCESS) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_PRIVATE_KEY_OPERATION_FAILED);
      return false;
    }

    if (!CBB_add_bytes(out, public_key.data(), public_key.size())) {
      return false;
    }

    return true;
  }

  // Server computes shared secret under client's public key
  // and sends a ciphertext to client
  bool Accept(CBB *out_public_key, Array<uint8_t> *out_secret,
              uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    Array<uint8_t> shared_secret;
    Array<uint8_t> ciphertext;

    if (peer_key.size() != oqs_kex_->length_public_key) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    if (!shared_secret.Init(oqs_kex_->length_shared_secret) ||
        !ciphertext.Init(oqs_kex_->length_ciphertext)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    if (OQS_KEM_encaps(oqs_kex_, ciphertext.data(), shared_secret.data(), peer_key.data()) != OQS_SUCCESS) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    if (!CBB_add_bytes(out_public_key, ciphertext.data(), oqs_kex_->length_ciphertext)) {
      return false;
    }

    *out_secret = std::move(shared_secret);

    return true;
  }

  // Client decapsulates the ciphertext using its
  // private key to obtain the shared secret.
  bool Finish(Array<uint8_t> *out_secret, uint8_t *out_alert,
              Span<const uint8_t> peer_key) override {
    Array<uint8_t> shared_secret;

    if (peer_key.size() != oqs_kex_->length_ciphertext) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    if (!shared_secret.Init(oqs_kex_->length_shared_secret)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    if (OQS_KEM_decaps(oqs_kex_, shared_secret.data(), peer_key.data(), private_key_.data()) != OQS_SUCCESS) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    *out_secret = std::move(shared_secret);

    return true;
  }

  ~OQSKeyShare() {
      OQS_KEM_free(oqs_kex_);
  }

 private:
  uint16_t group_id_;

  OQS_KEM *oqs_kex_;
  Array<uint8_t> private_key_;
};

// Class for key-exchange using a classical key-exchange
// algorithm in hybrid mode with OQS supplied post-quantum
// algorithms. Following https://tools.ietf.org/html/draft-ietf-tls-hybrid-design-01#section-3.2
// hybrid messages are encoded as follows:
// classical_artifact | pq_artifact
class ClassicalWithOQSKeyShare : public SSLKeyShare {
 public:
  ClassicalWithOQSKeyShare(uint16_t group_id, uint16_t classical_group_id, const char *oqs_meth) : group_id_(group_id), classical_group_id_(classical_group_id), oqs_meth_(oqs_meth) {}

  uint16_t GroupID() const override { return group_id_; }

  bool Offer(CBB *out) override {
    if (!initCheck()) {
        return false;
    }

    ScopedCBB classical_offer;
    ScopedCBB pq_offer;

    if (!CBB_init(classical_offer.get(), 0) ||
        !classical_kex_->Offer(classical_offer.get()) ||
        !CBB_flush(classical_offer.get())) {
      // classical_kex_ will set the appropriate error on failure
      return false;
    }

    if (!CBB_init(pq_offer.get(), 0) ||
        !pq_kex_->Offer(pq_offer.get()) ||
        !CBB_flush(pq_offer.get())) {
      // pq_kex_ will set the appropriate error on failure
      return false;
    }

    if (!CBB_add_bytes(out, CBB_data(classical_offer.get()), CBB_len(classical_offer.get())) ||
        !CBB_add_bytes(out, CBB_data(pq_offer.get()), CBB_len(pq_offer.get()))) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    return true;
  }

  bool Accept(CBB *out_public_key, Array<uint8_t> *out_secret,
              uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    if (!initCheck()) {
        return false;
    }

    Array<uint8_t> out_classical_secret;
    ScopedCBB out_classical_public_key;

    Array<uint8_t> out_pq_secret;
    ScopedCBB out_pq_ciphertext;

    ScopedCBB out_secret_cbb;

    if (!CBB_init(out_classical_public_key.get(), classical_pub_size_) ||
        !classical_kex_->Accept(out_classical_public_key.get(), &out_classical_secret, out_alert, peer_key.subspan(0, classical_pub_size_)) ||
        !CBB_flush(out_classical_public_key.get())) {
      return false;
    }

    if (!CBB_init(out_pq_ciphertext.get(), 0) ||
        !pq_kex_->Accept(out_pq_ciphertext.get(), &out_pq_secret, out_alert, peer_key.subspan(classical_pub_size_, pq_kex_->length_public_key())) ||
        !CBB_flush(out_pq_ciphertext.get())) {
      return false;
    }

    if (!CBB_add_bytes(out_public_key, CBB_data(out_classical_public_key.get()), CBB_len(out_classical_public_key.get())) ||
        !CBB_add_bytes(out_public_key, CBB_data(out_pq_ciphertext.get()), CBB_len(out_pq_ciphertext.get()))) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    if (!CBB_init(out_secret_cbb.get(), out_classical_secret.size() + out_pq_secret.size()) ||
        !CBB_add_bytes(out_secret_cbb.get(), out_classical_secret.data(), out_classical_secret.size()) ||
        !CBB_add_bytes(out_secret_cbb.get(), out_pq_secret.data(), out_pq_secret.size()) ||
        !CBBFinishArray(out_secret_cbb.get(), out_secret)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }

    return true;
  }

  bool Finish(Array<uint8_t> *out_secret, uint8_t *out_alert,
              Span<const uint8_t> peer_key) override {
    if (!initCheck()) {
        return false;
    }

    ScopedCBB out_secret_cbb;

    Array<uint8_t> out_classical_secret;
    Array<uint8_t> out_pq_secret;

    if (!classical_kex_->Finish(&out_classical_secret, out_alert, peer_key.subspan(0, classical_pub_size_))) {
      return false;
    }

    if (!pq_kex_->Finish(&out_pq_secret, out_alert, peer_key.subspan(classical_pub_size_, pq_kex_->length_ciphertext()))) {
      return false;
    }

    if (!CBB_init(out_secret_cbb.get(), out_classical_secret.size() + out_pq_secret.size()) ||
        !CBB_add_bytes(out_secret_cbb.get(), out_classical_secret.data(), out_classical_secret.size()) ||
        !CBB_add_bytes(out_secret_cbb.get(), out_pq_secret.data(), out_pq_secret.size()) ||
        !CBBFinishArray(out_secret_cbb.get(), out_secret)) {
      return false;
    }

    return true;
  }

 private:
  uint16_t group_id_;
  uint16_t classical_group_id_;
  const char *oqs_meth_;

  UniquePtr<SSLKeyShare> classical_kex_ = nullptr;
  size_t classical_pub_size_ = 0;

  UniquePtr<OQSKeyShare> pq_kex_ = nullptr;

  bool initCheck() {
    if (!classical_kex_) {
        classical_kex_ = SSLKeyShare::Create(classical_group_id_);
        if (!classical_kex_) {
            OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
            return false;
        }
    }
    if (!pq_kex_) {
        pq_kex_ = MakeUnique<OQSKeyShare>(0, oqs_meth_); //We don't need pq_kex_->GroupID()
        if (!pq_kex_) {
            OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
            return false;
        }
    }
    if (!classical_pub_size_) {
        // TODO(oqs): This is hacky, but seems like the easiest way to go from
        // classical group ID -> classical public key size.
        UniquePtr<SSLKeyShare> tmp_kex = SSLKeyShare::Create(classical_group_id_);
        ScopedCBB tmp;
        if (!CBB_init(tmp.get(), 0) ||
            !tmp_kex->Offer(tmp.get()) ||
            !CBB_flush(tmp.get())) {
          OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
          return false;
        }
        classical_pub_size_ = CBB_len(tmp.get());
        if(!classical_pub_size_) {
            return false;
        }
    }
    return true;
  }
};

CONSTEXPR_ARRAY NamedGroup kNamedGroups[] = {
    {NID_secp224r1, SSL_CURVE_SECP224R1, "P-224", "secp224r1"},
    {NID_X9_62_prime256v1, SSL_CURVE_SECP256R1, "P-256", "prime256v1"},
    {NID_secp384r1, SSL_CURVE_SECP384R1, "P-384", "secp384r1"},
    {NID_secp521r1, SSL_CURVE_SECP521R1, "P-521", "secp521r1"},
    {NID_X25519, SSL_CURVE_X25519, "X25519", "x25519"},
    {NID_CECPQ2, SSL_CURVE_CECPQ2, "CECPQ2", "CECPQ2"},
///// OQS_TEMPLATE_FRAGMENT_DEF_NAMEDGROUPS_START
    {NID_frodo640aes, SSL_CURVE_FRODO640AES, "frodo640aes", "frodo640aes"},
    {NID_p256_frodo640aes, SSL_CURVE_P256_FRODO640AES, "p256_frodo640aes", "p256_frodo640aes"},
    {NID_frodo640shake, SSL_CURVE_FRODO640SHAKE, "frodo640shake", "frodo640shake"},
    {NID_p256_frodo640shake, SSL_CURVE_P256_FRODO640SHAKE, "p256_frodo640shake", "p256_frodo640shake"},
    {NID_frodo976aes, SSL_CURVE_FRODO976AES, "frodo976aes", "frodo976aes"},
    {NID_p384_frodo976aes, SSL_CURVE_P384_FRODO976AES, "p384_frodo976aes", "p384_frodo976aes"},
    {NID_frodo976shake, SSL_CURVE_FRODO976SHAKE, "frodo976shake", "frodo976shake"},
    {NID_p384_frodo976shake, SSL_CURVE_P384_FRODO976SHAKE, "p384_frodo976shake", "p384_frodo976shake"},
    {NID_frodo1344aes, SSL_CURVE_FRODO1344AES, "frodo1344aes", "frodo1344aes"},
    {NID_p521_frodo1344aes, SSL_CURVE_P521_FRODO1344AES, "p521_frodo1344aes", "p521_frodo1344aes"},
    {NID_frodo1344shake, SSL_CURVE_FRODO1344SHAKE, "frodo1344shake", "frodo1344shake"},
    {NID_p521_frodo1344shake, SSL_CURVE_P521_FRODO1344SHAKE, "p521_frodo1344shake", "p521_frodo1344shake"},
    {NID_bikel1, SSL_CURVE_BIKEL1, "bikel1", "bikel1"},
    {NID_p256_bikel1, SSL_CURVE_P256_BIKEL1, "p256_bikel1", "p256_bikel1"},
    {NID_bikel3, SSL_CURVE_BIKEL3, "bikel3", "bikel3"},
    {NID_p384_bikel3, SSL_CURVE_P384_BIKEL3, "p384_bikel3", "p384_bikel3"},
    {NID_kyber512, SSL_CURVE_KYBER512, "kyber512", "kyber512"},
    {NID_p256_kyber512, SSL_CURVE_P256_KYBER512, "p256_kyber512", "p256_kyber512"},
    {NID_kyber768, SSL_CURVE_KYBER768, "kyber768", "kyber768"},
    {NID_p384_kyber768, SSL_CURVE_P384_KYBER768, "p384_kyber768", "p384_kyber768"},
    {NID_kyber1024, SSL_CURVE_KYBER1024, "kyber1024", "kyber1024"},
    {NID_p521_kyber1024, SSL_CURVE_P521_KYBER1024, "p521_kyber1024", "p521_kyber1024"},
    {NID_ntru_hps2048509, SSL_CURVE_NTRU_HPS2048509, "ntru_hps2048509", "ntru_hps2048509"},
    {NID_p256_ntru_hps2048509, SSL_CURVE_P256_NTRU_HPS2048509, "p256_ntru_hps2048509", "p256_ntru_hps2048509"},
    {NID_ntru_hps2048677, SSL_CURVE_NTRU_HPS2048677, "ntru_hps2048677", "ntru_hps2048677"},
    {NID_p384_ntru_hps2048677, SSL_CURVE_P384_NTRU_HPS2048677, "p384_ntru_hps2048677", "p384_ntru_hps2048677"},
    {NID_ntru_hps4096821, SSL_CURVE_NTRU_HPS4096821, "ntru_hps4096821", "ntru_hps4096821"},
    {NID_p521_ntru_hps4096821, SSL_CURVE_P521_NTRU_HPS4096821, "p521_ntru_hps4096821", "p521_ntru_hps4096821"},
    {NID_ntru_hps40961229, SSL_CURVE_NTRU_HPS40961229, "ntru_hps40961229", "ntru_hps40961229"},
    {NID_p521_ntru_hps40961229, SSL_CURVE_P521_NTRU_HPS40961229, "p521_ntru_hps40961229", "p521_ntru_hps40961229"},
    {NID_ntru_hrss701, SSL_CURVE_NTRU_HRSS701, "ntru_hrss701", "ntru_hrss701"},
    {NID_p384_ntru_hrss701, SSL_CURVE_P384_NTRU_HRSS701, "p384_ntru_hrss701", "p384_ntru_hrss701"},
    {NID_ntru_hrss1373, SSL_CURVE_NTRU_HRSS1373, "ntru_hrss1373", "ntru_hrss1373"},
    {NID_p521_ntru_hrss1373, SSL_CURVE_P521_NTRU_HRSS1373, "p521_ntru_hrss1373", "p521_ntru_hrss1373"},
    {NID_kyber90s512, SSL_CURVE_KYBER90S512, "kyber90s512", "kyber90s512"},
    {NID_p256_kyber90s512, SSL_CURVE_P256_KYBER90S512, "p256_kyber90s512", "p256_kyber90s512"},
    {NID_kyber90s768, SSL_CURVE_KYBER90S768, "kyber90s768", "kyber90s768"},
    {NID_p384_kyber90s768, SSL_CURVE_P384_KYBER90S768, "p384_kyber90s768", "p384_kyber90s768"},
    {NID_kyber90s1024, SSL_CURVE_KYBER90S1024, "kyber90s1024", "kyber90s1024"},
    {NID_p521_kyber90s1024, SSL_CURVE_P521_KYBER90S1024, "p521_kyber90s1024", "p521_kyber90s1024"},
    {NID_hqc128, SSL_CURVE_HQC128, "hqc128", "hqc128"},
    {NID_p256_hqc128, SSL_CURVE_P256_HQC128, "p256_hqc128", "p256_hqc128"},
    {NID_hqc192, SSL_CURVE_HQC192, "hqc192", "hqc192"},
    {NID_p384_hqc192, SSL_CURVE_P384_HQC192, "p384_hqc192", "p384_hqc192"},
    {NID_hqc256, SSL_CURVE_HQC256, "hqc256", "hqc256"},
    {NID_p521_hqc256, SSL_CURVE_P521_HQC256, "p521_hqc256", "p521_hqc256"},
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
///// OQS_TEMPLATE_FRAGMENT_HANDLE_GROUP_IDS_START
    case SSL_CURVE_FRODO640AES:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_640_aes))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_FRODO640AES, OQS_KEM_alg_frodokem_640_aes));
      else
          return nullptr;
    case SSL_CURVE_P256_FRODO640AES:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_640_aes))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P256_FRODO640AES, SSL_CURVE_SECP256R1, OQS_KEM_alg_frodokem_640_aes));
      else
          return nullptr;
    case SSL_CURVE_FRODO640SHAKE:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_640_shake))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_FRODO640SHAKE, OQS_KEM_alg_frodokem_640_shake));
      else
          return nullptr;
    case SSL_CURVE_P256_FRODO640SHAKE:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_640_shake))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P256_FRODO640SHAKE, SSL_CURVE_SECP256R1, OQS_KEM_alg_frodokem_640_shake));
      else
          return nullptr;
    case SSL_CURVE_FRODO976AES:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_976_aes))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_FRODO976AES, OQS_KEM_alg_frodokem_976_aes));
      else
          return nullptr;
    case SSL_CURVE_P384_FRODO976AES:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_976_aes))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P384_FRODO976AES, SSL_CURVE_SECP384R1, OQS_KEM_alg_frodokem_976_aes));
      else
          return nullptr;
    case SSL_CURVE_FRODO976SHAKE:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_976_shake))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_FRODO976SHAKE, OQS_KEM_alg_frodokem_976_shake));
      else
          return nullptr;
    case SSL_CURVE_P384_FRODO976SHAKE:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_976_shake))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P384_FRODO976SHAKE, SSL_CURVE_SECP384R1, OQS_KEM_alg_frodokem_976_shake));
      else
          return nullptr;
    case SSL_CURVE_FRODO1344AES:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_1344_aes))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_FRODO1344AES, OQS_KEM_alg_frodokem_1344_aes));
      else
          return nullptr;
    case SSL_CURVE_P521_FRODO1344AES:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_1344_aes))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P521_FRODO1344AES, SSL_CURVE_SECP521R1, OQS_KEM_alg_frodokem_1344_aes));
      else
          return nullptr;
    case SSL_CURVE_FRODO1344SHAKE:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_1344_shake))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_FRODO1344SHAKE, OQS_KEM_alg_frodokem_1344_shake));
      else
          return nullptr;
    case SSL_CURVE_P521_FRODO1344SHAKE:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_frodokem_1344_shake))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P521_FRODO1344SHAKE, SSL_CURVE_SECP521R1, OQS_KEM_alg_frodokem_1344_shake));
      else
          return nullptr;
    case SSL_CURVE_BIKEL1:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_bike_l1))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_BIKEL1, OQS_KEM_alg_bike_l1));
      else
          return nullptr;
    case SSL_CURVE_P256_BIKEL1:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_bike_l1))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P256_BIKEL1, SSL_CURVE_SECP256R1, OQS_KEM_alg_bike_l1));
      else
          return nullptr;
    case SSL_CURVE_BIKEL3:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_bike_l3))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_BIKEL3, OQS_KEM_alg_bike_l3));
      else
          return nullptr;
    case SSL_CURVE_P384_BIKEL3:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_bike_l3))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P384_BIKEL3, SSL_CURVE_SECP384R1, OQS_KEM_alg_bike_l3));
      else
          return nullptr;
    case SSL_CURVE_KYBER512:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_512))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_KYBER512, OQS_KEM_alg_kyber_512));
      else
          return nullptr;
    case SSL_CURVE_P256_KYBER512:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_512))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P256_KYBER512, SSL_CURVE_SECP256R1, OQS_KEM_alg_kyber_512));
      else
          return nullptr;
    case SSL_CURVE_KYBER768:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_KYBER768, OQS_KEM_alg_kyber_768));
      else
          return nullptr;
    case SSL_CURVE_P384_KYBER768:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P384_KYBER768, SSL_CURVE_SECP384R1, OQS_KEM_alg_kyber_768));
      else
          return nullptr;
    case SSL_CURVE_KYBER1024:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_1024))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_KYBER1024, OQS_KEM_alg_kyber_1024));
      else
          return nullptr;
    case SSL_CURVE_P521_KYBER1024:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_1024))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P521_KYBER1024, SSL_CURVE_SECP521R1, OQS_KEM_alg_kyber_1024));
      else
          return nullptr;
    case SSL_CURVE_NTRU_HPS2048509:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hps2048509))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_NTRU_HPS2048509, OQS_KEM_alg_ntru_hps2048509));
      else
          return nullptr;
    case SSL_CURVE_P256_NTRU_HPS2048509:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hps2048509))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P256_NTRU_HPS2048509, SSL_CURVE_SECP256R1, OQS_KEM_alg_ntru_hps2048509));
      else
          return nullptr;
    case SSL_CURVE_NTRU_HPS2048677:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hps2048677))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_NTRU_HPS2048677, OQS_KEM_alg_ntru_hps2048677));
      else
          return nullptr;
    case SSL_CURVE_P384_NTRU_HPS2048677:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hps2048677))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P384_NTRU_HPS2048677, SSL_CURVE_SECP384R1, OQS_KEM_alg_ntru_hps2048677));
      else
          return nullptr;
    case SSL_CURVE_NTRU_HPS4096821:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hps4096821))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_NTRU_HPS4096821, OQS_KEM_alg_ntru_hps4096821));
      else
          return nullptr;
    case SSL_CURVE_P521_NTRU_HPS4096821:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hps4096821))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P521_NTRU_HPS4096821, SSL_CURVE_SECP521R1, OQS_KEM_alg_ntru_hps4096821));
      else
          return nullptr;
    case SSL_CURVE_NTRU_HPS40961229:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hps40961229))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_NTRU_HPS40961229, OQS_KEM_alg_ntru_hps40961229));
      else
          return nullptr;
    case SSL_CURVE_P521_NTRU_HPS40961229:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hps40961229))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P521_NTRU_HPS40961229, SSL_CURVE_SECP521R1, OQS_KEM_alg_ntru_hps40961229));
      else
          return nullptr;
    case SSL_CURVE_NTRU_HRSS701:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hrss701))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_NTRU_HRSS701, OQS_KEM_alg_ntru_hrss701));
      else
          return nullptr;
    case SSL_CURVE_P384_NTRU_HRSS701:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hrss701))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P384_NTRU_HRSS701, SSL_CURVE_SECP384R1, OQS_KEM_alg_ntru_hrss701));
      else
          return nullptr;
    case SSL_CURVE_NTRU_HRSS1373:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hrss1373))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_NTRU_HRSS1373, OQS_KEM_alg_ntru_hrss1373));
      else
          return nullptr;
    case SSL_CURVE_P521_NTRU_HRSS1373:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_ntru_hrss1373))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P521_NTRU_HRSS1373, SSL_CURVE_SECP521R1, OQS_KEM_alg_ntru_hrss1373));
      else
          return nullptr;
    case SSL_CURVE_KYBER90S512:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_512_90s))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_KYBER90S512, OQS_KEM_alg_kyber_512_90s));
      else
          return nullptr;
    case SSL_CURVE_P256_KYBER90S512:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_512_90s))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P256_KYBER90S512, SSL_CURVE_SECP256R1, OQS_KEM_alg_kyber_512_90s));
      else
          return nullptr;
    case SSL_CURVE_KYBER90S768:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768_90s))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_KYBER90S768, OQS_KEM_alg_kyber_768_90s));
      else
          return nullptr;
    case SSL_CURVE_P384_KYBER90S768:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768_90s))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P384_KYBER90S768, SSL_CURVE_SECP384R1, OQS_KEM_alg_kyber_768_90s));
      else
          return nullptr;
    case SSL_CURVE_KYBER90S1024:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_1024_90s))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_KYBER90S1024, OQS_KEM_alg_kyber_1024_90s));
      else
          return nullptr;
    case SSL_CURVE_P521_KYBER90S1024:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_1024_90s))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P521_KYBER90S1024, SSL_CURVE_SECP521R1, OQS_KEM_alg_kyber_1024_90s));
      else
          return nullptr;
    case SSL_CURVE_HQC128:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_hqc_128))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_HQC128, OQS_KEM_alg_hqc_128));
      else
          return nullptr;
    case SSL_CURVE_P256_HQC128:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_hqc_128))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P256_HQC128, SSL_CURVE_SECP256R1, OQS_KEM_alg_hqc_128));
      else
          return nullptr;
    case SSL_CURVE_HQC192:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_hqc_192))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_HQC192, OQS_KEM_alg_hqc_192));
      else
          return nullptr;
    case SSL_CURVE_P384_HQC192:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_hqc_192))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P384_HQC192, SSL_CURVE_SECP384R1, OQS_KEM_alg_hqc_192));
      else
          return nullptr;
    case SSL_CURVE_HQC256:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_hqc_256))
          return UniquePtr<SSLKeyShare>(New<OQSKeyShare>(SSL_CURVE_HQC256, OQS_KEM_alg_hqc_256));
      else
          return nullptr;
    case SSL_CURVE_P521_HQC256:
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_hqc_256))
          return UniquePtr<SSLKeyShare>(New<ClassicalWithOQSKeyShare>(SSL_CURVE_P521_HQC256, SSL_CURVE_SECP521R1, OQS_KEM_alg_hqc_256));
      else
          return nullptr;
///// OQS_TEMPLATE_FRAGMENT_HANDLE_GROUP_IDS_END
    default:
      return nullptr;
  }
}

UniquePtr<SSLKeyShare> SSLKeyShare::Create(CBS *in) {
  uint64_t group;
  CBS private_key;
  if (!CBS_get_asn1_uint64(in, &group) || group > 0xffff ||
      !CBS_get_asn1(in, &private_key, CBS_ASN1_OCTETSTRING)) {
    return nullptr;
  }
  UniquePtr<SSLKeyShare> key_share = Create(static_cast<uint16_t>(group));
  if (!key_share || !key_share->DeserializePrivateKey(&private_key)) {
    return nullptr;
  }
  return key_share;
}

bool SSLKeyShare::Serialize(CBB *out) {
  CBB private_key;
  if (!CBB_add_asn1_uint64(out, GroupID()) ||
      !CBB_add_asn1(out, &private_key, CBS_ASN1_OCTETSTRING) ||
      !SerializePrivateKey(&private_key) ||  //
      !CBB_flush(out)) {
    return false;
  }
  return true;
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
