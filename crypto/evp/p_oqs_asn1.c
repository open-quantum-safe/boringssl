/* Copyright (c) 2017, Google Inc., modifications by the Open Quantum Safe
 * project 2020.
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

#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <oqs/oqs.h>
#include <stdio.h>

#include "../internal.h"
#include "internal.h"

static void oqs_free(EVP_PKEY *pkey) {
  OPENSSL_free(pkey->pkey);
  pkey->pkey = NULL;
}

void oqs_pkey_ctx_free(OQS_KEY* key) {
  int privkey_len = 0;
  if (key == NULL) {
    return;
  }
  if (key->ctx) {
    privkey_len = key->ctx->length_secret_key;
    OQS_SIG_free(key->ctx);
  }
  if (key->priv) {
    OPENSSL_secure_clear_free(key->priv, privkey_len);
  }
  if (key->pub) {
    OPENSSL_free(key->pub);
  }
  if (key->classical_pkey) {
    EVP_PKEY_free(key->classical_pkey);
  }
  OPENSSL_free(key);
}

#define DEFINE_OQS_SET_PRIV_RAW(ALG, OQS_METH)                              \
  static int ALG##_set_priv_raw(EVP_PKEY *pkey, const uint8_t *in,          \
                                size_t len) {                               \
    OQS_KEY *key = (OQS_KEY *)(OPENSSL_malloc(sizeof(OQS_KEY)));            \
    if (!key) {                                                             \
      OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                         \
      goto err;                                                             \
    }                                                                       \
                                                                            \
    key->ctx = OQS_SIG_new(OQS_METH);                                       \
    if (!key->ctx) {                                                        \
      OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                         \
      goto err;                                                             \
    }                                                                       \
                                                                            \
    unsigned int max_privkey_len = key->ctx->length_secret_key + key->ctx->length_public_key;                      \
    int id = pkey->ameth->pkey_id;                                          \
    int index = 0;                                                          \
    int is_hybrid = is_oqs_hybrid_alg(id);                                  \
    key->nid = id;                                                          \
    if (is_hybrid) {                                                        \
      max_privkey_len += (SIZE_OF_UINT32 + get_classical_key_len(KEY_TYPE_PRIVATE, get_classical_nid(id)));        \
      unsigned int actual_classical_privkey_len;                            \
      DECODE_UINT32(actual_classical_privkey_len, in);                      \
      const unsigned char* privkey_temp = in + SIZE_OF_UINT32;              \
      key->classical_pkey = d2i_AutoPrivateKey(&key->classical_pkey, &privkey_temp, actual_classical_privkey_len); \
      if (key->classical_pkey == NULL) {                                    \
        OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);                         \
        goto err;                                                           \
      }                                                                     \
      index += (SIZE_OF_UINT32 + actual_classical_privkey_len);             \
    }                                                                       \
                                                                            \
    if (len != max_privkey_len) {                                           \
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);                           \
      goto err;                                                             \
    }                                                                       \
                                                                            \
    key->priv = (uint8_t*)(malloc(key->ctx->length_secret_key));            \
    OPENSSL_memcpy(key->priv, in + index, key->ctx->length_secret_key);     \
    key->has_private = 1;                                                   \
                                                                            \
    key->pub = (uint8_t*)(malloc(key->ctx->length_public_key));             \
    OPENSSL_memcpy(key->pub, in + index + key->ctx->length_secret_key,      \
                   key->ctx->length_public_key);                            \
                                                                            \
    oqs_free(pkey);                                                         \
    pkey->pkey = key;                                                       \
    return 1;                                                               \
  err:                                                                      \
   oqs_pkey_ctx_free(key);                                                  \
   return 0;                                                                \
  }

#define DEFINE_OQS_PRIV_DECODE(ALG)                                    \
  static int ALG##_priv_decode(EVP_PKEY *out, CBS *params, CBS *key) { \
    CBS inner;                                                         \
    if (CBS_len(params) != 0 ||                                        \
        !CBS_get_asn1(key, &inner, CBS_ASN1_OCTETSTRING) ||            \
        CBS_len(key) != 0) {                                           \
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);                      \
      return 0;                                                        \
    }                                                                  \
                                                                       \
    return ALG##_set_priv_raw(out, CBS_data(&inner), CBS_len(&inner)); \
  }


#define DEFINE_OQS_SET_PUB_RAW(ALG, OQS_METH)                       \
  static int ALG##_set_pub_raw(EVP_PKEY *pkey, const uint8_t *in,   \
                               size_t len) {                        \
    OQS_KEY *key = (OQS_KEY *)(OPENSSL_malloc(sizeof(OQS_KEY)));    \
    if (!key) {                                                     \
      OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                 \
      goto err;                                                     \
    }                                                               \
                                                                    \
    key->ctx = OQS_SIG_new(OQS_METH);                               \
    if (!key->ctx) {                                                \
      OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                 \
      goto err;                                                     \
    }                                                               \
                                                                    \
    unsigned int max_pubkey_len = key->ctx->length_public_key;      \
    int id = pkey->ameth->pkey_id;                                  \
    int index = 0;                                                  \
    int is_hybrid = is_oqs_hybrid_alg(id);                          \
    key->nid = id;                                                  \
    if (is_hybrid) {                                                \
      max_pubkey_len += (SIZE_OF_UINT32 + get_classical_key_len(KEY_TYPE_PUBLIC, get_classical_nid(id)));                   \
      int classical_id = get_classical_nid(id);                     \
      int actual_classical_pubkey_len;                              \
      DECODE_UINT32(actual_classical_pubkey_len, in);               \
      if (is_EC_nid(classical_id)) {                                \
        decode_EC_pub(classical_id, in + SIZE_OF_UINT32, actual_classical_pubkey_len, key);                                 \
      } else {                                                      \
        const unsigned char* pubkey_temp = in + SIZE_OF_UINT32;     \
        key->classical_pkey = decode_RSA_pub(&key->classical_pkey, &pubkey_temp, actual_classical_pubkey_len);              \
      }                                                             \
      if (key->classical_pkey == NULL) {                            \
        OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);                 \
        goto err;                                                   \
      }                                                             \
      index += (SIZE_OF_UINT32 + actual_classical_pubkey_len);      \
    }                                                               \
                                                                    \
    if (len != max_pubkey_len) {                                    \
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);                   \
      goto err;                                                     \
    }                                                               \
                                                                    \
    max_pubkey_len = key->ctx->length_public_key;                   \
    key->pub = (uint8_t*)(malloc(max_pubkey_len));                  \
    OPENSSL_memcpy(key->pub, index + in, max_pubkey_len);           \
    key->has_private = 0;                                           \
                                                                    \
    oqs_free(pkey);                                                 \
    pkey->pkey = key;                                               \
    return 1;                                                       \
  err:                                                              \
   oqs_pkey_ctx_free(key);                                          \
   return 0;                                                        \
  }

#define DEFINE_OQS_PUB_DECODE(ALG)                                    \
  static int ALG##_pub_decode(EVP_PKEY *out, CBS *params, CBS *key) { \
    if (CBS_len(params) != 0) {                                       \
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);                     \
      return 0;                                                       \
    }                                                                 \
                                                                      \
    return ALG##_set_pub_raw(out, CBS_data(key), CBS_len(key));       \
  }

#define DEFINE_OQS_PUB_ENCODE(ALG)                                            \
  static int ALG##_pub_encode(CBB *out, const EVP_PKEY *pkey) {               \
    const OQS_KEY *key = pkey->pkey;                                          \
    uint32_t pubkey_len = 0, max_classical_pubkey_len = 0, classical_pubkey_len = 0, index = 0;                   \
                                                                              \
    int is_hybrid = (key->classical_pkey != NULL);                            \
    pubkey_len = key->ctx->length_public_key;                                 \
    if (is_hybrid) {                                                          \
      max_classical_pubkey_len = get_classical_key_len(KEY_TYPE_PUBLIC, get_classical_nid(pkey->ameth->pkey_id)); \
      pubkey_len += (SIZE_OF_UINT32 + max_classical_pubkey_len);              \
    }                                                                         \
    unsigned char *penc = OPENSSL_malloc(pubkey_len);                         \
    unsigned char *classical_pubkey = penc + SIZE_OF_UINT32;                  \
    if (is_hybrid) {                                                          \
      classical_pubkey = penc + SIZE_OF_UINT32;                               \
      uint32_t actual_classical_pubkey_len = i2d_PublicKey(key->classical_pkey, &classical_pubkey);               \
      if (actual_classical_pubkey_len > max_classical_pubkey_len) {           \
        OPENSSL_free(classical_pubkey);                                       \
        OPENSSL_free(penc);                                                   \
        OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);                           \
        return 0;                                                             \
      }                                                                       \
      ENCODE_UINT32(penc, actual_classical_pubkey_len);                       \
      classical_pubkey_len = SIZE_OF_UINT32 + actual_classical_pubkey_len;    \
      index += classical_pubkey_len;                                          \
    }                                                                         \
    OPENSSL_memcpy(penc + index, key->pub, key->ctx->length_public_key);      \
    pubkey_len = classical_pubkey_len + key->ctx->length_public_key;          \
                                                                              \
    /* See RFC 8410, section 4. */                                            \
    CBB spki, algorithm, oid, key_bitstring;                                  \
    if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||                       \
        !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||                \
        !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||                   \
        !CBB_add_bytes(&oid, ALG##_asn1_meth.oid, ALG##_asn1_meth.oid_len) || \
        !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||           \
        !CBB_add_u8(&key_bitstring, 0 /* padding */) ||                       \
        !CBB_add_bytes(&key_bitstring, penc, pubkey_len) ||                   \
        !CBB_flush(out)) {                                                    \
      OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);                             \
      OPENSSL_free(classical_pubkey);                                         \
      OPENSSL_free(penc);                                                     \
      return 0;                                                               \
    }                                                                         \
                                                                              \
    return 1;                                                                 \
  }

static int oqs_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
  const OQS_KEY *a_key = a->pkey;
  const OQS_KEY *b_key = b->pkey;
  if (is_oqs_hybrid_alg(a->ameth->pkey_id)) {
    if (!EVP_PKEY_cmp(a_key->classical_pkey, b_key->classical_pkey)) {
      return 0;
    }
  }
  return OPENSSL_memcmp(a_key->pub, b_key->pub,
                        a_key->ctx->length_public_key) == 0;
}

static size_t oqs_sig_size(const EVP_PKEY *pkey) {
  const OQS_KEY *key = pkey->pkey;
  unsigned int sig_len = key->ctx->length_signature;
  if (is_oqs_hybrid_alg(pkey->ameth->pkey_id)) {
    int classical_nid = get_classical_nid(pkey->ameth->pkey_id);
    sig_len += (SIZE_OF_UINT32 + get_classical_sig_len(classical_nid));
  }
  return sig_len;
}

static int get_classical_key_len(oqs_key_type_t keytype, int classical_id) {
 switch (classical_id)
    {
    case NID_rsaEncryption:
      return (keytype == KEY_TYPE_PRIVATE) ? 1770 : 398;
    case NID_X9_62_prime256v1:
      return (keytype == KEY_TYPE_PRIVATE) ? 121 : 65;
    case NID_secp384r1:
      return (keytype == KEY_TYPE_PRIVATE) ? 167 : 97;
    case NID_secp521r1:
      return (keytype == KEY_TYPE_PRIVATE) ? 223 : 133;
    default:
      return 0;
    }
}

int get_classical_nid(int hybrid_id)
{
  switch (hybrid_id)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_CLASSICAL_NIDS_START
    case NID_rsa3072_mldsa44:
      return NID_rsaEncryption;
    case NID_p384_mldsa65:
      return NID_secp384r1;
    case NID_p256_falcon512:
      return NID_X9_62_prime256v1;
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_CLASSICAL_NIDS_END
    default:
      return 0;
  }
}

int is_oqs_hybrid_alg(int hybrid_nid)
{
  switch (hybrid_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_NIDS_START
    case NID_rsa3072_mldsa44:
      return 1;
    case NID_p384_mldsa65:
      return 1;
    case NID_p256_falcon512:
      return 1;
///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_NIDS_END
    default:
      return 0;
  }
}

int is_EC_nid(int nid) {
  return (nid == NID_X9_62_prime256v1 || nid == NID_secp384r1 || nid == NID_secp521r1);
}

int get_classical_sig_len(int classical_id)
{
  switch (classical_id) {
    case NID_rsaEncryption:
      return 384;
    case NID_X9_62_prime256v1:
      return 72;
    case NID_secp384r1:
      return 104;
    case NID_secp521r1:
      return 141;
    default:
      return 0;
  }
}

static EVP_PKEY *decode_RSA_pub(EVP_PKEY **out, const uint8_t **inp, long len) {
  EVP_PKEY *ret = EVP_PKEY_new();
  if (ret == NULL) {
    EVP_PKEY_free(ret);
    return NULL;
  }

  CBS cbs;
  CBS_init(&cbs, *inp, len < 0 ? 0 : (size_t)len);
  RSA *rsa = RSA_parse_public_key(&cbs);
  if (rsa == NULL || !EVP_PKEY_assign_RSA(ret, rsa)) {
    RSA_free(rsa);
    EVP_PKEY_free(ret);
    return NULL;
  }

  *inp = CBS_data(&cbs);
  if (out != NULL) {
    *out = ret;
  }
  return ret;
}

static int decode_EC_pub(int nid, const unsigned char* encoded_key, int key_len, OQS_KEY* oqs_key) {
  EC_GROUP *ecgroup = NULL;
  EC_KEY *ec_key = NULL;
  const unsigned char* p_encoded_key = encoded_key;
  int rv = 0;

  if ((ecgroup = EC_GROUP_new_by_curve_name(nid)) == NULL) {
    goto end;
  }

  if ((ec_key = EC_KEY_new()) == NULL ||
      !EC_KEY_set_group(ec_key, ecgroup)) {
    goto end;
  }

  if (o2i_ECPublicKey(&ec_key, &p_encoded_key, key_len) == NULL) {
    goto end;
  }

  if ((oqs_key->classical_pkey = EVP_PKEY_new()) == NULL ||
      !EVP_PKEY_set_type(oqs_key->classical_pkey, NID_X9_62_id_ecPublicKey) ||
      !EVP_PKEY_assign_EC_KEY(oqs_key->classical_pkey, ec_key)) {;
    goto end;
  }

  rv = 1;

end:
  if (rv == 0) {
    EC_GROUP_free(ecgroup);
    EC_KEY_free(ec_key);
  }
  return rv;
}

// Dummy wrapper to improve readability
#define OID(...) __VA_ARGS__

#define OID_LEN(...) (sizeof((int[]){__VA_ARGS__}) / sizeof(int))

#define DEFINE_OQS_ASN1_METHODS(ALG, OQS_METH, ALG_PKEY) \
  DEFINE_OQS_SET_PRIV_RAW(ALG, OQS_METH)                 \
  DEFINE_OQS_PRIV_DECODE(ALG)                            \
  DEFINE_OQS_SET_PUB_RAW(ALG, OQS_METH)                  \
  DEFINE_OQS_PUB_DECODE(ALG)                             \
  DEFINE_OQS_PUB_ENCODE(ALG)

#define DEFINE_OQS_PKEY_ASN1_METHOD(ALG, ALG_PKEY, ...) \
  const EVP_PKEY_ASN1_METHOD ALG##_asn1_meth = {        \
      ALG_PKEY,                                         \
      {__VA_ARGS__},                                    \
      OID_LEN(__VA_ARGS__),                             \
      &ALG##_pkey_meth,                                 \
      ALG##_pub_decode,                                 \
      ALG##_pub_encode /* pub_encode */,                \
      oqs_pub_cmp,                                      \
      ALG##_priv_decode,                                \
      NULL /* priv_encode */,                           \
      ALG##_set_priv_raw,                               \
      ALG##_set_pub_raw,                                \
      NULL /* get_priv_raw */,                          \
      NULL /* get_pub_raw */,                           \
      NULL /* int set1_tls_encodedpoint */,             \
      NULL /* size_t set1_tls_encodedpoint */,          \
      NULL /* pkey_opaque */,                           \
      oqs_sig_size,                                     \
      NULL /* pkey_bits */,                             \
      NULL /* param_missing */,                         \
      NULL /* param_copy */,                            \
      NULL /* param_cmp */,                             \
      oqs_free,                                         \
  };

// the OIDs can also be found in the kObjectData array in crypto/obj/obj_dat.h
///// OQS_TEMPLATE_FRAGMENT_DEF_ASN1_METHODS_START
DEFINE_OQS_ASN1_METHODS(mldsa44, OQS_SIG_alg_ml_dsa_44, EVP_PKEY_MLDSA44)
DEFINE_OQS_PKEY_ASN1_METHOD(mldsa44, EVP_PKEY_MLDSA44, OID(0x2B, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0B, 0x0C, 0x04, 0x04))

DEFINE_OQS_ASN1_METHODS(rsa3072_mldsa44, OQS_SIG_alg_ml_dsa_44, EVP_PKEY_RSA3072_MLDSA44)
DEFINE_OQS_PKEY_ASN1_METHOD(rsa3072_mldsa44, EVP_PKEY_RSA3072_MLDSA44, OID(0x2B, 0xCE, 0x0F, 0x07, 0x02))

DEFINE_OQS_ASN1_METHODS(mldsa65, OQS_SIG_alg_ml_dsa_65, EVP_PKEY_MLDSA65)
DEFINE_OQS_PKEY_ASN1_METHOD(mldsa65, EVP_PKEY_MLDSA65, OID(0x2B, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0B, 0x0C, 0x06, 0x05))

DEFINE_OQS_ASN1_METHODS(p384_mldsa65, OQS_SIG_alg_ml_dsa_65, EVP_PKEY_P384_MLDSA65)
DEFINE_OQS_PKEY_ASN1_METHOD(p384_mldsa65, EVP_PKEY_P384_MLDSA65, OID(0x2B, 0xCE, 0x0F, 0x07, 0x03))

DEFINE_OQS_ASN1_METHODS(mldsa87, OQS_SIG_alg_ml_dsa_87, EVP_PKEY_MLDSA87)
DEFINE_OQS_PKEY_ASN1_METHOD(mldsa87, EVP_PKEY_MLDSA87, OID(0x2B, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0B, 0x0C, 0x08, 0x07))

DEFINE_OQS_ASN1_METHODS(dilithium2, OQS_SIG_alg_dilithium_2, EVP_PKEY_DILITHIUM2)
DEFINE_OQS_PKEY_ASN1_METHOD(dilithium2, EVP_PKEY_DILITHIUM2, OID(0x2B, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0B, 0x07, 0x04, 0x04))

DEFINE_OQS_ASN1_METHODS(dilithium3, OQS_SIG_alg_dilithium_3, EVP_PKEY_DILITHIUM3)
DEFINE_OQS_PKEY_ASN1_METHOD(dilithium3, EVP_PKEY_DILITHIUM3, OID(0x2B, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0B, 0x07, 0x06, 0x05))

DEFINE_OQS_ASN1_METHODS(dilithium5, OQS_SIG_alg_dilithium_5, EVP_PKEY_DILITHIUM5)
DEFINE_OQS_PKEY_ASN1_METHOD(dilithium5, EVP_PKEY_DILITHIUM5, OID(0x2B, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0B, 0x07, 0x08, 0x07))

DEFINE_OQS_ASN1_METHODS(falcon512, OQS_SIG_alg_falcon_512, EVP_PKEY_FALCON512)
DEFINE_OQS_PKEY_ASN1_METHOD(falcon512, EVP_PKEY_FALCON512, OID(0x2B, 0xCE, 0x0F, 0x03, 0x0B))

DEFINE_OQS_ASN1_METHODS(p256_falcon512, OQS_SIG_alg_falcon_512, EVP_PKEY_P256_FALCON512)
DEFINE_OQS_PKEY_ASN1_METHOD(p256_falcon512, EVP_PKEY_P256_FALCON512, OID(0x2B, 0xCE, 0x0F, 0x03, 0x0C))

DEFINE_OQS_ASN1_METHODS(falconpadded512, OQS_SIG_alg_falcon_padded_512, EVP_PKEY_FALCONPADDED512)
DEFINE_OQS_PKEY_ASN1_METHOD(falconpadded512, EVP_PKEY_FALCONPADDED512, OID(0x2B, 0xCE, 0x0F, 0x03, 0x10))

DEFINE_OQS_ASN1_METHODS(falcon1024, OQS_SIG_alg_falcon_1024, EVP_PKEY_FALCON1024)
DEFINE_OQS_PKEY_ASN1_METHOD(falcon1024, EVP_PKEY_FALCON1024, OID(0x2B, 0xCE, 0x0F, 0x03, 0x0E))

DEFINE_OQS_ASN1_METHODS(falconpadded1024, OQS_SIG_alg_falcon_padded_1024, EVP_PKEY_FALCONPADDED1024)
DEFINE_OQS_PKEY_ASN1_METHOD(falconpadded1024, EVP_PKEY_FALCONPADDED1024, OID(0x2B, 0xCE, 0x0F, 0x03, 0x13))

DEFINE_OQS_ASN1_METHODS(mayo1, OQS_SIG_alg_mayo_1, EVP_PKEY_MAYO1)
DEFINE_OQS_PKEY_ASN1_METHOD(mayo1, EVP_PKEY_MAYO1, OID(0x2B, 0xCE, 0x0F, 0x08, 0x01, 0x01))

DEFINE_OQS_ASN1_METHODS(mayo2, OQS_SIG_alg_mayo_2, EVP_PKEY_MAYO2)
DEFINE_OQS_PKEY_ASN1_METHOD(mayo2, EVP_PKEY_MAYO2, OID(0x2B, 0xCE, 0x0F, 0x08, 0x02, 0x01))

DEFINE_OQS_ASN1_METHODS(mayo3, OQS_SIG_alg_mayo_3, EVP_PKEY_MAYO3)
DEFINE_OQS_PKEY_ASN1_METHOD(mayo3, EVP_PKEY_MAYO3, OID(0x2B, 0xCE, 0x0F, 0x08, 0x03, 0x01))

DEFINE_OQS_ASN1_METHODS(mayo5, OQS_SIG_alg_mayo_5, EVP_PKEY_MAYO5)
DEFINE_OQS_PKEY_ASN1_METHOD(mayo5, EVP_PKEY_MAYO5, OID(0x2B, 0xCE, 0x0F, 0x08, 0x05, 0x01))

DEFINE_OQS_ASN1_METHODS(sphincssha2128fsimple, OQS_SIG_alg_sphincs_sha2_128f_simple, EVP_PKEY_SPHINCSSHA2128FSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincssha2128fsimple, EVP_PKEY_SPHINCSSHA2128FSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x04, 0x0D))

DEFINE_OQS_ASN1_METHODS(sphincssha2128ssimple, OQS_SIG_alg_sphincs_sha2_128s_simple, EVP_PKEY_SPHINCSSHA2128SSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincssha2128ssimple, EVP_PKEY_SPHINCSSHA2128SSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x04, 0x10))

DEFINE_OQS_ASN1_METHODS(sphincssha2192fsimple, OQS_SIG_alg_sphincs_sha2_192f_simple, EVP_PKEY_SPHINCSSHA2192FSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincssha2192fsimple, EVP_PKEY_SPHINCSSHA2192FSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x05, 0x0A))

DEFINE_OQS_ASN1_METHODS(sphincssha2192ssimple, OQS_SIG_alg_sphincs_sha2_192s_simple, EVP_PKEY_SPHINCSSHA2192SSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincssha2192ssimple, EVP_PKEY_SPHINCSSHA2192SSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x05, 0x0C))

DEFINE_OQS_ASN1_METHODS(sphincssha2256fsimple, OQS_SIG_alg_sphincs_sha2_256f_simple, EVP_PKEY_SPHINCSSHA2256FSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincssha2256fsimple, EVP_PKEY_SPHINCSSHA2256FSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x06, 0x0A))

DEFINE_OQS_ASN1_METHODS(sphincssha2256ssimple, OQS_SIG_alg_sphincs_sha2_256s_simple, EVP_PKEY_SPHINCSSHA2256SSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincssha2256ssimple, EVP_PKEY_SPHINCSSHA2256SSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x06, 0x0C))

DEFINE_OQS_ASN1_METHODS(sphincsshake128fsimple, OQS_SIG_alg_sphincs_shake_128f_simple, EVP_PKEY_SPHINCSSHAKE128FSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincsshake128fsimple, EVP_PKEY_SPHINCSSHAKE128FSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x07, 0x0D))

DEFINE_OQS_ASN1_METHODS(sphincsshake128ssimple, OQS_SIG_alg_sphincs_shake_128s_simple, EVP_PKEY_SPHINCSSHAKE128SSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincsshake128ssimple, EVP_PKEY_SPHINCSSHAKE128SSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x07, 0x10))

DEFINE_OQS_ASN1_METHODS(sphincsshake192fsimple, OQS_SIG_alg_sphincs_shake_192f_simple, EVP_PKEY_SPHINCSSHAKE192FSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincsshake192fsimple, EVP_PKEY_SPHINCSSHAKE192FSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x08, 0x0A))

DEFINE_OQS_ASN1_METHODS(sphincsshake192ssimple, OQS_SIG_alg_sphincs_shake_192s_simple, EVP_PKEY_SPHINCSSHAKE192SSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincsshake192ssimple, EVP_PKEY_SPHINCSSHAKE192SSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x08, 0x0C))

DEFINE_OQS_ASN1_METHODS(sphincsshake256fsimple, OQS_SIG_alg_sphincs_shake_256f_simple, EVP_PKEY_SPHINCSSHAKE256FSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincsshake256fsimple, EVP_PKEY_SPHINCSSHAKE256FSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x09, 0x0A))

DEFINE_OQS_ASN1_METHODS(sphincsshake256ssimple, OQS_SIG_alg_sphincs_shake_256s_simple, EVP_PKEY_SPHINCSSHAKE256SSIMPLE)
DEFINE_OQS_PKEY_ASN1_METHOD(sphincsshake256ssimple, EVP_PKEY_SPHINCSSHAKE256SSIMPLE, OID(0x2B, 0xCE, 0x0F, 0x06, 0x09, 0x0C))

///// OQS_TEMPLATE_FRAGMENT_DEF_ASN1_METHODS_END
