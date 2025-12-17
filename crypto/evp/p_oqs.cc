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

#include <openssl/evp.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <oqs/oqs.h>

#include "internal.h"

// oqs has no parameters to copy.
static int pkey_oqs_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) { return 1; }

#define DEFINE_PKEY_KEYGEN(ALG, OQS_METH, ALG_PKEY)                         \
  static int ALG##_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {         \
    OQS_KEY *key = (OQS_KEY *)(OPENSSL_malloc(sizeof(OQS_KEY)));            \
    EVP_PKEY_CTX *param_ctx = NULL, *keygen_ctx = NULL;                     \
    short int rv = 0;                                                       \
    if (!key) {                                                             \
      OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                         \
      goto end;                                                             \
    }                                                                       \
                                                                            \
    key->ctx = OQS_SIG_new(OQS_METH);                                       \
    if (!key->ctx) {                                                        \
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);                  \
      goto end;                                                             \
    }                                                                       \
                                                                            \
    {                                                                       \
      int id = ctx->pmeth->pkey_id;                                         \
      int is_hybrid = is_oqs_hybrid_alg(id);                                \
      if (is_hybrid) {                                                      \
        int rsa_size = 3072;                                                \
        int classical_id = get_classical_nid(id);                           \
        EVP_PKEY *param_pkey = NULL;                                        \
        if (is_EC_nid(classical_id)) {                                      \
          if (!(param_ctx =                                                 \
                    EVP_PKEY_CTX_new_id(NID_X9_62_id_ecPublicKey, NULL)) || \
              !EVP_PKEY_paramgen_init(param_ctx) ||                         \
              !EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx,            \
                                                      classical_id) ||      \
              !EVP_PKEY_paramgen(param_ctx, &param_pkey)) {                 \
            OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);                     \
            EVP_PKEY_free(param_pkey);                                      \
            goto end;                                                       \
          }                                                                 \
        }                                                                   \
        if (param_pkey != NULL) {                                           \
          keygen_ctx = EVP_PKEY_CTX_new(param_pkey, NULL);                  \
        } else {                                                            \
          keygen_ctx = EVP_PKEY_CTX_new_id(classical_id, NULL);             \
        }                                                                   \
        EVP_PKEY_free(param_pkey);                                          \
        if (!keygen_ctx || !EVP_PKEY_keygen_init(keygen_ctx)) {             \
          OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                     \
          goto end;                                                         \
        }                                                                   \
        if (classical_id == EVP_PKEY_RSA) {                                 \
          if (!EVP_PKEY_CTX_set_rsa_keygen_bits(keygen_ctx, rsa_size)) {    \
            OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);                     \
            goto end;                                                       \
          }                                                                 \
        }                                                                   \
        if (!EVP_PKEY_keygen(keygen_ctx, &key->classical_pkey)) {           \
          OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);                       \
          goto end;                                                         \
        }                                                                   \
      }                                                                     \
    }                                                                       \
                                                                            \
    key->priv = (uint8_t *)(malloc(key->ctx->length_secret_key));           \
    if (!key->priv) {                                                       \
      OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                         \
      goto end;                                                             \
    }                                                                       \
                                                                            \
    key->pub = (uint8_t *)(malloc(key->ctx->length_public_key));            \
    if (!key->pub) {                                                        \
      OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                         \
      goto end;                                                             \
    }                                                                       \
                                                                            \
    if (OQS_SIG_keypair(key->ctx, key->pub, key->priv) != OQS_SUCCESS) {    \
      OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);                           \
      goto end;                                                             \
    }                                                                       \
    key->has_private = 1;                                                   \
                                                                            \
    OPENSSL_free(pkey->pkey);                                               \
    evp_pkey_set0(pkey, &ALG##_asn1_meth, key);                             \
    rv = 1;                                                                 \
                                                                            \
  end:                                                                      \
    EVP_PKEY_CTX_free(keygen_ctx);                                          \
    EVP_PKEY_CTX_free(param_ctx);                                           \
    if (rv == 0)                                                            \
      oqs_pkey_ctx_free(key);                                               \
    return rv;                                                              \
  }

static int pkey_oqs_sign_message(EVP_PKEY_CTX *ctx, uint8_t *sig,
                                 size_t *siglen, const uint8_t *tbs,
                                 size_t tbslen) {
  OQS_KEY *key = (OQS_KEY *)(ctx->pkey->pkey);
  int key_nid = ctx->pmeth->pkey_id;
  int is_hybrid = is_oqs_hybrid_alg(key_nid);
  int classical_id = 0;
  size_t actual_classical_sig_len = 0;
  size_t max_sig_len = key->ctx->length_signature;
  EVP_PKEY_CTX *classical_ctx_sign = NULL;

  if (!key->has_private) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
    goto err;
  }

  if (is_hybrid) {
    classical_id = get_classical_nid(key_nid);
    actual_classical_sig_len = get_classical_sig_len(classical_id);
    max_sig_len += (SIZE_OF_UINT32 + actual_classical_sig_len);
  }

  if (sig == NULL) {
    *siglen = max_sig_len;
    EVP_PKEY_CTX_free(classical_ctx_sign);
    return 1;
  }
  if (*siglen != max_sig_len) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    goto err;
  }

  {
    size_t index = 0, classical_sig_len = 0;
    if (is_hybrid) {
      const EVP_MD *classical_md;
      int digest_len;
      unsigned char digest[64]; /* SHA512_DIGEST_LENGTH */

      if ((classical_ctx_sign = EVP_PKEY_CTX_new(key->classical_pkey, NULL)) ==
              NULL ||
          EVP_PKEY_sign_init(classical_ctx_sign) <= 0) {
        goto err;
      }
      if ((classical_id == EVP_PKEY_RSA) &&
          (EVP_PKEY_CTX_set_rsa_padding(classical_ctx_sign,
                                        /* RSA_PKCS1_PADDING */ 1) <= 0)) {
        goto err;
      }

      switch (key->ctx->claimed_nist_level) {
        case 1:
          classical_md = EVP_sha256();
          digest_len = 32;
          SHA256(tbs, tbslen, (unsigned char *)&digest);
          break;
        case 2:
        case 3:
          classical_md = EVP_sha384();
          digest_len = 48;
          SHA384(tbs, tbslen, (unsigned char *)&digest);
          break;
        default:
          classical_md = EVP_sha512();
          digest_len = 64;
          SHA512(tbs, tbslen, (unsigned char *)&digest);
          break;
      }

      if ((EVP_PKEY_CTX_set_signature_md(classical_ctx_sign, classical_md) <=
           0) ||
          (EVP_PKEY_sign(classical_ctx_sign, sig + SIZE_OF_UINT32,
                         &actual_classical_sig_len, digest, digest_len) <= 0) ||
          (actual_classical_sig_len >
           (size_t)get_classical_sig_len(classical_id))) {
        goto err;
      }

      ENCODE_UINT32(sig, actual_classical_sig_len);
      classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
      index += classical_sig_len;
    }

    size_t oqs_sig_len = 0;
    if (OQS_SIG_sign_with_ctx_str(key->ctx, sig + index, &oqs_sig_len, tbs,
                                  tbslen, NULL, 0, key->priv) != OQS_SUCCESS) {
      goto err;
    }
    *siglen = classical_sig_len + oqs_sig_len;
  }
  EVP_PKEY_CTX_free(classical_ctx_sign);
  return 1;
err:
  EVP_PKEY_CTX_free(classical_ctx_sign);
  return 0;
}

int oqs_verify_sig(EVP_PKEY *bssl_oqs_pkey, const uint8_t *sig, size_t siglen,
                   const uint8_t *tbs, size_t tbslen) {
  OQS_KEY *key = (OQS_KEY *)(bssl_oqs_pkey->pkey);
  size_t index = 0, classical_sig_len = 0;

  if (is_oqs_hybrid_alg(bssl_oqs_pkey->ameth->pkey_id)) {
    int classical_id = get_classical_nid(bssl_oqs_pkey->ameth->pkey_id);
    EVP_PKEY_CTX *ctx_verify = NULL;
    const EVP_MD *classical_md;
    size_t actual_classical_sig_len = 0;
    int digest_len;
    unsigned char digest[64]; /* SHA512_DIGEST_LENGTH */

    if ((ctx_verify = EVP_PKEY_CTX_new(key->classical_pkey, NULL)) == NULL ||
        EVP_PKEY_verify_init(ctx_verify) <= 0) {
      EVP_PKEY_CTX_free(ctx_verify);
      return 0;
    }
    if ((classical_id == EVP_PKEY_RSA) &&
        (EVP_PKEY_CTX_set_rsa_padding(ctx_verify,
                                      /* RSA_PKCS1_PADDING */ 1) <= 0)) {
      EVP_PKEY_CTX_free(ctx_verify);
      return 0;
    }
    DECODE_UINT32(actual_classical_sig_len, sig);

    switch (key->ctx->claimed_nist_level) {
      case 1:
        classical_md = EVP_sha256();
        digest_len = 32;
        SHA256(tbs, tbslen, (unsigned char *)&digest);
        break;
      case 2:
      case 3:
        classical_md = EVP_sha384();
        digest_len = 48;
        SHA384(tbs, tbslen, (unsigned char *)&digest);
        break;
      default:
        classical_md = EVP_sha512();
        digest_len = 64;
        SHA512(tbs, tbslen, (unsigned char *)&digest);
        break;
    }

    if ((EVP_PKEY_CTX_set_signature_md(ctx_verify, classical_md) <= 0) ||
        (EVP_PKEY_verify(ctx_verify, sig + SIZE_OF_UINT32,
                         actual_classical_sig_len, digest, digest_len) <= 0)) {
      EVP_PKEY_CTX_free(ctx_verify);
      return 0;
    }

    classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
    index += classical_sig_len;
    EVP_PKEY_CTX_free(ctx_verify);
  }

  if (OQS_SIG_verify_with_ctx_str(key->ctx, tbs, tbslen, sig + index,
                                  siglen - classical_sig_len, NULL, 0,
                                  key->pub) != OQS_SUCCESS) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_SIGNATURE);
    return 0;
  }
  return 1;
}

static int pkey_oqs_verify_message(EVP_PKEY_CTX *ctx, const uint8_t *sig,
                                   size_t siglen, const uint8_t *tbs,
                                   size_t tbslen) {
  return oqs_verify_sig(ctx->pkey.get(), sig, siglen, tbs, tbslen);
}

static int pkey_oqs_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  return 1;
}

#define DEFINE_OQS_PKEY_METHOD(ALG, ALG_PKEY)   \
  const EVP_PKEY_CTX_METHOD ALG##_pkey_meth = { \
      ALG_PKEY,                                 \
      NULL /* init */,                          \
      pkey_oqs_copy,                            \
      NULL /* cleanup */,                       \
      ALG##_pkey_keygen,                        \
      NULL /* sign */,                          \
      pkey_oqs_sign_message,                    \
      NULL /* verify */,                        \
      pkey_oqs_verify_message,                  \
      NULL /* verify_recover */,                \
      NULL /* encrypt */,                       \
      NULL /* decrypt */,                       \
      NULL /* derive */,                        \
      NULL /* paramgen */,                      \
      pkey_oqs_ctrl,                            \
  };

#define DEFINE_OQS_PKEY_METHODS(ALG, OQS_METH, ALG_PKEY) \
  DEFINE_PKEY_KEYGEN(ALG, OQS_METH, ALG_PKEY)            \
  DEFINE_OQS_PKEY_METHOD(ALG, ALG_PKEY)

///// OQS_TEMPLATE_FRAGMENT_DEF_PKEY_METHODS_START
DEFINE_OQS_PKEY_METHODS(CROSSrsdp128balanced, OQS_SIG_alg_cross_rsdp_128_balanced, EVP_PKEY_CROSSRSDP128BALANCED)
DEFINE_OQS_PKEY_METHODS(OV_Ip_pkc, OQS_SIG_alg_uov_ov_Ip_pkc, EVP_PKEY_OV_IP_PKC)
DEFINE_OQS_PKEY_METHODS(OV_Ip_pkc_skc, OQS_SIG_alg_uov_ov_Ip_pkc_skc, EVP_PKEY_OV_IP_PKC_SKC)
DEFINE_OQS_PKEY_METHODS(falcon1024, OQS_SIG_alg_falcon_1024, EVP_PKEY_FALCON1024)
DEFINE_OQS_PKEY_METHODS(falcon512, OQS_SIG_alg_falcon_512, EVP_PKEY_FALCON512)
DEFINE_OQS_PKEY_METHODS(rsa3072_falcon512, OQS_SIG_alg_falcon_512, EVP_PKEY_RSA3072_FALCON512)
DEFINE_OQS_PKEY_METHODS(falconpadded1024, OQS_SIG_alg_falcon_padded_1024, EVP_PKEY_FALCONPADDED1024)
DEFINE_OQS_PKEY_METHODS(falconpadded512, OQS_SIG_alg_falcon_padded_512, EVP_PKEY_FALCONPADDED512)
DEFINE_OQS_PKEY_METHODS(mayo1, OQS_SIG_alg_mayo_1, EVP_PKEY_MAYO1)
DEFINE_OQS_PKEY_METHODS(mayo2, OQS_SIG_alg_mayo_2, EVP_PKEY_MAYO2)
DEFINE_OQS_PKEY_METHODS(mayo3, OQS_SIG_alg_mayo_3, EVP_PKEY_MAYO3)
DEFINE_OQS_PKEY_METHODS(mayo5, OQS_SIG_alg_mayo_5, EVP_PKEY_MAYO5)
DEFINE_OQS_PKEY_METHODS(mldsa44, OQS_SIG_alg_ml_dsa_44, EVP_PKEY_MLDSA44)
DEFINE_OQS_PKEY_METHODS(p256_mldsa44, OQS_SIG_alg_ml_dsa_44, EVP_PKEY_P256_MLDSA44)
DEFINE_OQS_PKEY_METHODS(mldsa65, OQS_SIG_alg_ml_dsa_65, EVP_PKEY_MLDSA65)
DEFINE_OQS_PKEY_METHODS(p384_mldsa65, OQS_SIG_alg_ml_dsa_65, EVP_PKEY_P384_MLDSA65)
DEFINE_OQS_PKEY_METHODS(mldsa87, OQS_SIG_alg_ml_dsa_87, EVP_PKEY_MLDSA87)
DEFINE_OQS_PKEY_METHODS(p521_mldsa87, OQS_SIG_alg_ml_dsa_87, EVP_PKEY_P521_MLDSA87)
DEFINE_OQS_PKEY_METHODS(snova2454, OQS_SIG_alg_snova_SNOVA_24_5_4, EVP_PKEY_SNOVA2454)
DEFINE_OQS_PKEY_METHODS(snova2454esk, OQS_SIG_alg_snova_SNOVA_24_5_4_esk, EVP_PKEY_SNOVA2454ESK)
DEFINE_OQS_PKEY_METHODS(snova37172, OQS_SIG_alg_snova_SNOVA_37_17_2, EVP_PKEY_SNOVA37172)
DEFINE_OQS_PKEY_METHODS(snova2455, OQS_SIG_alg_snova_SNOVA_24_5_5, EVP_PKEY_SNOVA2455)
DEFINE_OQS_PKEY_METHODS(snova2965, OQS_SIG_alg_snova_SNOVA_29_6_5, EVP_PKEY_SNOVA2965)
DEFINE_OQS_PKEY_METHODS(sphincssha2128fsimple, OQS_SIG_alg_sphincs_sha2_128f_simple, EVP_PKEY_SPHINCSSHA2128FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha2128ssimple, OQS_SIG_alg_sphincs_sha2_128s_simple, EVP_PKEY_SPHINCSSHA2128SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha2192fsimple, OQS_SIG_alg_sphincs_sha2_192f_simple, EVP_PKEY_SPHINCSSHA2192FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha2192ssimple, OQS_SIG_alg_sphincs_sha2_192s_simple, EVP_PKEY_SPHINCSSHA2192SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha2256fsimple, OQS_SIG_alg_sphincs_sha2_256f_simple, EVP_PKEY_SPHINCSSHA2256FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha2256ssimple, OQS_SIG_alg_sphincs_sha2_256s_simple, EVP_PKEY_SPHINCSSHA2256SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake128fsimple, OQS_SIG_alg_sphincs_shake_128f_simple, EVP_PKEY_SPHINCSSHAKE128FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake128ssimple, OQS_SIG_alg_sphincs_shake_128s_simple, EVP_PKEY_SPHINCSSHAKE128SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake192fsimple, OQS_SIG_alg_sphincs_shake_192f_simple, EVP_PKEY_SPHINCSSHAKE192FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake192ssimple, OQS_SIG_alg_sphincs_shake_192s_simple, EVP_PKEY_SPHINCSSHAKE192SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake256fsimple, OQS_SIG_alg_sphincs_shake_256f_simple, EVP_PKEY_SPHINCSSHAKE256FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake256ssimple, OQS_SIG_alg_sphincs_shake_256s_simple, EVP_PKEY_SPHINCSSHAKE256SSIMPLE)
DEFINE_OQS_PKEY_METHODS(slhdsa_sha2_128s, OQS_SIG_alg_slh_dsa_pure_sha2_128s, EVP_PKEY_SLHDSA_SHA2_128S)
DEFINE_OQS_PKEY_METHODS(slhdsa_sha2_128f, OQS_SIG_alg_slh_dsa_pure_sha2_128f, EVP_PKEY_SLHDSA_SHA2_128F)
DEFINE_OQS_PKEY_METHODS(slhdsa_sha2_192s, OQS_SIG_alg_slh_dsa_pure_sha2_192s, EVP_PKEY_SLHDSA_SHA2_192S)
DEFINE_OQS_PKEY_METHODS(slhdsa_sha2_192f, OQS_SIG_alg_slh_dsa_pure_sha2_192f, EVP_PKEY_SLHDSA_SHA2_192F)
DEFINE_OQS_PKEY_METHODS(slhdsa_sha2_256s, OQS_SIG_alg_slh_dsa_pure_sha2_256s, EVP_PKEY_SLHDSA_SHA2_256S)
DEFINE_OQS_PKEY_METHODS(slhdsa_sha2_256f, OQS_SIG_alg_slh_dsa_pure_sha2_256f, EVP_PKEY_SLHDSA_SHA2_256F)
DEFINE_OQS_PKEY_METHODS(slhdsa_shake_128s, OQS_SIG_alg_slh_dsa_pure_shake_128s, EVP_PKEY_SLHDSA_SHAKE_128S)
DEFINE_OQS_PKEY_METHODS(slhdsa_shake_128f, OQS_SIG_alg_slh_dsa_pure_shake_128f, EVP_PKEY_SLHDSA_SHAKE_128F)
DEFINE_OQS_PKEY_METHODS(slhdsa_shake_192s, OQS_SIG_alg_slh_dsa_pure_shake_192s, EVP_PKEY_SLHDSA_SHAKE_192S)
DEFINE_OQS_PKEY_METHODS(slhdsa_shake_192f, OQS_SIG_alg_slh_dsa_pure_shake_192f, EVP_PKEY_SLHDSA_SHAKE_192F)
DEFINE_OQS_PKEY_METHODS(slhdsa_shake_256s, OQS_SIG_alg_slh_dsa_pure_shake_256s, EVP_PKEY_SLHDSA_SHAKE_256S)
DEFINE_OQS_PKEY_METHODS(slhdsa_shake_256f, OQS_SIG_alg_slh_dsa_pure_shake_256f, EVP_PKEY_SLHDSA_SHAKE_256F)
///// OQS_TEMPLATE_FRAGMENT_DEF_PKEY_METHODS_END
