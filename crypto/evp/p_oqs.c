/* Copyright (c) 2017, Google Inc., modifications by the Open Quantum Safe project 2020.
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
#include <oqs/oqs.h>

#include "internal.h"

// oqs has no parameters to copy.
static int pkey_oqs_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) { return 1; }

#define DEFINE_PKEY_KEYGEN(ALG, OQS_METH, ALG_PKEY)                     \
static int ALG##_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {       \
  OQS_KEY *key = OPENSSL_malloc(sizeof(OQS_KEY));                       \
  if (!key) {                                                           \
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                       \
    return 0;                                                           \
  }                                                                     \
                                                                        \
  if (!EVP_PKEY_set_type(pkey, ALG_PKEY)) {                             \
    OPENSSL_free(key);                                                  \
    return 0;                                                           \
  }                                                                     \
                                                                        \
  key->ctx = OQS_SIG_new(OQS_METH);                                     \
  if (!key->ctx) {                                                      \
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);                \
    return 0;                                                           \
  }                                                                     \
                                                                        \
  key->priv = malloc(key->ctx->length_secret_key);                      \
  if(!key->priv)                                                        \
  {                                                                     \
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                       \
    return 0;                                                           \
  }                                                                     \
                                                                        \
  key->pub = malloc(key->ctx->length_public_key);                       \
  if(!key->pub)                                                         \
  {                                                                     \
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                       \
    return 0;                                                           \
  }                                                                     \
                                                                        \
  if (OQS_SIG_keypair(key->ctx, key->pub, key->priv) != OQS_SUCCESS) {  \
    OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);                         \
    return 0;                                                           \
  }                                                                     \
  key->has_private = 1;                                                 \
                                                                        \
  OPENSSL_free(pkey->pkey.ptr);                                         \
  pkey->pkey.ptr = key;                                                 \
  return 1;                                                             \
}

static int pkey_oqs_sign_message(EVP_PKEY_CTX *ctx, uint8_t *sig,
                                 size_t *siglen, const uint8_t *tbs,
                                 size_t tbslen) {
  OQS_KEY *key = ctx->pkey->pkey.ptr;
  if (!key->has_private) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
    return 0;
  }

  if (sig == NULL) {
    *siglen = key->ctx->length_signature;
    return 1;
  }

  if (*siglen < key->ctx->length_signature) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (OQS_SIG_sign(key->ctx, sig, siglen, tbs, tbslen, key->priv) != OQS_SUCCESS) {
    return 0;
  }

  return 1;
}

static int pkey_oqs_verify_message(EVP_PKEY_CTX *ctx, const uint8_t *sig,
                                   size_t siglen, const uint8_t *tbs,
                                   size_t tbslen) {
  OQS_KEY *key = ctx->pkey->pkey.ptr;
  if (siglen > key->ctx->length_signature ||
      OQS_SIG_verify(key->ctx, tbs, tbslen, sig, siglen, key->pub) != OQS_SUCCESS) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_SIGNATURE);
    return 0;
  }

  return 1;
}

static int pkey_oqs_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
    return 1;
}

#define DEFINE_OQS_PKEY_METHOD(ALG, ALG_PKEY) \
const EVP_PKEY_METHOD ALG##_pkey_meth = {     \
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
DEFINE_PKEY_KEYGEN(ALG, OQS_METH, ALG_PKEY)              \
DEFINE_OQS_PKEY_METHOD(ALG, ALG_PKEY)

///// OQS_TEMPLATE_FRAGMENT_DEF_PKEY_METHODS_START
DEFINE_OQS_PKEY_METHODS(dilithium2, OQS_SIG_alg_dilithium_2, EVP_PKEY_DILITHIUM2)
DEFINE_OQS_PKEY_METHODS(dilithium3, OQS_SIG_alg_dilithium_3, EVP_PKEY_DILITHIUM3)
DEFINE_OQS_PKEY_METHODS(dilithium5, OQS_SIG_alg_dilithium_5, EVP_PKEY_DILITHIUM5)
DEFINE_OQS_PKEY_METHODS(dilithium2_aes, OQS_SIG_alg_dilithium_2_aes, EVP_PKEY_DILITHIUM2_AES)
DEFINE_OQS_PKEY_METHODS(dilithium3_aes, OQS_SIG_alg_dilithium_3_aes, EVP_PKEY_DILITHIUM3_AES)
DEFINE_OQS_PKEY_METHODS(dilithium5_aes, OQS_SIG_alg_dilithium_5_aes, EVP_PKEY_DILITHIUM5_AES)
DEFINE_OQS_PKEY_METHODS(falcon512, OQS_SIG_alg_falcon_512, EVP_PKEY_FALCON512)
DEFINE_OQS_PKEY_METHODS(falcon1024, OQS_SIG_alg_falcon_1024, EVP_PKEY_FALCON1024)
DEFINE_OQS_PKEY_METHODS(sphincsharaka128frobust, OQS_SIG_alg_sphincs_haraka_128f_robust, EVP_PKEY_SPHINCSHARAKA128FROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsharaka128fsimple, OQS_SIG_alg_sphincs_haraka_128f_simple, EVP_PKEY_SPHINCSHARAKA128FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsharaka128srobust, OQS_SIG_alg_sphincs_haraka_128s_robust, EVP_PKEY_SPHINCSHARAKA128SROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsharaka128ssimple, OQS_SIG_alg_sphincs_haraka_128s_simple, EVP_PKEY_SPHINCSHARAKA128SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsharaka192frobust, OQS_SIG_alg_sphincs_haraka_192f_robust, EVP_PKEY_SPHINCSHARAKA192FROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsharaka192fsimple, OQS_SIG_alg_sphincs_haraka_192f_simple, EVP_PKEY_SPHINCSHARAKA192FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsharaka192srobust, OQS_SIG_alg_sphincs_haraka_192s_robust, EVP_PKEY_SPHINCSHARAKA192SROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsharaka192ssimple, OQS_SIG_alg_sphincs_haraka_192s_simple, EVP_PKEY_SPHINCSHARAKA192SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsharaka256frobust, OQS_SIG_alg_sphincs_haraka_256f_robust, EVP_PKEY_SPHINCSHARAKA256FROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsharaka256fsimple, OQS_SIG_alg_sphincs_haraka_256f_simple, EVP_PKEY_SPHINCSHARAKA256FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsharaka256srobust, OQS_SIG_alg_sphincs_haraka_256s_robust, EVP_PKEY_SPHINCSHARAKA256SROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsharaka256ssimple, OQS_SIG_alg_sphincs_haraka_256s_simple, EVP_PKEY_SPHINCSHARAKA256SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha256128frobust, OQS_SIG_alg_sphincs_sha256_128f_robust, EVP_PKEY_SPHINCSSHA256128FROBUST)
DEFINE_OQS_PKEY_METHODS(sphincssha256128fsimple, OQS_SIG_alg_sphincs_sha256_128f_simple, EVP_PKEY_SPHINCSSHA256128FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha256128srobust, OQS_SIG_alg_sphincs_sha256_128s_robust, EVP_PKEY_SPHINCSSHA256128SROBUST)
DEFINE_OQS_PKEY_METHODS(sphincssha256128ssimple, OQS_SIG_alg_sphincs_sha256_128s_simple, EVP_PKEY_SPHINCSSHA256128SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha256192frobust, OQS_SIG_alg_sphincs_sha256_192f_robust, EVP_PKEY_SPHINCSSHA256192FROBUST)
DEFINE_OQS_PKEY_METHODS(sphincssha256192fsimple, OQS_SIG_alg_sphincs_sha256_192f_simple, EVP_PKEY_SPHINCSSHA256192FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha256192srobust, OQS_SIG_alg_sphincs_sha256_192s_robust, EVP_PKEY_SPHINCSSHA256192SROBUST)
DEFINE_OQS_PKEY_METHODS(sphincssha256192ssimple, OQS_SIG_alg_sphincs_sha256_192s_simple, EVP_PKEY_SPHINCSSHA256192SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha256256frobust, OQS_SIG_alg_sphincs_sha256_256f_robust, EVP_PKEY_SPHINCSSHA256256FROBUST)
DEFINE_OQS_PKEY_METHODS(sphincssha256256fsimple, OQS_SIG_alg_sphincs_sha256_256f_simple, EVP_PKEY_SPHINCSSHA256256FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincssha256256srobust, OQS_SIG_alg_sphincs_sha256_256s_robust, EVP_PKEY_SPHINCSSHA256256SROBUST)
DEFINE_OQS_PKEY_METHODS(sphincssha256256ssimple, OQS_SIG_alg_sphincs_sha256_256s_simple, EVP_PKEY_SPHINCSSHA256256SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake256128frobust, OQS_SIG_alg_sphincs_shake256_128f_robust, EVP_PKEY_SPHINCSSHAKE256128FROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsshake256128fsimple, OQS_SIG_alg_sphincs_shake256_128f_simple, EVP_PKEY_SPHINCSSHAKE256128FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake256128srobust, OQS_SIG_alg_sphincs_shake256_128s_robust, EVP_PKEY_SPHINCSSHAKE256128SROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsshake256128ssimple, OQS_SIG_alg_sphincs_shake256_128s_simple, EVP_PKEY_SPHINCSSHAKE256128SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake256192frobust, OQS_SIG_alg_sphincs_shake256_192f_robust, EVP_PKEY_SPHINCSSHAKE256192FROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsshake256192fsimple, OQS_SIG_alg_sphincs_shake256_192f_simple, EVP_PKEY_SPHINCSSHAKE256192FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake256192srobust, OQS_SIG_alg_sphincs_shake256_192s_robust, EVP_PKEY_SPHINCSSHAKE256192SROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsshake256192ssimple, OQS_SIG_alg_sphincs_shake256_192s_simple, EVP_PKEY_SPHINCSSHAKE256192SSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake256256frobust, OQS_SIG_alg_sphincs_shake256_256f_robust, EVP_PKEY_SPHINCSSHAKE256256FROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsshake256256fsimple, OQS_SIG_alg_sphincs_shake256_256f_simple, EVP_PKEY_SPHINCSSHAKE256256FSIMPLE)
DEFINE_OQS_PKEY_METHODS(sphincsshake256256srobust, OQS_SIG_alg_sphincs_shake256_256s_robust, EVP_PKEY_SPHINCSSHAKE256256SROBUST)
DEFINE_OQS_PKEY_METHODS(sphincsshake256256ssimple, OQS_SIG_alg_sphincs_shake256_256s_simple, EVP_PKEY_SPHINCSSHAKE256256SSIMPLE)
///// OQS_TEMPLATE_FRAGMENT_DEF_PKEY_METHODS_END
