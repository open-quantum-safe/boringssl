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
  OQS_KEY *key = (OQS_KEY *)(OPENSSL_malloc(sizeof(OQS_KEY)));          \
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
  key->priv = (uint8_t *)(malloc(key->ctx->length_secret_key));         \
  if(!key->priv)                                                        \
  {                                                                     \
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);                       \
    return 0;                                                           \
  }                                                                     \
                                                                        \
  key->pub = (uint8_t *)(malloc(key->ctx->length_public_key));          \
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
  OQS_KEY *key = (OQS_KEY *)(ctx->pkey->pkey.ptr);
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
  OQS_KEY *key = (OQS_KEY *)(ctx->pkey->pkey.ptr);
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
DEFINE_OQS_PKEY_METHODS(falcon512, OQS_SIG_alg_falcon_512, EVP_PKEY_FALCON512)
DEFINE_OQS_PKEY_METHODS(falcon1024, OQS_SIG_alg_falcon_1024, EVP_PKEY_FALCON1024)
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
///// OQS_TEMPLATE_FRAGMENT_DEF_PKEY_METHODS_END
