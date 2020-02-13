/* Copyright (c) 2017, Google Inc.
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

// oqs_sig has no parameters to copy.
static int pkey_oqs_sig_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) { return 1; }

#define DEFINE_PKEY_KEYGEN(ALG, ALG_OQS_ID, ALG_PKEY_ID)		\
static int ALG##_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {	\
  OQS_KEY *key = OPENSSL_malloc(sizeof(OQS_KEY));			\
  if (!key) {								\
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);			\
    return 0;								\
  }									\
									\
  if (!EVP_PKEY_set_type(pkey, ALG_PKEY_ID)) {				\
    OPENSSL_free(key);							\
    return 0;								\
  }									\
									\
  key->ctx = OQS_SIG_new(ALG_OQS_ID);					\
  if (!key->ctx) {							\
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);		\
    return 0;								\
  }									\
									\
  key->priv = malloc(key->ctx->length_secret_key);			\
  if(!key->priv)							\
  {									\
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);			\
    return 0;								\
  }									\
									\
  key->pub = malloc(key->ctx->length_public_key);			\
  if(!key->pub)								\
  {									\
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);			\
    return 0;								\
  }									\
									\
  if (OQS_SIG_keypair(key->ctx, key->pub, key->priv) != OQS_SUCCESS) {	\
    OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);				\
    return 0;								\
  }									\
  key->has_private = 1;							\
									\
  OPENSSL_free(pkey->pkey.ptr);						\
  pkey->pkey.ptr = key;							\
  return 1;								\
}

static int pkey_oqs_sig_sign_message(EVP_PKEY_CTX *ctx, uint8_t *sig,
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

static int pkey_oqs_sig_verify_message(EVP_PKEY_CTX *ctx, const uint8_t *sig,
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

static int pkey_oqs_sig_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
    return 1;
}

#define DEFINE_OQS_SIG_PKEY_METHOD(ALG, ALG_PKEY_ID) \
const EVP_PKEY_METHOD ALG##_pkey_meth = {	     \
    ALG_PKEY_ID,				     \
    NULL /* init */,				     \
    pkey_oqs_sig_copy,				     \
    NULL /* cleanup */,				     \
    ALG##_pkey_keygen,				     \
    NULL /* sign */,				     \
    pkey_oqs_sig_sign_message,			     \
    NULL /* verify */,				     \
    pkey_oqs_sig_verify_message,		     \
    NULL /* verify_recover */,			     \
    NULL /* encrypt */,				     \
    NULL /* decrypt */,				     \
    NULL /* derive */,				     \
    NULL /* paramgen */,			     \
    pkey_oqs_sig_ctrl,				     \
};


#define DEFINE_OQS_FUNCTIONS(ALG, ALG_OQS_ID, ALG_PKEY_ID) \
DEFINE_PKEY_KEYGEN(ALG, ALG_OQS_ID, ALG_PKEY_ID)	   \
DEFINE_OQS_SIG_PKEY_METHOD(ALG, ALG_PKEY_ID)

DEFINE_OQS_FUNCTIONS(oqs_sigdefault, 	OQS_SIG_alg_default, 		EVP_PKEY_OQS_SIGDEFAULT)
DEFINE_OQS_FUNCTIONS(dilithium2,	OQS_SIG_alg_dilithium_2, 	EVP_PKEY_DILITHIUM2)
DEFINE_OQS_FUNCTIONS(dilithium3, 	OQS_SIG_alg_dilithium_3, 	EVP_PKEY_DILITHIUM3)
DEFINE_OQS_FUNCTIONS(dilithium4, 	OQS_SIG_alg_dilithium_4, 	EVP_PKEY_DILITHIUM4)
//DEFINE_OQS_FUNCTIONS(picnicl1fs, 	OQS_SIG_alg_picnic_L1_FS,	EVP_PKEY_PICNICL1FS)
//DEFINE_OQS_FUNCTIONS(picnic2l1fs, 	OQS_SIG_alg_picnic2_L1_FS,	EVP_PKEY_PICNIC2L1FS)
DEFINE_OQS_FUNCTIONS(qteslapi, 		OQS_SIG_alg_qTesla_p_I, 	EVP_PKEY_QTESLAPI)
DEFINE_OQS_FUNCTIONS(qteslapiii, 	OQS_SIG_alg_qTesla_p_III, 	EVP_PKEY_QTESLAPIII)

// FIXMEOQS: add template
