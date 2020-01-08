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

// oqs_sigdefault has no parameters to copy.
static int pkey_oqs_sigdefault_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) { return 1; }

static int pkey_oqs_sigdefault_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  OQS_KEY *key = OPENSSL_malloc(sizeof(OQS_KEY));
  if (key == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  if (!EVP_PKEY_set_type(pkey, EVP_PKEY_OQS_SIGDEFAULT)) {
    OPENSSL_free(key);
    return 0;
  }

  key->ctx = OQS_SIG_new("oqsdefault");
  if (!key->ctx) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    return 0;
  }

  if (OQS_SIG_keypair(key->ctx, key->pub, key->priv) != OQS_SUCCESS) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);
    return 0;
  }
  key->has_private = 1;

  OPENSSL_free(pkey->pkey.ptr);
  pkey->pkey.ptr = key;
  return 1;
}

static int pkey_oqs_sigdefault_sign_message(EVP_PKEY_CTX *ctx, uint8_t *sig,
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

static int pkey_oqs_sigdefault_verify_message(EVP_PKEY_CTX *ctx, const uint8_t *sig,
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

const EVP_PKEY_METHOD oqs_sigdefault_pkey_meth = {
    EVP_PKEY_OQS_SIGDEFAULT,
    NULL /* init */,
    pkey_oqs_sigdefault_copy,
    NULL /* cleanup */,
    pkey_oqs_sigdefault_keygen,
    NULL /* sign */,
    pkey_oqs_sigdefault_sign_message,
    NULL /* verify */,
    pkey_oqs_sigdefault_verify_message,
    NULL /* verify_recover */,
    NULL /* encrypt */,
    NULL /* decrypt */,
    NULL /* derive */,
    NULL /* paramgen */,
    NULL /* ctrl */,
};
