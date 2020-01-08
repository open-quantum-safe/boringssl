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

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include <oqs/oqs.h>

#include "internal.h"
#include "../internal.h"


static void oqs_sigdefault_free(EVP_PKEY *pkey) {
  OPENSSL_free(pkey->pkey.ptr);
  pkey->pkey.ptr = NULL;
}

static int oqs_sigdefault_set_priv_raw(EVP_PKEY *pkey, const uint8_t *in, size_t len) {
  OQS_KEY *key = OPENSSL_malloc(sizeof(OQS_KEY));
  if (key == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  key->ctx = OQS_SIG_new("oqsdefault");
  if (!key->ctx) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    return 0;
  }

  if (len != key->ctx->length_secret_key) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  if (OQS_SIG_keypair(key->ctx, key->pub, key->priv) != OQS_SUCCESS) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);
    return 0;
  }
  key->has_private = 1;

  oqs_sigdefault_free(pkey);
  pkey->pkey.ptr = key;
  return 1;
}

static int oqs_sigdefault_set_pub_raw(EVP_PKEY *pkey, const uint8_t *in, size_t len) {
  OQS_KEY *key = OPENSSL_malloc(sizeof(OQS_KEY));
  if (key == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  key->ctx = OQS_SIG_new("oqsdefault");
  if (!key->ctx) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    return 0;
  }

  if (len != key->ctx->length_public_key) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  OPENSSL_memcpy(key->pub, in, key->ctx->length_public_key);
  key->has_private = 0;

  oqs_sigdefault_free(pkey);
  pkey->pkey.ptr = key;
  return 1;
}

static int oqs_sigdefault_get_priv_raw(const EVP_PKEY *pkey, uint8_t *out,
                                size_t *out_len) {
  const OQS_KEY *key = pkey->pkey.ptr;
  if (!key->has_private) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
    return 0;
  }

  if (out == NULL) {
    *out_len = key->ctx->length_secret_key;
    return 1;
  }

  if (*out_len < key->ctx->length_secret_key) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  OPENSSL_memcpy(out, key->priv, key->ctx->length_secret_key);
  *out_len = key->ctx->length_secret_key;
  return 1;
}

static int oqs_sigdefault_get_pub_raw(const EVP_PKEY *pkey, uint8_t *out,
                               size_t *out_len) {
  const OQS_KEY *key = pkey->pkey.ptr;
  if (out == NULL) {
    *out_len = key->ctx->length_public_key;
    return 1;
  }

  if (*out_len < key->ctx->length_public_key) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  OPENSSL_memcpy(out, key->pub, key->ctx->length_public_key);
  *out_len = key->ctx->length_public_key;
  return 1;
}

static int oqs_sigdefault_pub_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  if (CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  return oqs_sigdefault_set_pub_raw(out, CBS_data(key), CBS_len(key));
}

static int oqs_sigdefault_pub_encode(CBB *out, const EVP_PKEY *pkey) {
  const OQS_KEY *key = pkey->pkey.ptr;

  // See RFC 8410, section 4.
  CBB spki, algorithm, oid, key_bitstring;
  if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, oqs_sigdefault_asn1_meth.oid, oqs_sigdefault_asn1_meth.oid_len) ||
      !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&key_bitstring, 0 /* padding */) ||
      !CBB_add_bytes(&key_bitstring, key->pub, key->ctx->length_public_key) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int oqs_sigdefault_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
  const OQS_KEY *a_key = a->pkey.ptr;
  const OQS_KEY *b_key = b->pkey.ptr;
  return OPENSSL_memcmp(a_key->pub, b_key->pub, a_key->ctx->length_public_key) == 0;
}

static int oqs_sigdefault_priv_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  // See RFC 8410, section 7.

  CBS inner;
  if (CBS_len(params) != 0 ||
      !CBS_get_asn1(key, &inner, CBS_ASN1_OCTETSTRING) ||
      CBS_len(key) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  return oqs_sigdefault_set_priv_raw(out, CBS_data(&inner), CBS_len(&inner));
}

static int oqs_sigdefault_priv_encode(CBB *out, const EVP_PKEY *pkey) {
  OQS_KEY *key = pkey->pkey.ptr;
  if (!key->has_private) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
    return 0;
  }

  // See RFC 8410, section 7.
  CBB pkcs8, algorithm, oid, private_key, inner;
  if (!CBB_add_asn1(out, &pkcs8, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
      !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, oqs_sigdefault_asn1_meth.oid, oqs_sigdefault_asn1_meth.oid_len) ||
      !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_asn1(&private_key, &inner, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&inner, key->priv, key->ctx->length_secret_key) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int oqs_sigdefault_size(const EVP_PKEY *pkey) {
  const OQS_KEY *key = pkey->pkey.ptr;
  return key->ctx->length_secret_key + key->ctx->length_public_key;
}

static int oqs_sigdefault_bits(const EVP_PKEY *pkey) { return 253; /*TODO: Update with actual bit count*/ }

const EVP_PKEY_ASN1_METHOD oqs_sigdefault_asn1_meth = {
    EVP_PKEY_OQS_SIGDEFAULT,
    {0x2c, 0x66, 0x71},
    3,
    oqs_sigdefault_pub_decode,
    oqs_sigdefault_pub_encode,
    oqs_sigdefault_pub_cmp,
    oqs_sigdefault_priv_decode,
    oqs_sigdefault_priv_encode,
    oqs_sigdefault_set_priv_raw,
    oqs_sigdefault_set_pub_raw,
    oqs_sigdefault_get_priv_raw,
    oqs_sigdefault_get_pub_raw,
    NULL /* pkey_opaque */,
    oqs_sigdefault_size,
    oqs_sigdefault_bits,
    NULL /* param_missing */,
    NULL /* param_copy */,
    NULL /* param_cmp */,
    oqs_sigdefault_free,
};
