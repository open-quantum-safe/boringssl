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


static void oqs_sig_free(EVP_PKEY *pkey) {
  OPENSSL_free(pkey->pkey.ptr);
  pkey->pkey.ptr = NULL;
}

#define DEFINE_OQS_SIG_SET_PRIV_RAW(ALG, ALG_OQS_ID)			       \
static int ALG##_set_priv_raw(EVP_PKEY *pkey, const uint8_t *in, size_t len) { \
  OQS_KEY *key = OPENSSL_malloc(sizeof(OQS_KEY));			       \
  if (key == NULL) {							       \
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);			       \
    return 0;								       \
  }									       \
									       \
  key->ctx = OQS_SIG_new(ALG_OQS_ID);					       \
  if (!key->ctx) {							       \
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);		       \
    return 0;								       \
  }									       \
									       \
  if (len != key->ctx->length_secret_key) {				       \
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);				       \
    return 0;								       \
  }									       \
									       \
  key->priv = malloc(key->ctx->length_secret_key);			       \
  key->pub = malloc(key->ctx->length_public_key);			       \
  if (OQS_SIG_keypair(key->ctx, key->pub, key->priv) != OQS_SUCCESS) {	       \
    OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);				       \
    return 0;								       \
  }									       \
  key->has_private = 1;							       \
									       \
  oqs_sig_free(pkey);							       \
  pkey->pkey.ptr = key;							       \
  return 1;								       \
}

#define DEFINE_OQS_SIG_SET_PUB_RAW(ALG, ALG_OQS_ID)			      \
static int ALG##_set_pub_raw(EVP_PKEY *pkey, const uint8_t *in, size_t len) { \
  OQS_KEY *key = OPENSSL_malloc(sizeof(OQS_KEY));			      \
  if (key == NULL) {							      \
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);			      \
    return 0;								      \
  }									      \
									      \
  key->ctx = OQS_SIG_new(ALG_OQS_ID);					      \
  if (!key->ctx) {							      \
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);		      \
    return 0;								      \
  }									      \
									      \
  if (len != key->ctx->length_public_key) {				      \
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);				      \
    return 0;								      \
  }									      \
									      \
  key->pub = malloc(key->ctx->length_public_key);			      \
  OPENSSL_memcpy(key->pub, in, key->ctx->length_public_key);		      \
  key->has_private = 0;							      \
									      \
  oqs_sig_free(pkey);							      \
  pkey->pkey.ptr = key;							      \
  return 1;								      \
}

static int oqs_sig_get_priv_raw(const EVP_PKEY *pkey, uint8_t *out,
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

static int oqs_sig_get_pub_raw(const EVP_PKEY *pkey, uint8_t *out,
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

#define DEFINE_OQS_SIG_PUB_DECODE(ALG)				    \
static int ALG##_pub_decode(EVP_PKEY *out, CBS *params, CBS *key) { \
  if (CBS_len(params) != 0) {					    \
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);			    \
    return 0;							    \
  }								    \
								    \
  return ALG##_set_pub_raw(out, CBS_data(key), CBS_len(key));	    \
}

#define DEFINE_OQS_SIG_PUB_ENCODE(ALG)					     \
static int ALG##_pub_encode(CBB *out, const EVP_PKEY *pkey) {		     \
  const OQS_KEY *key = pkey->pkey.ptr;					     \
									     \
  /* See RFC 8410, section 4. */					     \
  CBB spki, algorithm, oid, key_bitstring;				     \
  if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||			     \
    !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||		     \
    !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||			     \
    !CBB_add_bytes(&oid, ALG##_asn1_meth.oid, ALG##_asn1_meth.oid_len) ||    \
    !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||		     \
    !CBB_add_u8(&key_bitstring, 0 /* padding */) ||			     \
    !CBB_add_bytes(&key_bitstring, key->pub, key->ctx->length_public_key) || \
    !CBB_flush(out)) {							     \
       OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);			     \
       return 0;							     \
    }									     \
									     \
  return 1;								     \
}

static int oqs_sig_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
  const OQS_KEY *a_key = a->pkey.ptr;
  const OQS_KEY *b_key = b->pkey.ptr;
  return OPENSSL_memcmp(a_key->pub, b_key->pub, a_key->ctx->length_public_key) == 0;
}

#define DEFINE_OQS_SIG_PRIV_DECODE(ALG)				     \
static int ALG##_priv_decode(EVP_PKEY *out, CBS *params, CBS *key) { \
/* See RFC 8410, section 7. */					     \
								     \
  CBS inner;							     \
  if (CBS_len(params) != 0 ||					     \
      !CBS_get_asn1(key, &inner, CBS_ASN1_OCTETSTRING) ||	     \
      CBS_len(key) != 0) {					     \
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);			     \
    return 0;							     \
  }								     \
								     \
  return ALG##_set_priv_raw(out, CBS_data(&inner), CBS_len(&inner)); \
}

#define DEFINE_OQS_SIG_PRIV_ENCODE(ALG)			       \
static int ALG##_priv_encode(CBB *out, const EVP_PKEY *pkey) { \
  OQS_KEY *key = pkey->pkey.ptr;			       \
  if (!key->has_private) {				       \
    OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);	       \
    return 0;						       \
  }							       \
							       \
  /* See RFC 8410, section 7. */			       \
  CBB pkcs8, algorithm, oid, private_key, inner;	       \
  if (!CBB_add_asn1(out, &pkcs8, CBS_ASN1_SEQUENCE) ||	       \
      !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||	       \
      !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||  \
      !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||		\
      !CBB_add_bytes(&oid, ALG##_asn1_meth.oid, ALG##_asn1_meth.oid_len) || \
      !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||	\
      !CBB_add_asn1(&private_key, &inner, CBS_ASN1_OCTETSTRING) ||	\
      !CBB_add_bytes(&inner, key->priv, key->ctx->length_secret_key) || \
      !CBB_flush(out)) {						\
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);				\
    return 0;								\
  }									\
									\
  return 1;								\
}

// FIXMEOQS: boringssl uses an in for this function, which is too small for some PQ schemes.
//           We'll need to refactor the API to support them.
static int oqs_sig_size(const EVP_PKEY *pkey) {
  const OQS_KEY *key = pkey->pkey.ptr;
  return key->ctx->length_signature;
}

// FIXMEOQS: boringssl uses an in for this function, which is too small for some PQ schemes.
//           We'll need to refactor the API to support them.
// FIXMEOQS: what should we return here? RSA returns the modulus size, ECDSA returns the length
//           of the group order. This function is not used in the boringssl code base (other than
//           for some rsa-specific processing), so it's unclear what we should do. Currently
//           returning the public key size, which won't overflow the int for the schemes in OQS (for now).
static int oqs_sig_bits(const EVP_PKEY *pkey) {
  const OQS_KEY *key = pkey->pkey.ptr;
  return key->ctx->length_public_key;
}

#define DEFINE_OQS_SIG_PKEY_ASN1_METHOD(ALG, ALG_PKEY_ID) \
const EVP_PKEY_ASN1_METHOD ALG##_asn1_meth = {		  \
    ALG_PKEY_ID,					  \
    ALG##_OID,						  \
    ALG##_OID_LEN, /* FIXMEOQS: make a macro for this */  \
    ALG##_pub_decode,					  \
    ALG##_pub_encode,					  \
    oqs_sig_pub_cmp,					  \
    ALG##_priv_decode,					  \
    ALG##_priv_encode,					  \
    ALG##_set_priv_raw,					  \
    ALG##_set_pub_raw,					  \
    oqs_sig_get_priv_raw,				  \
    oqs_sig_get_pub_raw,				  \
    NULL /* pkey_opaque */,				  \
    oqs_sig_size,					  \
    oqs_sig_bits,					  \
    NULL /* param_missing */,				  \
    NULL /* param_copy */,				  \
    NULL /* param_cmp */,				  \
    oqs_sig_free,					  \
};

#define DEFINE_OQS_FUNCTIONS(ALG, ALG_OQS_ID, ALG_PKEY_ID) \
DEFINE_OQS_SIG_SET_PUB_RAW(ALG, ALG_OQS_ID)		   \
DEFINE_OQS_SIG_SET_PRIV_RAW(ALG, ALG_OQS_ID)		   \
DEFINE_OQS_SIG_PUB_ENCODE(ALG)				   \
DEFINE_OQS_SIG_PUB_DECODE(ALG)				   \
DEFINE_OQS_SIG_PRIV_ENCODE(ALG)				   \
DEFINE_OQS_SIG_PRIV_DECODE(ALG)				   \
DEFINE_OQS_SIG_PKEY_ASN1_METHOD(ALG, ALG_PKEY_ID)

// OQS note: the ALG_OID values can be found in the kObjectData array in crypto/objects/obj_dat.h
#define oqs_sigdefault_OID 	{0x2B,0xCE,0x0F,0x01,0x01}
#define oqs_sigdefault_OID_LEN	5
#define dilithium2_OID		{0x2B,0xCE,0x0F,0x02,0x01}
#define dilithium2_OID_LEN	5
#define dilithium3_OID		{0x2B,0xCE,0x0F,0x02,0x04}
#define dilithium3_OID_LEN	5
#define dilithium4_OID		{0x2B,0xCE,0x0F,0x02,0x05}
#define dilithium4_OID_LEN	5
//#define picnicl1fs_OID		{0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x59,0x02,0x01,0x01}
//#define picnicl1fs_OID_LEN	11
//#define picnic2l1fs_OID		{0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x59,0x02,0x01,0x0B}
//#define picnic2l1fs_OID_LEN	11
#define qteslapi_OID		{0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x59,0x02,0x02,0x0A}
#define qteslapi_OID_LEN	11
#define qteslapiii_OID		{0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x59,0x02,0x02,0x14}
#define qteslapiii_OID_LEN	11

// FIXMEOQS: add template
DEFINE_OQS_FUNCTIONS(oqs_sigdefault, 	OQS_SIG_alg_default, 		EVP_PKEY_OQS_SIGDEFAULT)
DEFINE_OQS_FUNCTIONS(dilithium2,	OQS_SIG_alg_dilithium_2, 	EVP_PKEY_DILITHIUM2)
DEFINE_OQS_FUNCTIONS(dilithium3, 	OQS_SIG_alg_dilithium_3, 	EVP_PKEY_DILITHIUM3)
DEFINE_OQS_FUNCTIONS(dilithium4, 	OQS_SIG_alg_dilithium_4, 	EVP_PKEY_DILITHIUM4)
//DEFINE_OQS_FUNCTIONS(picnicl1fs, 	OQS_SIG_alg_picnic_L1_FS,	EVP_PKEY_PICNICL1FS)
//DEFINE_OQS_FUNCTIONS(picnic2l1fs, 	OQS_SIG_alg_picnic2_L1_FS,	EVP_PKEY_PICNIC2L1FS)
DEFINE_OQS_FUNCTIONS(qteslapi, 		OQS_SIG_alg_qTesla_p_I, 	EVP_PKEY_QTESLAPI)
DEFINE_OQS_FUNCTIONS(qteslapiii, 	OQS_SIG_alg_qTesla_p_III, 	EVP_PKEY_QTESLAPIII)
// FIXMEOQS: add template
