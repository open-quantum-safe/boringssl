// Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef OPENSSL_HEADER_CRYPTO_EVP_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_EVP_INTERNAL_H

#include <openssl/evp.h>

#include <array>

#include <openssl/span.h>

#include <oqs/oqs.h>

#include "../internal.h"

#if defined(__cplusplus)
extern "C" {
#endif


typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
typedef struct evp_pkey_ctx_method_st EVP_PKEY_CTX_METHOD;

struct evp_pkey_alg_st {
  // method implements operations for this |EVP_PKEY_ALG|.
  const EVP_PKEY_ASN1_METHOD *method;
};

enum evp_decode_result_t {
  evp_decode_error = 0,
  evp_decode_ok = 1,
  evp_decode_unsupported = 2,
};

struct evp_pkey_asn1_method_st {
  // pkey_id contains one of the |EVP_PKEY_*| values and corresponds to the OID
  // in the key type's AlgorithmIdentifier.
  int pkey_id;
  uint8_t oid[13]; // OQS note: increased length (was 9) to accomodate larger PQ OIDs
  uint8_t oid_len;

  const EVP_PKEY_CTX_METHOD *pkey_method;

  // pub_decode decodes |params| and |key| as a SubjectPublicKeyInfo
  // and writes the result into |out|. It returns |evp_decode_ok| on success,
  // and |evp_decode_error| on error, and |evp_decode_unsupported| if the input
  // was not supported by this |EVP_PKEY_ALG|. In case of
  // |evp_decode_unsupported|, it does not add an error to the error queue. May
  // modify |params| and |key|. Callers must make a copy if calling in a loop.
  //
  // |params| is the AlgorithmIdentifier after the OBJECT IDENTIFIER type field,
  // and |key| is the contents of the subjectPublicKey with the leading padding
  // byte checked and removed. Although X.509 uses BIT STRINGs to represent
  // SubjectPublicKeyInfo, every key type defined encodes the key as a byte
  // string with the same conversion to BIT STRING.
  evp_decode_result_t (*pub_decode)(const EVP_PKEY_ALG *alg, EVP_PKEY *out,
                                    CBS *params, CBS *key);

  // pub_encode encodes |key| as a SubjectPublicKeyInfo and appends the result
  // to |out|. It returns one on success and zero on error.
  int (*pub_encode)(CBB *out, const EVP_PKEY *key);

  int (*pub_cmp)(const EVP_PKEY *a, const EVP_PKEY *b);

  // priv_decode decodes |params| and |key| as a PrivateKeyInfo and writes the
  // result into |out|.  It returns |evp_decode_ok| on success, and
  // |evp_decode_error| on error, and |evp_decode_unsupported| if the key type
  // was not supported by this |EVP_PKEY_ALG|. In case of
  // |evp_decode_unsupported|, it does not add an error to the error queue. May
  // modify |params| and |key|. Callers must make a copy if calling in a loop.
  //
  // |params| is the AlgorithmIdentifier after the OBJECT IDENTIFIER type field,
  // and |key| is the contents of the OCTET STRING privateKey field.
  evp_decode_result_t (*priv_decode)(const EVP_PKEY_ALG *alg, EVP_PKEY *out,
                                     CBS *params, CBS *key);

  // priv_encode encodes |key| as a PrivateKeyInfo and appends the result to
  // |out|. It returns one on success and zero on error.
  int (*priv_encode)(CBB *out, const EVP_PKEY *key);

  int (*set_priv_raw)(EVP_PKEY *pkey, const uint8_t *in, size_t len);
  int (*set_priv_seed)(EVP_PKEY *pkey, const uint8_t *in, size_t len);
  int (*set_pub_raw)(EVP_PKEY *pkey, const uint8_t *in, size_t len);
  int (*get_priv_raw)(const EVP_PKEY *pkey, uint8_t *out, size_t *out_len);
  int (*get_priv_seed)(const EVP_PKEY *pkey, uint8_t *out, size_t *out_len);
  int (*get_pub_raw)(const EVP_PKEY *pkey, uint8_t *out, size_t *out_len);

  // TODO(davidben): Can these be merged with the functions above? OpenSSL does
  // not implement |EVP_PKEY_get_raw_public_key|, etc., for |EVP_PKEY_EC|, but
  // the distinction seems unimportant. OpenSSL 3.0 has since renamed
  // |EVP_PKEY_get1_tls_encodedpoint| to |EVP_PKEY_get1_encoded_public_key|, and
  // what is the difference between "raw" and an "encoded" public key.
  //
  // One nuisance is the notion of "raw" is slightly ambiguous for EC keys. Is
  // it a DER ECPrivateKey or just the scalar?
  int (*set1_tls_encodedpoint)(EVP_PKEY *pkey, const uint8_t *in, size_t len);
  size_t (*get1_tls_encodedpoint)(const EVP_PKEY *pkey, uint8_t **out_ptr);

  // pkey_opaque returns 1 if the |pk| is opaque. Opaque keys are backed by
  // custom implementations which do not expose key material and parameters.
  int (*pkey_opaque)(const EVP_PKEY *pk);

  // OQS note: We've changed the return type from "int" to "size_t"
  // to allow for PQ algorithms with large signatures.
  size_t (*pkey_size)(const EVP_PKEY *pk);
  int (*pkey_bits)(const EVP_PKEY *pk);

  int (*param_missing)(const EVP_PKEY *pk);
  int (*param_copy)(EVP_PKEY *to, const EVP_PKEY *from);
  int (*param_cmp)(const EVP_PKEY *a, const EVP_PKEY *b);

  void (*pkey_free)(EVP_PKEY *pkey);
} /* EVP_PKEY_ASN1_METHOD */;

struct evp_pkey_st {
  CRYPTO_refcount_t references;

  // pkey contains a pointer to a structure dependent on |ameth|.
  void *pkey;

  // ameth contains a pointer to a method table that determines the key type, or
  // nullptr if the key is empty.
  const EVP_PKEY_ASN1_METHOD *ameth;
} /* EVP_PKEY */;

#define EVP_PKEY_OP_UNDEFINED 0
#define EVP_PKEY_OP_KEYGEN (1 << 2)
#define EVP_PKEY_OP_SIGN (1 << 3)
#define EVP_PKEY_OP_VERIFY (1 << 4)
#define EVP_PKEY_OP_VERIFYRECOVER (1 << 5)
#define EVP_PKEY_OP_ENCRYPT (1 << 6)
#define EVP_PKEY_OP_DECRYPT (1 << 7)
#define EVP_PKEY_OP_DERIVE (1 << 8)
#define EVP_PKEY_OP_PARAMGEN (1 << 9)

#define EVP_PKEY_OP_TYPE_SIG \
  (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYRECOVER)

#define EVP_PKEY_OP_TYPE_CRYPT (EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT)

#define EVP_PKEY_OP_TYPE_NOGEN \
  (EVP_PKEY_OP_SIG | EVP_PKEY_OP_CRYPT | EVP_PKEY_OP_DERIVE)

#define EVP_PKEY_OP_TYPE_GEN (EVP_PKEY_OP_KEYGEN | EVP_PKEY_OP_PARAMGEN)

// EVP_PKEY_CTX_ctrl performs |cmd| on |ctx|. The |keytype| and |optype|
// arguments can be -1 to specify that any type and operation are acceptable,
// otherwise |keytype| must match the type of |ctx| and the bits of |optype|
// must intersect the operation flags set on |ctx|.
//
// The |p1| and |p2| arguments depend on the value of |cmd|.
//
// It returns one on success and zero on error.
OPENSSL_EXPORT int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                                     int cmd, int p1, void *p2);

#define EVP_PKEY_CTRL_MD 1
#define EVP_PKEY_CTRL_GET_MD 2

// EVP_PKEY_CTRL_PEER_KEY is called with different values of |p1|:
//   0: Is called from |EVP_PKEY_derive_set_peer| and |p2| contains a peer key.
//      If the return value is <= 0, the key is rejected.
//   1: Is called at the end of |EVP_PKEY_derive_set_peer| and |p2| contains a
//      peer key. If the return value is <= 0, the key is rejected.
//   2: Is called with |p2| == NULL to test whether the peer's key was used.
//      (EC)DH always return one in this case.
//   3: Is called with |p2| == NULL to set whether the peer's key was used.
//      (EC)DH always return one in this case. This was only used for GOST.
#define EVP_PKEY_CTRL_PEER_KEY 3

// EVP_PKEY_ALG_CTRL is the base value from which key-type specific ctrl
// commands are numbered.
#define EVP_PKEY_ALG_CTRL 0x1000

#define EVP_PKEY_CTRL_RSA_PADDING (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_GET_RSA_PADDING (EVP_PKEY_ALG_CTRL + 2)
#define EVP_PKEY_CTRL_RSA_PSS_SALTLEN (EVP_PKEY_ALG_CTRL + 3)
#define EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN (EVP_PKEY_ALG_CTRL + 4)
#define EVP_PKEY_CTRL_RSA_KEYGEN_BITS (EVP_PKEY_ALG_CTRL + 5)
#define EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP (EVP_PKEY_ALG_CTRL + 6)
#define EVP_PKEY_CTRL_RSA_OAEP_MD (EVP_PKEY_ALG_CTRL + 7)
#define EVP_PKEY_CTRL_GET_RSA_OAEP_MD (EVP_PKEY_ALG_CTRL + 8)
#define EVP_PKEY_CTRL_RSA_MGF1_MD (EVP_PKEY_ALG_CTRL + 9)
#define EVP_PKEY_CTRL_GET_RSA_MGF1_MD (EVP_PKEY_ALG_CTRL + 10)
#define EVP_PKEY_CTRL_RSA_OAEP_LABEL (EVP_PKEY_ALG_CTRL + 11)
#define EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL (EVP_PKEY_ALG_CTRL + 12)
#define EVP_PKEY_CTRL_EC_PARAMGEN_GROUP (EVP_PKEY_ALG_CTRL + 13)
#define EVP_PKEY_CTRL_HKDF_MODE (EVP_PKEY_ALG_CTRL + 14)
#define EVP_PKEY_CTRL_HKDF_MD (EVP_PKEY_ALG_CTRL + 15)
#define EVP_PKEY_CTRL_HKDF_KEY (EVP_PKEY_ALG_CTRL + 16)
#define EVP_PKEY_CTRL_HKDF_SALT (EVP_PKEY_ALG_CTRL + 17)
#define EVP_PKEY_CTRL_HKDF_INFO (EVP_PKEY_ALG_CTRL + 18)
#define EVP_PKEY_CTRL_DH_PAD (EVP_PKEY_ALG_CTRL + 19)

struct evp_pkey_ctx_st {
  ~evp_pkey_ctx_st();

  // Method associated with this operation
  const EVP_PKEY_CTX_METHOD *pmeth = nullptr;
  // Key: may be nullptr
  bssl::UniquePtr<EVP_PKEY> pkey;
  // Peer key for key agreement, may be nullptr
  bssl::UniquePtr<EVP_PKEY> peerkey;
  // operation contains one of the |EVP_PKEY_OP_*| values.
  int operation = EVP_PKEY_OP_UNDEFINED;
  // Algorithm specific data.
  // TODO(davidben): Since a |EVP_PKEY_CTX| never has its type change after
  // creation, this should instead be a base class, with the algorithm-specific
  // data on the subclass, coming from the same allocation.
  void *data = nullptr;
} /* EVP_PKEY_CTX */;

struct evp_pkey_ctx_method_st {
  int pkey_id;

  int (*init)(EVP_PKEY_CTX *ctx);
  int (*copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
  void (*cleanup)(EVP_PKEY_CTX *ctx);

  int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

  int (*sign)(EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
              const uint8_t *tbs, size_t tbslen);

  int (*sign_message)(EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
                      const uint8_t *tbs, size_t tbslen);

  int (*verify)(EVP_PKEY_CTX *ctx, const uint8_t *sig, size_t siglen,
                const uint8_t *tbs, size_t tbslen);

  int (*verify_message)(EVP_PKEY_CTX *ctx, const uint8_t *sig, size_t siglen,
                        const uint8_t *tbs, size_t tbslen);

  int (*verify_recover)(EVP_PKEY_CTX *ctx, uint8_t *out, size_t *out_len,
                        const uint8_t *sig, size_t sig_len);

  int (*encrypt)(EVP_PKEY_CTX *ctx, uint8_t *out, size_t *outlen,
                 const uint8_t *in, size_t inlen);

  int (*decrypt)(EVP_PKEY_CTX *ctx, uint8_t *out, size_t *outlen,
                 const uint8_t *in, size_t inlen);

  int (*derive)(EVP_PKEY_CTX *ctx, uint8_t *key, size_t *keylen);

  int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

  int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
} /* EVP_PKEY_CTX_METHOD */;

typedef struct {
    OQS_SIG *ctx;
    uint8_t *pub;
    uint8_t *priv;
    char has_private;
    int nid;
    EVP_PKEY *classical_pkey;
} OQS_KEY;

typedef enum {
    KEY_TYPE_PUBLIC,
    KEY_TYPE_PRIVATE,
} oqs_key_type_t;

#define SIZE_OF_UINT32 4

#define ENCODE_UINT32(pbuf, i)  (pbuf)[0] = (unsigned char)((i>>24) & 0xff); \
                                (pbuf)[1] = (unsigned char)((i>>16) & 0xff); \
                                (pbuf)[2] = (unsigned char)((i>> 8) & 0xff); \
                                (pbuf)[3] = (unsigned char)((i    ) & 0xff)

#define DECODE_UINT32(i, pbuf)  i  = ((uint32_t) (pbuf)[0]) << 24; \
                                i |= ((uint32_t) (pbuf)[1]) << 16; \
                                i |= ((uint32_t) (pbuf)[2]) <<  8; \
                                i |= ((uint32_t) (pbuf)[3])

void oqs_pkey_ctx_free(OQS_KEY* key);
int get_classical_nid(int hybrid_id);
int is_oqs_hybrid_alg(int hybrid_nid);
int is_EC_nid(int nid);
int get_classical_sig_len(int classical_id);

///// OQS_TEMPLATE_FRAGMENT_DECLARE_ASN1_METHS_START
extern const EVP_PKEY_ASN1_METHOD CROSSrsdp128balanced_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD OV_Ip_pkc_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD OV_Ip_pkc_skc_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD falcon1024_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD falcon512_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD rsa3072_falcon512_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD falconpadded1024_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD falconpadded512_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD mayo1_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD mayo2_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD mayo3_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD mayo5_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD mldsa44_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD p256_mldsa44_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD mldsa65_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD p384_mldsa65_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD mldsa87_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD p521_mldsa87_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD snova2454_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD snova2454esk_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD snova37172_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD snova2455_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD snova2965_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincssha2128fsimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincssha2128ssimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincssha2192fsimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincssha2192ssimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincssha2256fsimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincssha2256ssimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincsshake128fsimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincsshake128ssimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincsshake192fsimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincsshake192ssimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincsshake256fsimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sphincsshake256ssimple_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_sha2_128s_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_sha2_128f_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_sha2_192s_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_sha2_192f_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_sha2_256s_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_sha2_256f_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_shake_128s_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_shake_128f_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_shake_192s_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_shake_192f_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_shake_256s_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD slhdsa_shake_256f_asn1_meth;
///// OQS_TEMPLATE_FRAGMENT_DECLARE_ASN1_METHS_END

extern const EVP_PKEY_CTX_METHOD rsa_pkey_meth;
extern const EVP_PKEY_CTX_METHOD rsa_pss_pkey_meth;
extern const EVP_PKEY_CTX_METHOD ec_pkey_meth;
extern const EVP_PKEY_CTX_METHOD ed25519_pkey_meth;
extern const EVP_PKEY_CTX_METHOD x25519_pkey_meth;
extern const EVP_PKEY_CTX_METHOD hkdf_pkey_meth;
extern const EVP_PKEY_CTX_METHOD dh_pkey_meth;
///// OQS_TEMPLATE_FRAGMENT_DECLARE_PKEY_METHS_START
extern const EVP_PKEY_CTX_METHOD CROSSrsdp128balanced_pkey_meth;
extern const EVP_PKEY_CTX_METHOD OV_Ip_pkc_pkey_meth;
extern const EVP_PKEY_CTX_METHOD OV_Ip_pkc_skc_pkey_meth;
extern const EVP_PKEY_CTX_METHOD falcon1024_pkey_meth;
extern const EVP_PKEY_CTX_METHOD falcon512_pkey_meth;
extern const EVP_PKEY_CTX_METHOD rsa3072_falcon512_pkey_meth;
extern const EVP_PKEY_CTX_METHOD falconpadded1024_pkey_meth;
extern const EVP_PKEY_CTX_METHOD falconpadded512_pkey_meth;
extern const EVP_PKEY_CTX_METHOD mayo1_pkey_meth;
extern const EVP_PKEY_CTX_METHOD mayo2_pkey_meth;
extern const EVP_PKEY_CTX_METHOD mayo3_pkey_meth;
extern const EVP_PKEY_CTX_METHOD mayo5_pkey_meth;
extern const EVP_PKEY_CTX_METHOD mldsa44_pkey_meth;
extern const EVP_PKEY_CTX_METHOD p256_mldsa44_pkey_meth;
extern const EVP_PKEY_CTX_METHOD mldsa65_pkey_meth;
extern const EVP_PKEY_CTX_METHOD p384_mldsa65_pkey_meth;
extern const EVP_PKEY_CTX_METHOD mldsa87_pkey_meth;
extern const EVP_PKEY_CTX_METHOD p521_mldsa87_pkey_meth;
extern const EVP_PKEY_CTX_METHOD snova2454_pkey_meth;
extern const EVP_PKEY_CTX_METHOD snova2454esk_pkey_meth;
extern const EVP_PKEY_CTX_METHOD snova37172_pkey_meth;
extern const EVP_PKEY_CTX_METHOD snova2455_pkey_meth;
extern const EVP_PKEY_CTX_METHOD snova2965_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincssha2128fsimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincssha2128ssimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincssha2192fsimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincssha2192ssimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincssha2256fsimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincssha2256ssimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincsshake128fsimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincsshake128ssimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincsshake192fsimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincsshake192ssimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincsshake256fsimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD sphincsshake256ssimple_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_sha2_128s_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_sha2_128f_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_sha2_192s_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_sha2_192f_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_sha2_256s_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_sha2_256f_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_shake_128s_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_shake_128f_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_shake_192s_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_shake_192f_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_shake_256s_pkey_meth;
extern const EVP_PKEY_CTX_METHOD slhdsa_shake_256f_pkey_meth;
///// OQS_TEMPLATE_FRAGMENT_DECLARE_PKEY_METHS_END

// evp_pkey_set0 sets |pkey|'s method to |method| and data to |pkey_data|,
// freeing any key that may previously have been configured. This function takes
// ownership of |pkey_data|, which must be of the type expected by |method|.
void evp_pkey_set0(EVP_PKEY *pkey, const EVP_PKEY_ASN1_METHOD *method,
                   void *pkey_data);


#if defined(__cplusplus)
}  // extern C
#endif

BSSL_NAMESPACE_BEGIN
inline auto GetDefaultEVPAlgorithms() {
  // A set of algorithms to use by default in |EVP_parse_public_key| and
  // |EVP_parse_private_key|.
  return std::array{
///// OQS_TEMPLATE_FRAGMENT_LIST_PKEY_ASN1_METHS_START
      EVP_pkey_CROSSrsdp128balanced(),
      EVP_pkey_OV_Ip_pkc(),
      EVP_pkey_OV_Ip_pkc_skc(),
      EVP_pkey_falcon1024(),
      EVP_pkey_falcon512(),
      EVP_pkey_rsa3072_falcon512(),
      EVP_pkey_falconpadded1024(),
      EVP_pkey_falconpadded512(),
      EVP_pkey_mayo1(),
      EVP_pkey_mayo2(),
      EVP_pkey_mayo3(),
      EVP_pkey_mayo5(),
      EVP_pkey_mldsa44(),
      EVP_pkey_p256_mldsa44(),
      EVP_pkey_mldsa65(),
      EVP_pkey_p384_mldsa65(),
      EVP_pkey_mldsa87(),
      EVP_pkey_p521_mldsa87(),
      EVP_pkey_snova2454(),
      EVP_pkey_snova2454esk(),
      EVP_pkey_snova37172(),
      EVP_pkey_snova2455(),
      EVP_pkey_snova2965(),
      EVP_pkey_sphincssha2128fsimple(),
      EVP_pkey_sphincssha2128ssimple(),
      EVP_pkey_sphincssha2192fsimple(),
      EVP_pkey_sphincssha2192ssimple(),
      EVP_pkey_sphincssha2256fsimple(),
      EVP_pkey_sphincssha2256ssimple(),
      EVP_pkey_sphincsshake128fsimple(),
      EVP_pkey_sphincsshake128ssimple(),
      EVP_pkey_sphincsshake192fsimple(),
      EVP_pkey_sphincsshake192ssimple(),
      EVP_pkey_sphincsshake256fsimple(),
      EVP_pkey_sphincsshake256ssimple(),
      EVP_pkey_slhdsa_sha2_128s(),
      EVP_pkey_slhdsa_sha2_128f(),
      EVP_pkey_slhdsa_sha2_192s(),
      EVP_pkey_slhdsa_sha2_192f(),
      EVP_pkey_slhdsa_sha2_256s(),
      EVP_pkey_slhdsa_sha2_256f(),
      EVP_pkey_slhdsa_shake_128s(),
      EVP_pkey_slhdsa_shake_128f(),
      EVP_pkey_slhdsa_shake_192s(),
      EVP_pkey_slhdsa_shake_192f(),
      EVP_pkey_slhdsa_shake_256s(),
      EVP_pkey_slhdsa_shake_256f(),
///// OQS_TEMPLATE_FRAGMENT_LIST_PKEY_ASN1_METHS_END
      EVP_pkey_ec_p224(),
      EVP_pkey_ec_p256(),
      EVP_pkey_ec_p384(),
      EVP_pkey_ec_p521(),
      EVP_pkey_ed25519(),
      EVP_pkey_rsa(),
      EVP_pkey_x25519(),
      // TODO(crbug.com/438761503): Remove DSA from this set, after callers that
      // need DSA pass in |EVP_pkey_dsa| explicitly.
      EVP_pkey_dsa(),
  };
}
BSSL_NAMESPACE_END

#endif  // OPENSSL_HEADER_CRYPTO_EVP_INTERNAL_H
