/* Copyright 2024 The BoringSSL Authors
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

#include <openssl/mlkem.h>

#include "../fipsmodule/bcm_interface.h"


static_assert(sizeof(BCM_mlkem768_private_key) <= sizeof(MLKEM768_private_key),
              "");
static_assert(alignof(BCM_mlkem768_private_key) <=
                  alignof(MLKEM768_private_key),
              "");
static_assert(sizeof(BCM_mlkem768_public_key) <= sizeof(MLKEM768_public_key),
              "");
static_assert(alignof(BCM_mlkem768_public_key) <= alignof(MLKEM768_public_key),
              "");
static_assert(MLKEM768_PUBLIC_KEY_BYTES == BCM_MLKEM768_PUBLIC_KEY_BYTES, "");
static_assert(MLKEM_SEED_BYTES == BCM_MLKEM_SEED_BYTES, "");
static_assert(MLKEM768_CIPHERTEXT_BYTES == BCM_MLKEM768_CIPHERTEXT_BYTES, "");
static_assert(MLKEM_SHARED_SECRET_BYTES == BCM_MLKEM_SHARED_SECRET_BYTES, "");
static_assert(MLKEM1024_PUBLIC_KEY_BYTES == BCM_MLKEM1024_PUBLIC_KEY_BYTES, "");
static_assert(MLKEM1024_CIPHERTEXT_BYTES == BCM_MLKEM1024_CIPHERTEXT_BYTES, "");

void MLKEM768_generate_key(
    uint8_t out_encoded_public_key[MLKEM768_PUBLIC_KEY_BYTES],
    uint8_t optional_out_seed[MLKEM_SEED_BYTES],
    struct MLKEM768_private_key *out_private_key) {
  BCM_mlkem768_generate_key(
      out_encoded_public_key, optional_out_seed,
      reinterpret_cast<BCM_mlkem768_private_key *>(out_private_key));
}

int MLKEM768_private_key_from_seed(struct MLKEM768_private_key *out_private_key,
                                   const uint8_t *seed, size_t seed_len) {
  return bcm_success(BCM_mlkem768_private_key_from_seed(
      reinterpret_cast<BCM_mlkem768_private_key *>(out_private_key), seed,
      seed_len));
}

void MLKEM768_public_from_private(
    struct MLKEM768_public_key *out_public_key,
    const struct MLKEM768_private_key *private_key) {
  (void)BCM_mlkem768_public_from_private(
      reinterpret_cast<BCM_mlkem768_public_key *>(out_public_key),
      reinterpret_cast<const BCM_mlkem768_private_key *>(private_key));
}

void MLKEM768_encap(uint8_t out_ciphertext[MLKEM768_CIPHERTEXT_BYTES],
                    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
                    const struct MLKEM768_public_key *public_key) {
  (void)BCM_mlkem768_encap(
      out_ciphertext, out_shared_secret,
      reinterpret_cast<const BCM_mlkem768_public_key *>(public_key));
}

int MLKEM768_decap(uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const struct MLKEM768_private_key *private_key) {
  return bcm_success(BCM_mlkem768_decap(
      out_shared_secret, ciphertext, ciphertext_len,
      reinterpret_cast<const BCM_mlkem768_private_key *>(private_key)));
}

int MLKEM768_marshal_public_key(CBB *out,
                                const struct MLKEM768_public_key *public_key) {
  return bcm_success(BCM_mlkem768_marshal_public_key(
      out, reinterpret_cast<const BCM_mlkem768_public_key *>(public_key)));
}

int MLKEM768_parse_public_key(struct MLKEM768_public_key *out_public_key,
                              CBS *in) {
  return bcm_success(BCM_mlkem768_parse_public_key(
      reinterpret_cast<BCM_mlkem768_public_key *>(out_public_key), in));
}


static_assert(sizeof(BCM_mlkem1024_private_key) <=
                  sizeof(MLKEM1024_private_key),
              "");
static_assert(alignof(BCM_mlkem1024_private_key) <=
                  alignof(MLKEM1024_private_key),
              "");
static_assert(sizeof(BCM_mlkem1024_public_key) <= sizeof(MLKEM1024_public_key),
              "");
static_assert(alignof(BCM_mlkem1024_public_key) <=
                  alignof(MLKEM1024_public_key),
              "");

void MLKEM1024_generate_key(
    uint8_t out_encoded_public_key[MLKEM1024_PUBLIC_KEY_BYTES],
    uint8_t optional_out_seed[MLKEM_SEED_BYTES],
    struct MLKEM1024_private_key *out_private_key) {
  (void)BCM_mlkem1024_generate_key(
      out_encoded_public_key, optional_out_seed,
      reinterpret_cast<BCM_mlkem1024_private_key *>(out_private_key));
}

int MLKEM1024_private_key_from_seed(
    struct MLKEM1024_private_key *out_private_key, const uint8_t *seed,
    size_t seed_len) {
  return bcm_success(BCM_mlkem1024_private_key_from_seed(
      reinterpret_cast<BCM_mlkem1024_private_key *>(out_private_key), seed,
      seed_len));
}

void MLKEM1024_public_from_private(
    struct MLKEM1024_public_key *out_public_key,
    const struct MLKEM1024_private_key *private_key) {
  (void)BCM_mlkem1024_public_from_private(
      reinterpret_cast<BCM_mlkem1024_public_key *>(out_public_key),
      reinterpret_cast<const BCM_mlkem1024_private_key *>(private_key));
}

void MLKEM1024_encap(uint8_t out_ciphertext[MLKEM1024_CIPHERTEXT_BYTES],
                     uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
                     const struct MLKEM1024_public_key *public_key) {
  (void)BCM_mlkem1024_encap(
      out_ciphertext, out_shared_secret,
      reinterpret_cast<const BCM_mlkem1024_public_key *>(public_key));
}

int MLKEM1024_decap(uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const struct MLKEM1024_private_key *private_key) {
  return bcm_success(BCM_mlkem1024_decap(
      out_shared_secret, ciphertext, ciphertext_len,
      reinterpret_cast<const BCM_mlkem1024_private_key *>(private_key)));
}

int MLKEM1024_marshal_public_key(
    CBB *out, const struct MLKEM1024_public_key *public_key) {
  return bcm_success(BCM_mlkem1024_marshal_public_key(
      out, reinterpret_cast<const BCM_mlkem1024_public_key *>(public_key)));
}

int MLKEM1024_parse_public_key(struct MLKEM1024_public_key *out_public_key,
                               CBS *in) {
  return bcm_success(BCM_mlkem1024_parse_public_key(
      reinterpret_cast<BCM_mlkem1024_public_key *>(out_public_key), in));
}