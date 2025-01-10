/* Copyright 2015 The BoringSSL Authors
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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "internal.h"

static const struct argument kArguments[] = {
    {
     "-algorithm", kRequiredArgument,
     "The public key algorithm",
    },
    {
     "", kOptionalArgument, "",
    },
};

bool GeneratePKey(const std::vector<std::string> &args) {
  std::map<std::string, std::string> args_map;

  if (!ParseKeyValueArguments(&args_map, args, kArguments)) {
    PrintUsage(kArguments);
    return false;
  }

  std::string algorithm_sn = args_map["-algorithm"];;
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(OBJ_sn2nid(algorithm_sn.c_str()), /*e=*/nullptr));
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
  bssl::UniquePtr<BIO> bio(BIO_new_fp(stdout, BIO_NOCLOSE));
  EVP_PKEY *pkey_ptr = pkey.get();

  if (!EVP_PKEY_keygen_init(ctx.get()) ||
      !EVP_PKEY_keygen(ctx.get(), &pkey_ptr) ||
      !PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey.get(), NULL /* cipher */,
                                   NULL /* password */, 0 /* password len */,
                                   NULL /* password callback */,
                                   NULL /* callback arg */)) {
    ERR_print_errors_fp(stderr);
        return false;
  }

  return true;
}
