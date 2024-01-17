/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * 
 * Copyright zhizhi-dev@gmail.com. All Rights Reserved.
 * 
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_SM3_H
#define OPENSSL_HEADER_SM3_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define SM3_DIGEST_LENGTH 32

#define SM3_BLOCK_SIZE 64

// TODO(lijinggang) -> base.h
typedef struct sm3_state_st {
  uint32_t h[8];
  uint32_t Nl, Nh;
  uint8_t data[SM3_BLOCK_SIZE];
  size_t num;
} SM3_CTX;

OPENSSL_EXPORT uint8_t *SM3(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_LENGTH]);

OPENSSL_EXPORT int SM3_Init(SM3_CTX *c);
OPENSSL_EXPORT int SM3_Update(SM3_CTX *c, const void *data, size_t len);
OPENSSL_EXPORT int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *c);

OPENSSL_EXPORT void SM3_Transform(SM3_CTX *md5,
                                  const uint8_t block[SM3_BLOCK_SIZE]);

#if defined(__cplusplus)
}
#endif

#endif // OPENSSL_HEADER_SM3_H