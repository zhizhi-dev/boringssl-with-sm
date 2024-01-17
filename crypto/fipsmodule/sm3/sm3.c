/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/base.h>
#include <openssl/e_os2.h>
#include <openssl/mem.h>
#include <openssl/sm3.h>

#include "../../internal.h"
#include "../digest/md32_common.h"
#include "internal.h"

uint8_t *SM3(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_LENGTH]) {
  SM3_CTX ctx;
  SM3_Init(&ctx);
  SM3_Update(&ctx, data, len);
  SM3_Final(out, &ctx);

  return out;
}

int SM3_Init(SM3_CTX *ctx) {
  OPENSSL_memset(ctx, 0, sizeof(SM3_CTX));
  ctx->h[0] = 0x7380166fUL;
  ctx->h[1] = 0x4914b2b9UL;
  ctx->h[2] = 0x172442d7UL;
  ctx->h[3] = 0xda8a0600UL;
  ctx->h[4] = 0xa96f30bcUL;
  ctx->h[5] = 0x163138aaUL;
  ctx->h[6] = 0xe38dee4dUL;
  ctx->h[7] = 0xb0fb0e4eUL;
  return 1;
}

#if defined(SM3_ASM)
#define sm3_block_data_order sm3_block_asm_data_order
#else
static void sm3_block_data_order(uint32_t *state, const uint8_t *data,
                                 size_t num);
#endif

void SM3_Transform(SM3_CTX *c, const uint8_t data[SM3_BLOCK_SIZE]) {
  sm3_block_data_order(c->h, data, 1);
}

int SM3_Update(SM3_CTX *c, const void *data, size_t len) {
  crypto_md32_update(&sm3_block_data_order, c->h, c->data, SM3_BLOCK_SIZE,
                     &c->num, &c->Nh, &c->Nl, data, len);
  return 1;
}

int SM3_Final(uint8_t *out, SM3_CTX *c) {
  crypto_md32_final(&sm3_block_data_order, c->h, c->data, SM3_BLOCK_SIZE,
                    &c->num, c->Nh, c->Nl, 1);
  CRYPTO_store_u32_be(out, c->h[0]);
  CRYPTO_store_u32_be(out + 4, c->h[1]);
  CRYPTO_store_u32_be(out + 8, c->h[2]);
  CRYPTO_store_u32_be(out + 12, c->h[3]);
  CRYPTO_store_u32_be(out + 16, c->h[4]);
  CRYPTO_store_u32_be(out + 20, c->h[5]);
  CRYPTO_store_u32_be(out + 24, c->h[6]);
  CRYPTO_store_u32_be(out + 28, c->h[7]);
  return 1;
}


#define GETU32(ptr) \
	((uint32_t)(ptr)[0] << 24 | \
	 (uint32_t)(ptr)[1] << 16 | \
	 (uint32_t)(ptr)[2] <<  8 | \
	 (uint32_t)(ptr)[3])

#define PUTU32(ptr,a) \
	((ptr)[0] = (uint8_t)((a) >> 24), \
	 (ptr)[1] = (uint8_t)((a) >> 16), \
	 (ptr)[2] = (uint8_t)((a) >>  8), \
	 (ptr)[3] = (uint8_t)(a))

#define ROTL(x,n)  (((x)<<(n)) | ((x)>>(32-(n))))

#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x),17))
#define P1(x) ((x) ^ ROTL((x),15) ^ ROTL((x),23))

#define FF00(x,y,z)  ((x) ^ (y) ^ (z))
#define FF16(x,y,z)  (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG00(x,y,z)  ((x) ^ (y) ^ (z))
#define GG16(x,y,z)  ((((y)^(z)) & (x)) ^ (z))

static uint32_t K[64] = {
	0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
	0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
	0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
	0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
	0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
	0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
	0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
	0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};

void sm3_block_data_order(uint32_t *state, const uint8_t *data, size_t blocks) {
  uint32_t A;
  uint32_t B;
  uint32_t C;
  uint32_t D;
  uint32_t E;
  uint32_t F;
  uint32_t G;
  uint32_t H;
  uint32_t W[68];
  uint32_t SS1, SS2, TT1, TT2;
  int j;

  while (blocks--) {
    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    F = state[5];
    G = state[6];
    H = state[7];

    for (j = 0; j < 16; j++) {
      W[j] = GETU32(data + j * 4);
    }

    for (; j < 68; j++) {
      W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^
             ROTL(W[j - 13], 7) ^ W[j - 6];
    }

    for (j = 0; j < 16; j++) {
      SS1 = ROTL((ROTL(A, 12) + E + K[j]), 7);
      SS2 = SS1 ^ ROTL(A, 12);
      TT1 = FF00(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
      TT2 = GG00(E, F, G) + H + SS1 + W[j];
      D = C;
      C = ROTL(B, 9);
      B = A;
      A = TT1;
      H = G;
      G = ROTL(F, 19);
      F = E;
      E = P0(TT2);
    }

    for (; j < 64; j++) {
      SS1 = ROTL((ROTL(A, 12) + E + K[j]), 7);
      SS2 = SS1 ^ ROTL(A, 12);
      TT1 = FF16(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
      TT2 = GG16(E, F, G) + H + SS1 + W[j];
      D = C;
      C = ROTL(B, 9);
      B = A;
      A = TT1;
      H = G;
      G = ROTL(F, 19);
      F = E;
      E = P0(TT2);
    }

    state[0] ^= A;
    state[1] ^= B;
    state[2] ^= C;
    state[3] ^= D;
    state[4] ^= E;
    state[5] ^= F;
    state[6] ^= G;
    state[7] ^= H;

    data += 64;
  }
}