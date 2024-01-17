#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/sm4.h>

#include "internal.h"
#include "../../internal.h"
#include "../modes/internal.h"
#include "../service_indicator/internal.h"
#include "../delocate.h"

typedef struct {
  union {
    double align;
    SM4_KEY ks;
  } ks;
  block128_f block;
  union {
    ecb128_f ecb;
    cbc128_f cbc;
    ctr128_f ctr;
  } stream;
} EVP_SM4_KEY;

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc) {
  EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;
  dat->block = NULL;
  dat->stream.cbc = NULL;

  const int mode = ctx->cipher->flags & EVP_CIPH_MODE_MASK;
  if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
    dat->block = (block128_f)SM4_decrypt;
    SM4_set_key(key, ctx->cipher_data);
  } else {
    dat->block = (block128_f)SM4_encrypt;
    SM4_set_key(key, ctx->cipher_data);
  }
  return 1;
}

static int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len) {
  EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;
  if (dat->stream.cbc)
    (*dat->stream.cbc)(in, out, len, &dat->ks.ks, ctx->iv, ctx->encrypt);
  else if (ctx->encrypt)
    CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
  else
    CRYPTO_cbc128_decrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
  return 1;
}

static int sm4_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len) {
  EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;
  unsigned num = ctx->num;
  CRYPTO_cfb128_encrypt(in, out, len, &dat->ks, ctx->iv, &num, ctx->encrypt,
                        dat->block);
  ctx->num = num;
  return 1;
}

static int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len) {
  EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;
  const size_t block_size = ctx->cipher->block_size;
  if (len < block_size)
    return 1;

  if (dat->stream.ecb != NULL)
    (*dat->stream.ecb)(in, out, len, &dat->ks.ks, ctx->encrypt);
  else {
    len -= block_size;
    for (size_t i = 0; i <= len; i += block_size)
      (*dat->block)(in + i, out + i, &dat->ks);
  }
  return 1;
}

static int sm4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len) {
  EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;
  unsigned num = ctx->num;

  CRYPTO_ofb128_encrypt(in, out, len, &dat->ks, ctx->iv, &num, dat->block);
  ctx->num = num;
  return 1;
}

static int sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len) {
  EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;
  unsigned num;

  if (ctx->num < 0)
    return 0;

  num = ctx->num;

  if (dat->stream.ctr)
    CRYPTO_ctr128_encrypt_ctr32(in, out, len, &dat->ks, ctx->iv, ctx->buf, &num,
                                dat->stream.ctr);
  else
    CRYPTO_ctr128_encrypt(in, out, len, &dat->ks, ctx->iv, ctx->buf, &num,
                          dat->block);
  ctx->num = num;
  return 1;
}

#define BLOCK_CIPHER_generic(nnid, nblocksize, ivlen, nmode, mode, MODE, \
                             nflags)                                     \
  DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_sm4_##nmode) {                  \
    memset(out, 0, sizeof(EVP_CIPHER));                                  \
                                                                         \
    out->nid = nnid##_##nmode;                                           \
    out->block_size = nblocksize;                                        \
    out->key_len = 128 / 8;                                              \
    out->iv_len = ivlen;                                                 \
    out->flags = nflags | EVP_CIPH_##MODE##_MODE;                        \
    out->ctx_size = sizeof(EVP_SM4_KEY);                                 \
    out->init = sm4_init_key;                                            \
    out->cipher = sm4_##mode##_cipher;                                   \
  }

#define EVP_CIPH_FLAG_DEFAULT_ASN1 0

#define DEFINE_BLOCK_CIPHERS(nnid, flags)                                           \
  BLOCK_CIPHER_generic(nnid,16,16,cbc,cbc,CBC, EVP_CIPH_FLAG_DEFAULT_ASN1)          \
  BLOCK_CIPHER_generic(nnid,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)      \
  BLOCK_CIPHER_generic(nnid,1,16,ofb128,ofb,OFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
  BLOCK_CIPHER_generic(nnid,1,16,cfb128,cfb,CFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
  BLOCK_CIPHER_generic(nnid,1,16,ctr,ctr,CTR,flags)

DEFINE_BLOCK_CIPHERS(NID_sm4, 0)

// This is the only function that is not defined in the original source code.
const EVP_CIPHER *EVP_sm4_cfb(void){
  return EVP_sm4_cfb128();
}

const EVP_CIPHER *EVP_sm4_ofb(void){
  return EVP_sm4_ofb128();
}