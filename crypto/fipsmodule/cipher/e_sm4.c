#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/sm4.h>

#include "../../internal.h"
#include "../delocate.h"
#include "../modes/internal.h"
#include "../service_indicator/internal.h"
#include "internal.h"


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



typedef struct {
  GCM128_CONTEXT gcm;
  union {
    double align;
    SM4_KEY ks;
  } ks;              /* SM4 key schedule to use */
  int key_set;       /* Set if key initialized */
  int iv_set;        /* Set if an iv is set */
  unsigned char *iv; /* Temporary IV store */
  int ivlen;         /* IV length */
  int taglen;
  int iv_gen; /* It is OK to generate IVs */
  ctr128_f ctr;
} EVP_SM4_GCM_CTX;


#define SM4_GCM_NONCE_LENGTH 12

#if defined(OPENSSL_32_BIT)
#define EVP_SM4_GCM_CTX_PADDING (4+8)
#else
#define EVP_SM4_GCM_CTX_PADDING 8
#endif

static EVP_SM4_GCM_CTX *SM4_gcm_from_cipher_ctx(EVP_CIPHER_CTX *ctx) {
  static_assert(
      alignof(EVP_SM4_GCM_CTX) <= 16,
      "EVP_SM4_GCM_CTX needs more alignment than this function provides");

  // |malloc| guarantees up to 4-byte alignment on 32-bit and 8-byte alignment
  // on 64-bit systems, so we need to adjust to reach 16-byte alignment.
  assert(ctx->cipher->ctx_size ==
         sizeof(EVP_SM4_GCM_CTX) + EVP_SM4_GCM_CTX_PADDING);

  char *ptr = ctx->cipher_data;
#if defined(OPENSSL_32_BIT)
  assert((uintptr_t)ptr % 4 == 0);
  ptr += (uintptr_t)ptr & 4;
#endif
  assert((uintptr_t)ptr % 8 == 0);
  ptr += (uintptr_t)ptr & 8;
  return (EVP_SM4_GCM_CTX *)ptr;
}


static int sm4_gcm_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                            const uint8_t *iv, int enc) {
  EVP_SM4_GCM_CTX *gctx = SM4_gcm_from_cipher_ctx(ctx);
  if (iv == NULL && key == NULL)
    return 1;
  if (key) {
    OPENSSL_memset(&gctx->gcm, 0, sizeof(gctx->gcm));
    SM4_set_key(key, &gctx->ks.ks);
    CRYPTO_gcm128_init_key(&gctx->gcm.gcm_key, &gctx->ks, (block128_f)SM4_encrypt, 0);
    gctx->ctr = NULL;

    // If we have an iv can set it directly, otherwise use saved IV.
    if (iv == NULL && gctx->iv_set) {
      iv = gctx->iv;
    }
    if (iv) {
      CRYPTO_gcm128_setiv(&gctx->gcm, &gctx->ks.ks, iv, gctx->ivlen);
      gctx->iv_set = 1;
    }
    gctx->key_set = 1;
  } else {
    // If key set use IV, otherwise copy
    if (gctx->key_set) {
      CRYPTO_gcm128_setiv(&gctx->gcm, &gctx->ks.ks, iv, gctx->ivlen);
    } else {
      OPENSSL_memcpy(gctx->iv, iv, gctx->ivlen);
    }
    gctx->iv_set = 1;
    gctx->iv_gen = 0;
  }
  return 1;
}

static void sm4_gcm_cleanup(EVP_CIPHER_CTX *c) {
  EVP_SM4_GCM_CTX *gctx = SM4_gcm_from_cipher_ctx(c);
  OPENSSL_cleanse(&gctx->gcm, sizeof(gctx->gcm));
  if (gctx->iv != c->iv) {
    OPENSSL_free(gctx->iv);
  }
}

/* increment counter (64-bit int) by 1 */
static void sm4_ctr64_inc(unsigned char *counter) {
  int n = 8;
  unsigned char c;

  do {
    --n;
    c = counter[n];
    ++c;
    counter[n] = c;
    if (c)
      return;
  } while (n);
}

static int sm4_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr) {
  EVP_SM4_GCM_CTX *gctx = SM4_gcm_from_cipher_ctx(c);

  switch (type) {
    case EVP_CTRL_INIT:
      gctx->key_set = 0;
      gctx->iv_set = 0;
      gctx->ivlen = EVP_CIPHER_iv_length(c->cipher);
      gctx->iv = c->iv;
      gctx->taglen = -1;
      gctx->iv_gen = 0;
      return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
      if (arg <= 0) {
        return 0;
      }

      // Allocate memory for IV if needed
      if (arg > EVP_MAX_IV_LENGTH && arg > gctx->ivlen) {
        if (gctx->iv != c->iv) {
          OPENSSL_free(gctx->iv);
        }
        gctx->iv = OPENSSL_malloc(arg);
        if (!gctx->iv) {
          return 0;
        }
      }
      gctx->ivlen = arg;
      return 1;

    case EVP_CTRL_GET_IVLEN:
      *(int *)ptr = gctx->ivlen;
      return 1;

    case EVP_CTRL_AEAD_GET_TAG:
      if (arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0) {
        return 0;
      }
      OPENSSL_memcpy(ptr, c->buf, arg);
      return 1;

    case EVP_CTRL_AEAD_SET_TAG:
      if (arg <= 0 || arg > 16 || c->encrypt) {
        return 0;
      }
      OPENSSL_memcpy(c->buf, ptr, arg);
      gctx->taglen = arg;
      return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
      // Special case: -1 length restores whole IV
      if (arg == -1) {
        OPENSSL_memcpy(gctx->iv, ptr, gctx->ivlen);
        gctx->iv_gen = 1;
        return 1;
      }
      // Fixed field must be at least 4 bytes and invocation field
      // at least 8.
      if (arg < 4 || (gctx->ivlen - arg) < 8) {
        return 0;
      }
      if (arg) {
        OPENSSL_memcpy(gctx->iv, ptr, arg);
      }
      if (c->encrypt) {
        // |RAND_bytes| calls within the fipsmodule should be wrapped with state
        // lock functions to avoid updating the service indicator with the DRBG
        // functions.
        FIPS_service_indicator_lock_state();
        RAND_bytes(gctx->iv + arg, gctx->ivlen - arg);
        FIPS_service_indicator_unlock_state();
      }
      gctx->iv_gen = 1;
      return 1;

    case EVP_CTRL_GCM_IV_GEN:
      if (gctx->iv_gen == 0 || gctx->key_set == 0) {
        return 0;
      }
      CRYPTO_gcm128_setiv(&gctx->gcm, &gctx->ks.ks, gctx->iv, gctx->ivlen);
      if (arg <= 0 || arg > gctx->ivlen) {
        arg = gctx->ivlen;
      }
      OPENSSL_memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
      // Invocation field will be at least 8 bytes in size and
      // so no need to check wrap around or increment more than
      // last 8 bytes.
      sm4_ctr64_inc(gctx->iv + gctx->ivlen - 8);
      gctx->iv_set = 1;
      return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
      if (gctx->iv_gen == 0 || gctx->key_set == 0 || c->encrypt) {
        return 0;
      }
      OPENSSL_memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
      CRYPTO_gcm128_setiv(&gctx->gcm, &gctx->ks.ks, gctx->iv, gctx->ivlen);
      gctx->iv_set = 1;
      return 1;

    case EVP_CTRL_COPY: {
      EVP_CIPHER_CTX *out = ptr;
      EVP_SM4_GCM_CTX *gctx_out = SM4_gcm_from_cipher_ctx(out);
      // |EVP_CIPHER_CTX_copy| copies this generically, but we must redo it in
      // case |out->cipher_data| and |in->cipher_data| are differently aligned.
      OPENSSL_memcpy(gctx_out, gctx, sizeof(EVP_SM4_GCM_CTX));
      if (gctx->iv == c->iv) {
        gctx_out->iv = out->iv;
      } else {
        gctx_out->iv = OPENSSL_memdup(gctx->iv, gctx->ivlen);
        if (!gctx_out->iv) {
          return 0;
        }
      }
      return 1;
    }
    default:
      return -1;
  }
}

static int sm4_gcm_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                          size_t len) {
  EVP_SM4_GCM_CTX *gctx = SM4_gcm_from_cipher_ctx(ctx);

  // If not set up, return error
  if (!gctx->key_set) {
    return -1;
  }
  if (!gctx->iv_set) {
    return -1;
  }

  if (len > INT_MAX) {
    // This function signature can only express up to |INT_MAX| bytes encrypted.
    //
    // TODO(https://crbug.com/boringssl/494): Make the internal |EVP_CIPHER|
    // calling convention |size_t|-clean.
    return -1;
  }

  if (in) {
    if (out == NULL) {
      if (!CRYPTO_gcm128_aad(&gctx->gcm, in, len)) {
        return -1;
      }
    } else if (ctx->encrypt) {
      if (gctx->ctr) {
        if (!CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm, &gctx->ks.ks, in, out, len,
                                         gctx->ctr)) {
          return -1;
        }
      } else {
        if (!CRYPTO_gcm128_encrypt(&gctx->gcm, &gctx->ks.ks, in, out, len)) {
          return -1;
        }
      }
    } else {
      if (gctx->ctr) {
        if (!CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm, &gctx->ks.ks, in, out, len,
                                         gctx->ctr)) {
          return -1;
        }
      } else {
        if (!CRYPTO_gcm128_decrypt(&gctx->gcm, &gctx->ks.ks, in, out, len)) {
          return -1;
        }
      }
    }
    return (int)len;
  } else {
    if (!ctx->encrypt) {
      if (gctx->taglen < 0 ||
          !CRYPTO_gcm128_finish(&gctx->gcm, ctx->buf, gctx->taglen)) {
        return -1;
      }
      gctx->iv_set = 0;
      return 0;
    }
    CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, 16);
    gctx->taglen = 16;
    // Don't reuse the IV
    gctx->iv_set = 0;
    return 0;
  }
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_sm4_128_gcm) {
  memset(out, 0, sizeof(EVP_CIPHER));

  out->nid = NID_sm4_gcm;
  out->block_size = 1;
  out->key_len = 16;
  out->iv_len = SM4_GCM_NONCE_LENGTH;
  out->ctx_size = sizeof(EVP_SM4_GCM_CTX) + EVP_SM4_GCM_CTX_PADDING;
  out->flags = EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_CUSTOM_COPY |
               EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT |
               EVP_CIPH_CTRL_INIT | EVP_CIPH_FLAG_AEAD_CIPHER;
  out->init = sm4_gcm_init_key;
  out->cipher = sm4_gcm_cipher;
  out->cleanup = sm4_gcm_cleanup;
  out->ctrl = sm4_gcm_ctrl;
}