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

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */

#include <openssl/sm2.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h> /* ossl_ecdh_kdf_X9_63() */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include <assert.h>
#include <string.h>

#include "../../bytestring/internal.h"

typedef struct SM2_Ciphertext_st {
  BIGNUM *C1x;
  BIGNUM *C1y;
  ASN1_OCTET_STRING *C3;
  ASN1_OCTET_STRING *C2;
} SM2_Ciphertext;

DECLARE_ASN1_FUNCTIONS_const(SM2_Ciphertext)

static int parse_integer(CBS *cbs, BIGNUM **out) {
  assert(*out == NULL);
  *out = BN_new();
  if (*out == NULL) {
    return 0;
  }
  return BN_parse_asn1_unsigned(cbs, *out);
}

static int parse_octet_string(CBS *cbs, ASN1_OCTET_STRING **out) {
  assert(*out == NULL);
  *out = ASN1_OCTET_STRING_new();
  if (*out == NULL) {
    return 0;
  }
  CBS child;
  if (!CBS_get_asn1(cbs, &child, CBS_ASN1_OCTETSTRING) ||
      !ASN1_OCTET_STRING_set(*out, CBS_data(&child), CBS_len(&child))) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    return 0;
  }
  return 1;
}

SM2_Ciphertext *SM2_Ciphertext_new() {
  SM2_Ciphertext *ret = OPENSSL_zalloc(sizeof(SM2_Ciphertext));
  if (ret == NULL) {
    return NULL;
  }
  return ret;
}

void SM2_Ciphertext_free(SM2_Ciphertext *a) {
  if (a == NULL) {
    return;
  }
  BN_free(a->C1x);
  BN_free(a->C1y);
  ASN1_OCTET_STRING_free(a->C3);
  ASN1_OCTET_STRING_free(a->C2);
  OPENSSL_free(a);
}

SM2_Ciphertext *d2i_SM2_Ciphertext(SM2_Ciphertext **a, const uint8_t **in,
                                   long len) {
  CBS cbs;
  CBS_init(&cbs, *in, len);

  SM2_Ciphertext *ret = SM2_Ciphertext_new();
  if (ret == NULL) {
    return NULL;
  }

  CBS child;
  if (!CBS_get_asn1(&cbs, &child, CBS_ASN1_SEQUENCE) ||
      !parse_integer(&child, &ret->C1x) || !parse_integer(&child, &ret->C1y) ||
      !parse_octet_string(&child, &ret->C3) ||
      !parse_octet_string(&child, &ret->C2) || CBS_len(&child) != 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    SM2_Ciphertext_free(ret);
    return NULL;
  }

  return ret;
}

// i2d_SM2_Ciphertext
int i2d_SM2_Ciphertext(const SM2_Ciphertext *a, uint8_t **outp) {
  CBB cbb, child;
  CBB_zero(&cbb);
  
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_asn1(&cbb, &child, CBS_ASN1_SEQUENCE) ||
      !BN_marshal_asn1(&child, a->C1x) ||
      !BN_marshal_asn1(&child, a->C1y) ||
      !CBB_add_asn1(&child, &child, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&child, ASN1_STRING_get0_data(a->C3),
                     ASN1_STRING_length(a->C3)) ||
      !CBB_add_asn1(&child, &child, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&child, ASN1_STRING_get0_data(a->C2),
                     ASN1_STRING_length(a->C2))) {
    CBB_cleanup(&cbb);
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);    
    return -1;
  }
  return CBB_finish_i2d(&cbb, outp);
}

static size_t ec_field_size(const EC_GROUP *group) {
  /* Is there some simpler way to do this? */
  BIGNUM *p = BN_new();
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  size_t field_size = 0;

  if (p == NULL || a == NULL || b == NULL)
    goto done;

  if (!EC_GROUP_get_curve_GFp(group, p, a, b, NULL))
    goto done;
  field_size = (BN_num_bits(p) + 7) / 8;

done:
  BN_free(p);
  BN_free(a);
  BN_free(b);

  return field_size;
}

#define SSKDF_MAX_INLEN (1 << 30)
#define SSKDF_KMAC128_DEFAULT_SALT_SIZE (168 - 4)
#define SSKDF_KMAC256_DEFAULT_SALT_SIZE (136 - 4)

/*
 * Refer to https://csrc.nist.gov/publications/detail/sp/800-56c/rev-1/final
 * Section 4. One-Step Key Derivation using H(x) = hash(x)
 * Note: X9.63 also uses this code with the only difference being that the
 * counter is appended to the secret 'z'.
 * i.e.
 *   result[i] = Hash(counter || z || info) for One Step OR
 *   result[i] = Hash(z || counter || info) for X9.63.
 */
static int SSKDF_hash_kdm(const EVP_MD *kdf_md, const uint8_t *z, size_t z_len,
                          const uint8_t *info, size_t info_len,
                          unsigned int append_ctr, uint8_t *derived_key,
                          size_t derived_key_len) {
  int ret = 0, hlen;
  size_t counter, out_len, len = derived_key_len;
  uint8_t c[4];
  uint8_t mac[EVP_MAX_MD_SIZE];
  uint8_t *out = derived_key;
  EVP_MD_CTX *ctx = NULL, *ctx_init = NULL;

  if (z_len > SSKDF_MAX_INLEN || info_len > SSKDF_MAX_INLEN ||
      derived_key_len > SSKDF_MAX_INLEN || derived_key_len == 0)
    return 0;

  hlen = EVP_MD_size(kdf_md);
  if (hlen <= 0)
    return 0;
  out_len = (size_t)hlen;

  ctx = EVP_MD_CTX_create();
  ctx_init = EVP_MD_CTX_create();
  if (ctx == NULL || ctx_init == NULL)
    goto end;

  if (!EVP_DigestInit(ctx_init, kdf_md))
    goto end;

  for (counter = 1;; counter++) {
    c[0] = (uint8_t)((counter >> 24) & 0xff);
    c[1] = (uint8_t)((counter >> 16) & 0xff);
    c[2] = (uint8_t)((counter >> 8) & 0xff);
    c[3] = (uint8_t)(counter & 0xff);

    if (!(EVP_MD_CTX_copy_ex(ctx, ctx_init) &&
          (append_ctr || EVP_DigestUpdate(ctx, c, sizeof(c))) &&
          EVP_DigestUpdate(ctx, z, z_len) &&
          (!append_ctr || EVP_DigestUpdate(ctx, c, sizeof(c))) &&
          EVP_DigestUpdate(ctx, info, info_len)))
      goto end;
    if (len >= out_len) {
      if (!EVP_DigestFinal_ex(ctx, out, NULL))
        goto end;
      out += out_len;
      len -= out_len;
      if (len == 0)
        break;
    } else {
      if (!EVP_DigestFinal_ex(ctx, mac, NULL))
        goto end;
      memcpy(out, mac, len);
      break;
    }
  }
  ret = 1;
end:
  EVP_MD_CTX_destroy(ctx);
  EVP_MD_CTX_destroy(ctx_init);
  OPENSSL_cleanse(mac, sizeof(mac));
  return ret;
}

static int ossl_ecdh_kdf_X9_63(uint8_t *out, size_t outlen,
                               const uint8_t *secret, size_t secret_len,
                               const uint8_t *sinfo, size_t sinfolen,
                               const EVP_MD *md) {
  return SSKDF_hash_kdm(md, secret, secret_len, sinfo, sinfolen, 1, out,
                        outlen);
}

int SM2_plaintext_size(const uint8_t *ct, size_t ct_size, size_t *pt_size) {
  struct SM2_Ciphertext_st *sm2_ctext = NULL;

  sm2_ctext = d2i_SM2_Ciphertext(NULL, &ct, ct_size);

  if (sm2_ctext == NULL) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ENCODING);
    return 0;
  }

  *pt_size = sm2_ctext->C2->length;
  SM2_Ciphertext_free(sm2_ctext);

  return 1;
}

int SM2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size) {
  const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
  const int md_size = EVP_MD_size(digest);
  size_t sz;

  if (field_size == 0 || md_size < 0)
    return 0;

  /* Integer and string are simple type; set constructed = 0, means primitive
   * and definite length encoding. */
  sz = 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER) +
       ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING) +
       ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
  /* Sequence is structured type; set constructed = 1, means constructed and
   * definite length encoding. */
  *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

  return 1;
}

int SM2_encrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *msg,
                size_t msg_len, uint8_t *ciphertext_buf,
                size_t *ciphertext_len) {
  int rc = 0, ciphertext_leni;
  size_t i;
  BN_CTX *ctx = NULL;
  BIGNUM *k = NULL;
  BIGNUM *x1 = NULL;
  BIGNUM *y1 = NULL;
  BIGNUM *x2 = NULL;
  BIGNUM *y2 = NULL;
  EVP_MD_CTX *hash = EVP_MD_CTX_new();
  struct SM2_Ciphertext_st ctext_struct;
  const EC_GROUP *group = EC_KEY_get0_group(key);
  const BIGNUM *order = EC_GROUP_get0_order(group);
  const EC_POINT *P = EC_KEY_get0_public_key(key);
  EC_POINT *kG = NULL;
  EC_POINT *kP = NULL;
  uint8_t *msg_mask = NULL;
  uint8_t *x2y2 = NULL;
  uint8_t *C3 = NULL;
  size_t field_size;
  const int C3_size = EVP_MD_size(digest);
  EVP_MD *fetched_digest = NULL;

  /* NULL these before any "goto done" */
  ctext_struct.C2 = NULL;
  ctext_struct.C3 = NULL;

  if (hash == NULL || C3_size <= 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto done;
  }

  field_size = ec_field_size(group);
  if (field_size == 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto done;
  }

  kG = EC_POINT_new(group);
  kP = EC_POINT_new(group);
  if (kG == NULL || kP == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto done;
  }
  ctx = BN_CTX_new();
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
    goto done;
  }

  BN_CTX_start(ctx);
  k = BN_CTX_get(ctx);
  x1 = BN_CTX_get(ctx);
  x2 = BN_CTX_get(ctx);
  y1 = BN_CTX_get(ctx);
  y2 = BN_CTX_get(ctx);

  if (y2 == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
    goto done;
  }

  x2y2 = OPENSSL_zalloc(2 * field_size);
  C3 = OPENSSL_zalloc(C3_size);

  if (x2y2 == NULL || C3 == NULL)
    goto done;

  memset(ciphertext_buf, 0, *ciphertext_len);

  if (!BN_rand_range_ex(k, 0, order)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto done;
  }

  if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx) ||
      !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx) ||
      !EC_POINT_mul(group, kP, NULL, P, k, ctx) ||
      !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto done;
  }

  if (BN_bn2binpad(x2, x2y2, field_size) < 0 ||
      BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto done;
  }

  msg_mask = OPENSSL_zalloc(msg_len);
  if (msg_mask == NULL)
    goto done;

  /* X9.63 with no salt happens to match the KDF used in SM2 */
  if (!ossl_ecdh_kdf_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                           digest)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto done;
  }

  for (i = 0; i != msg_len; ++i)
    msg_mask[i] ^= msg[i];

  if (EVP_DigestInit(hash, digest) == 0 ||
      EVP_DigestUpdate(hash, x2y2, field_size) == 0 ||
      EVP_DigestUpdate(hash, msg, msg_len) == 0 ||
      EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0 ||
      EVP_DigestFinal(hash, C3, NULL) == 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto done;
  }

  ctext_struct.C1x = x1;
  ctext_struct.C1y = y1;
  ctext_struct.C3 = ASN1_OCTET_STRING_new();
  ctext_struct.C2 = ASN1_OCTET_STRING_new();

  if (ctext_struct.C3 == NULL || ctext_struct.C2 == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
    goto done;
  }
  if (!ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size) ||
      !ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto done;
  }

  ciphertext_leni = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);
  /* Ensure cast to size_t is safe */
  if (ciphertext_leni < 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto done;
  }
  *ciphertext_len = (size_t)ciphertext_leni;

  rc = 1;

done:
  BN_CTX_end(ctx);

  ASN1_OCTET_STRING_free(ctext_struct.C2);
  ASN1_OCTET_STRING_free(ctext_struct.C3);
  OPENSSL_free(msg_mask);
  OPENSSL_free(x2y2);
  OPENSSL_free(C3);
  EVP_MD_CTX_free(hash);
  BN_CTX_free(ctx);
  EC_POINT_free(kG);
  EC_POINT_free(kP);
  return rc;
}

int SM2_decrypt(const EC_KEY *key, const EVP_MD *digest,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *ptext_buf, size_t *ptext_len) {
  int rc = 0;
  int i;
  BN_CTX *ctx = NULL;
  const EC_GROUP *group = EC_KEY_get0_group(key);
  EC_POINT *C1 = NULL;
  struct SM2_Ciphertext_st *sm2_ctext = NULL;
  BIGNUM *x2 = NULL;
  BIGNUM *y2 = NULL;
  uint8_t *x2y2 = NULL;
  uint8_t *computed_C3 = NULL;
  const size_t field_size = ec_field_size(group);
  const int hash_size = EVP_MD_size(digest);
  uint8_t *msg_mask = NULL;
  const uint8_t *C2 = NULL;
  const uint8_t *C3 = NULL;
  int msg_len = 0;
  EVP_MD_CTX *hash = NULL;

  if (field_size == 0 || hash_size <= 0)
    goto done;

  memset(ptext_buf, 0xFF, *ptext_len);

  sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);

  if (sm2_ctext == NULL) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    goto done;
  }

  if (sm2_ctext->C3->length != hash_size) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ENCODING);
    goto done;
  }

  C2 = sm2_ctext->C2->data;
  C3 = sm2_ctext->C3->data;
  msg_len = sm2_ctext->C2->length;
  if (*ptext_len < (size_t)msg_len) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_BUFFER_TOO_SMALL);
    goto done;
  }

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
    goto done;
  }

  BN_CTX_start(ctx);
  x2 = BN_CTX_get(ctx);
  y2 = BN_CTX_get(ctx);

  if (y2 == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
    goto done;
  }

  msg_mask = OPENSSL_zalloc(msg_len);
  x2y2 = OPENSSL_zalloc(2 * field_size);
  computed_C3 = OPENSSL_zalloc(hash_size);

  if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL)
    goto done;

  C1 = EC_POINT_new(group);
  if (C1 == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto done;
  }

  if (!EC_POINT_set_affine_coordinates(group, C1, sm2_ctext->C1x,
                                       sm2_ctext->C1y, ctx) ||
      !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key), ctx) ||
      !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto done;
  }

  if (BN_bn2binpad(x2, x2y2, field_size) < 0 ||
      BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0 ||
      !ossl_ecdh_kdf_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                           digest)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto done;
  }

  for (i = 0; i != msg_len; ++i)
    ptext_buf[i] = C2[i] ^ msg_mask[i];

  hash = EVP_MD_CTX_new();
  if (hash == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto done;
  }

  if (!EVP_DigestInit(hash, digest) ||
      !EVP_DigestUpdate(hash, x2y2, field_size) ||
      !EVP_DigestUpdate(hash, ptext_buf, msg_len) ||
      !EVP_DigestUpdate(hash, x2y2 + field_size, field_size) ||
      !EVP_DigestFinal(hash, computed_C3, NULL)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto done;
  }

  if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_DIGEST);
    goto done;
  }

  rc = 1;
  *ptext_len = msg_len;

done:
  BN_CTX_end(ctx);

  if (rc == 0)
    memset(ptext_buf, 0, *ptext_len);

  OPENSSL_free(msg_mask);
  OPENSSL_free(x2y2);
  OPENSSL_free(computed_C3);
  EC_POINT_free(C1);
  BN_CTX_free(ctx);
  SM2_Ciphertext_free(sm2_ctext);
  EVP_MD_CTX_free(hash);

  return rc;
}
