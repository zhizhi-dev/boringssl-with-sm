/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>

#include <openssl/asn1t.h>
#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>



#include "../asn1/internal.h"
#include "../bytestring/internal.h"
#include "../internal.h"
#include "internal.h"


static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it);
static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it);
static int bn_d2i(ASN1_VALUE **pval, const uint8_t **in, long len,
                       const ASN1_ITEM *it, int opt, ASN1_TLC *ctx);
static int bn_i2d(ASN1_VALUE **pval, uint8_t **out,
                       const ASN1_ITEM *it);

static ASN1_EXTERN_FUNCS bignum_pf = {
    bn_new,
    bn_free,
    bn_d2i,
    bn_i2d,
};

// IMPLEMENT_EXTERN_ASN1(BIGNUM, V_ASN1_INTEGER, bignum_pf)

ASN1_ITEM_start(BIGNUM)
        ASN1_ITYPE_EXTERN, V_ASN1_INTEGER, NULL, 0, &bignum_pf, 0, "BIGNUM"
ASN1_ITEM_end(BIGNUM)

int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  *pval = (ASN1_VALUE *)BN_new();
  return *pval != NULL ? 1 : 0;
}

void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  if (*pval == NULL)
    return;
  BN_free((BIGNUM *)*pval);
  *pval = NULL;
}

int bn_d2i(ASN1_VALUE **pval, const uint8_t **in, long len,
                       const ASN1_ITEM *it, int opt, ASN1_TLC *ctx){
  CBS cbs;
  CBS_init(&cbs, *in, len);
  if (!BN_parse_asn1_unsigned(&cbs, (BIGNUM*)*pval)) {
    return 0;
  }
  *in = CBS_data(&cbs);
  return 1;
}

int bn_i2d(ASN1_VALUE **pval, uint8_t **out, const ASN1_ITEM *it) {
  CBB cbb;
  CBB_zero(&cbb);
  if (!CBB_init(&cbb, 0) ||
      !BN_marshal_asn1(&cbb, (BIGNUM*)*pval) ||
      !CBB_finish(&cbb, out, NULL)) {
    CBB_cleanup(&cbb);
    return 0;
  }  
  return 1;
}
