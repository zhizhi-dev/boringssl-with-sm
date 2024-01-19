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

#ifndef OPENSSL_HEADER_SM2_H
#define OPENSSL_HEADER_SM2_H

#include <openssl/base.h>


/* The default user id as specified in GM/T 0009-2012 */
#define SM2_DEFAULT_USERID "1234567812345678"

#define SM2_R_ASN1_ERROR 100
#define SM2_R_BAD_SIGNATURE 101
#define SM2_R_BUFFER_TOO_SMALL 107
#define SM2_R_DIST_ID_TOO_LARGE 110
#define SM2_R_ID_NOT_SET 112
#define SM2_R_ID_TOO_LARGE 111
#define SM2_R_INVALID_CURVE 108
#define SM2_R_INVALID_DIGEST 102
#define SM2_R_INVALID_DIGEST_TYPE 103
#define SM2_R_INVALID_ENCODING 104
#define SM2_R_INVALID_FIELD 105
#define SM2_R_INVALID_PRIVATE_KEY 113
#define SM2_R_NO_PARAMETERS_SET 109
#define SM2_R_USER_ID_TOO_LARGE 106

#ifdef __cplusplus
extern "C" {
#endif

OPENSSL_EXPORT int SM2_key_private_check(const EC_KEY *eckey);

OPENSSL_EXPORT int SM2_compute_z_digest(uint8_t *out, const EVP_MD *digest,
                                        const uint8_t *id, const size_t id_len,
                                        const EC_KEY *key);

/*
 * SM2 signature operation. Computes Z and then signs H(Z || msg) using SM2
 */
OPENSSL_EXPORT ECDSA_SIG *SM2_do_sign(const EC_KEY *key, const EVP_MD *digest,
                                      const uint8_t *id, const size_t id_len,
                                      const uint8_t *msg, size_t msg_len);

OPENSSL_EXPORT int SM2_do_verify(const EC_KEY *key, const EVP_MD *digest,
                                 const ECDSA_SIG *signature, const uint8_t *id,
                                 const size_t id_len, const uint8_t *msg,
                                 size_t msg_len);

/*
 * SM2 signature generation.
 */
OPENSSL_EXPORT int SM2_internal_sign(const uint8_t *dgst, int dgstlen,
                                     uint8_t *sig, unsigned int *siglen,
                                     EC_KEY *eckey);

/*
 * SM2 signature verification.
 */
OPENSSL_EXPORT int SM2_internal_verify(const uint8_t *dgst, int dgstlen,
                                       const uint8_t *sig, int siglen,
                                       EC_KEY *eckey);

/*
 * SM2 encryption
 */
OPENSSL_EXPORT int SM2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest,
                                       size_t msg_len, size_t *ct_size);

OPENSSL_EXPORT int SM2_plaintext_size(const uint8_t *ct, size_t ct_size,
                                      size_t *pt_size);

OPENSSL_EXPORT int SM2_encrypt(const EC_KEY *key, const EVP_MD *digest,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *ciphertext_buf, size_t *ciphertext_len);

OPENSSL_EXPORT int SM2_decrypt(const EC_KEY *key, const EVP_MD *digest,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t *ptext_buf, size_t *ptext_len);

OPENSSL_EXPORT const uint8_t *SM2_algorithmidentifier_encoding(int md_nid,
                                                               size_t *len);

#ifdef __cplusplus
}
#endif
#endif  // OPENSSL_HEADER_SM2_H
