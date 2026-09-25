/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of GNU QUIC.

   GNU QUIC is free software: you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   GNU QUIC is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program.  If not, see
   <https://www.gnu.org/licenses/>.  */

/* Thin cryptographic layer.

   Every primitive (hash, HMAC, AEAD, block/stream cipher for header
   protection, random) is delegated to libgcrypt.  This module adds only
   the protocol glue that TLS 1.3 defines on top of primitives:
   HKDF-Extract/Expand (RFC 5869) and HKDF-Expand-Label (RFC 8446
   section 7.1).  QUIC-specific derivation lives in protect.h.

   Only AEAD suites are offered.  There is deliberately no CBC, no RC4
   and no MD5/SHA-1 here.

   All functions return a gq_status.  Output buffers are exact-size; no
   function allocates.  Call gq_crypto_init once, before creating
   threads, or let the first use do it.  */

#ifndef GNUQUIC_CRYPTO_H
#define GNUQUIC_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize libgcrypt if the application has not already done so.
   Idempotent.  Returns GQ_OK or GQ_ERR_CRYPTO (library too old).  */
int gq_crypto_init (void);

/* Fill BUF with LEN cryptographically strong random bytes.  */
int gq_random (void *buf, size_t len);

/* Constant-time comparison of two N-byte buffers: 1 if equal, else 0.
   Use for every comparison involving a MAC, tag or token.  */
int gq_ct_equal (const void *a, const void *b, size_t n);

/* Overwrite SECRET with zeros in a way the compiler may not elide.  */
void gq_wipe (void *secret, size_t len);

/* ---- Hashes and HMAC ---- */

enum gq_hash
{
  GQ_HASH_SHA256 = 1,
  GQ_HASH_SHA384
};

/* Digest length in bytes, or 0 for an unknown algorithm.  */
size_t gq_hash_size (enum gq_hash alg);

/* Hash DATA into OUT, which must be exactly gq_hash_size (ALG) bytes.  */
int gq_hash_compute (enum gq_hash alg, const void *data, size_t len,
                     uint8_t *out, size_t outlen);

/* HMAC of DATA under KEY into OUT (exactly gq_hash_size (ALG) bytes).  */
int gq_hmac (enum gq_hash alg, const void *key, size_t keylen,
             const void *data, size_t len, uint8_t *out, size_t outlen);

/* ---- HKDF ---- */

/* HKDF-Extract.  An empty SALT means a string of zeros as in RFC 5869.
   PRK must be exactly gq_hash_size (ALG) bytes.  */
int gq_hkdf_extract (enum gq_hash alg, const void *salt, size_t saltlen,
                     const void *ikm, size_t ikmlen,
                     uint8_t *prk, size_t prklen);

/* HKDF-Expand to exactly OUTLEN bytes (at most 255 hash lengths).  */
int gq_hkdf_expand (enum gq_hash alg, const void *prk, size_t prklen,
                    const void *info, size_t infolen,
                    uint8_t *out, size_t outlen);

/* HKDF-Expand-Label (RFC 8446 section 7.1).  LABEL is given without the
   "tls13 " prefix, which is added here.  CONTEXT may be empty.  */
int gq_hkdf_expand_label (enum gq_hash alg,
                          const void *secret, size_t secretlen,
                          const char *label,
                          const void *context, size_t contextlen,
                          uint8_t *out, size_t outlen);

/* ---- AEAD and header protection ---- */

enum gq_aead
{
  GQ_AEAD_AES_128_GCM = 1,
  GQ_AEAD_AES_256_GCM,
  GQ_AEAD_CHACHA20_POLY1305
};

#define GQ_AEAD_NONCE_LEN 12
#define GQ_AEAD_TAG_LEN 16
#define GQ_HP_SAMPLE_LEN 16
#define GQ_HP_MASK_LEN 5

size_t gq_aead_key_size (enum gq_aead alg);	/* 0 if unknown.  */

/* Hash used by the TLS 1.3 cipher suite that pairs with ALG
   (SHA-384 for AES-256-GCM, SHA-256 otherwise).  */
enum gq_hash gq_aead_hash (enum gq_aead alg);

/* Encrypt PT (PTLEN bytes) into OUT as ciphertext followed by the
   16-byte tag; OUTLEN must be PTLEN + GQ_AEAD_TAG_LEN.  PT and OUT may
   be the same buffer.  NONCE is 12 bytes.  */
int gq_aead_seal (enum gq_aead alg, const uint8_t *key, size_t keylen,
                  const uint8_t *nonce,
                  const void *aad, size_t aadlen,
                  const void *pt, size_t ptlen,
                  uint8_t *out, size_t outlen);

/* Verify and decrypt CT (ciphertext followed by tag, CTLEN bytes) into
   OUT, which must hold CTLEN - GQ_AEAD_TAG_LEN bytes.  On failure
   returns GQ_ERR_CRYPTO and OUT is zeroed.  CT and OUT may coincide.  */
int gq_aead_open (enum gq_aead alg, const uint8_t *key, size_t keylen,
                  const uint8_t *nonce,
                  const void *aad, size_t aadlen,
                  const void *ct, size_t ctlen,
                  uint8_t *out, size_t outlen);

/* QUIC header-protection mask (RFC 9001 section 5.4): MASK receives
   GQ_HP_MASK_LEN bytes from the 16-byte SAMPLE.  AES-GCM suites use
   AES-ECB, ChaCha20-Poly1305 uses the ChaCha20 block function.  */
int gq_hp_mask (enum gq_aead alg, const uint8_t *hp_key, size_t keylen,
                const uint8_t sample[GQ_HP_SAMPLE_LEN],
                uint8_t mask[GQ_HP_MASK_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_CRYPTO_H */
