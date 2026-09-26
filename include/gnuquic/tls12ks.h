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

/* TLS 1.2 key schedule (RFC 5246 sections 5 and 6.3, RFC 5288,
   RFC 7627, RFC 7905, RFC 5705).

   TLS 1.2 derives everything from one PRF, P_hash over HMAC, with the
   hash fixed by the cipher suite (SHA-384 for the AES-256-GCM suite, else
   SHA-256).  Only ECDHE suites with an AEAD exist here, and the master
   secret is always the extended master secret of RFC 7627: the
   non-extended derivation is not implemented.  */

#ifndef GNUQUIC_TLS12KS_H
#define GNUQUIC_TLS12KS_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GQ_TLS12_MASTER_LEN 48
#define GQ_TLS12_VERIFY_LEN 12
#define GQ_TLS12_RANDOM_LEN 32

/* AEAD and PRF hash for a TLS 1.2 suite (a gq_tls12_suite code point).
   Returns 1, or 0 for a suite that is not one of ours.  */
int gq_tls12_suite_params (unsigned suite, enum gq_aead *aead,
                           enum gq_hash *hash);

/* 1 if the suite authenticates with an RSA certificate, 0 for ECDSA.  */
int gq_tls12_suite_is_rsa (unsigned suite);

/* PRF (RFC 5246 section 5): P_hash (SECRET, LABEL || SEED), OUTLEN bytes.
   SEED is the already concatenated seed.  */
int gq_tls12_prf (enum gq_hash hash, const uint8_t *secret, size_t secret_len,
                  const char *label, const uint8_t *seed, size_t seed_len,
                  uint8_t *out, size_t out_len);

/* Extended master secret (RFC 7627 section 4): the PRF of the premaster
   secret over the session hash, which is the hash of the handshake
   messages up to and including ClientKeyExchange.  */
int gq_tls12_master_secret (enum gq_hash hash, const uint8_t *premaster,
                            size_t premaster_len, const uint8_t *session_hash,
                            uint8_t master[GQ_TLS12_MASTER_LEN]);

/* Record protection keys (RFC 5246 section 6.3).  IV is the implicit
   nonce part: 4 bytes for AES-GCM (RFC 5288), 12 bytes for
   ChaCha20-Poly1305 (RFC 7905).  */
typedef struct gq_tls12_keys
{
  enum gq_aead aead;
  size_t key_len, iv_len;
  uint8_t client_key[32], server_key[32];
  uint8_t client_iv[12], server_iv[12];
} gq_tls12_keys;

int gq_tls12_key_block (enum gq_hash hash, enum gq_aead aead,
                        const uint8_t master[GQ_TLS12_MASTER_LEN],
                        const uint8_t server_random[32],
                        const uint8_t client_random[32], gq_tls12_keys *keys);

/* Finished verify_data (RFC 5246 section 7.4.9) from the hash of all
   handshake messages so far.  */
int gq_tls12_verify_data (enum gq_hash hash,
                          const uint8_t master[GQ_TLS12_MASTER_LEN],
                          int from_client, const uint8_t *handshake_hash,
                          uint8_t out[GQ_TLS12_VERIFY_LEN]);

/* Keying material exporter (RFC 5705).  CONTEXT may be NULL (no context,
   as opposed to an empty one).  */
int gq_tls12_exporter (enum gq_hash hash,
                       const uint8_t master[GQ_TLS12_MASTER_LEN],
                     const uint8_t client_random[32],
                     const uint8_t server_random[32], const char *label,
                     const uint8_t *context, size_t context_len,
                     uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TLS12KS_H */
