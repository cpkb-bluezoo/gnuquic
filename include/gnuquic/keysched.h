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

/* TLS 1.3 key schedule (RFC 8446 section 7).

   The schedule is a chain of HKDF-Extract steps: early secret, handshake
   secret, master secret.  gq_ks holds the current one and moves forward
   only, so derivations are available exactly at the stages where the
   protocol allows them.  It works for both hashes in use: SHA-256 for
   TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256, SHA-384 for
   TLS_AES_256_GCM_SHA384.

   Secrets are hash-length arrays (at most GQ_MAX_HASH_LEN).  The
   transcript hash arguments are the values from gq_transcript_hash at the
   stage named in each function.  The same code serves QUIC (which turns
   traffic secrets into packet keys with gq_packet_keys_derive), TLS over
   TCP (gq_traffic_keys) and DTLS 1.3.  */

#ifndef GNUQUIC_KEYSCHED_H
#define GNUQUIC_KEYSCHED_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GQ_MAX_HASH_LEN 48

enum gq_ks_stage
{
  GQ_KS_EARLY = 1,
  GQ_KS_HANDSHAKE,
  GQ_KS_MASTER
};

typedef struct gq_ks
{
  enum gq_hash hash;
  size_t hlen;
  enum gq_ks_stage stage;
  uint8_t secret[GQ_MAX_HASH_LEN];
} gq_ks;

/* Start the schedule with the early secret.  PSK is the pre-shared key
   (NULL and 0 for none, meaning a string of zeros as in the RFC), which
   must be hash-length when given.  */
int gq_ks_early (gq_ks *ks, enum gq_hash hash, const uint8_t *psk,
                 size_t psk_len);

/* Early stage: binder key ("res binder" for a resumption PSK, "ext
   binder" otherwise), and the client early traffic secret ("c e traffic")
   from the ClientHello transcript hash.  */
int gq_ks_binder_key (const gq_ks *ks, int resumption, uint8_t *out);
int gq_ks_client_early_traffic (const gq_ks *ks, const uint8_t *hello_hash,
                                uint8_t *out);

/* Early to handshake, mixing in the (EC)DHE shared secret (all zeros of
   hash length if the handshake is PSK-only).  */
int gq_ks_handshake (gq_ks *ks, const uint8_t *shared, size_t shared_len);

/* Handshake stage: traffic secrets from Hash(ClientHello..ServerHello).  */
int gq_ks_handshake_traffic (const gq_ks *ks, const uint8_t *hello_hash,
                             uint8_t *client, uint8_t *server);

/* Handshake to master.  */
int gq_ks_master (gq_ks *ks);

/* Master stage: application traffic secrets and the exporter master
   secret from Hash(ClientHello..server Finished); the resumption master
   secret from Hash(ClientHello..client Finished).  */
int gq_ks_app_traffic (const gq_ks *ks, const uint8_t *finished_hash,
                       uint8_t *client, uint8_t *server);
int gq_ks_exporter_master (const gq_ks *ks, const uint8_t *finished_hash,
                           uint8_t *out);
int gq_ks_resumption_master (const gq_ks *ks, const uint8_t *client_fin_hash,
                             uint8_t *out);

void gq_ks_wipe (gq_ks *ks);

/* ---- Stateless helpers ---- */

/* Finished verify_data: HMAC (finished_key, transcript hash) where the
   key is HKDF-Expand-Label (BASE_SECRET, "finished").  Also used for PSK
   binders with the binder key as BASE_SECRET.  OUT is hash-length.  */
int gq_finished_verify_data (enum gq_hash hash, const uint8_t *base_secret,
                             const uint8_t *transcript_hash, uint8_t *out);

/* The finished key itself, hash-length.  */
int gq_finished_key (enum gq_hash hash, const uint8_t *base_secret,
                     uint8_t *out);

/* Next application traffic secret for KeyUpdate ("traffic upd").  */
int gq_traffic_secret_update (enum gq_hash hash, const uint8_t *secret,
                              uint8_t *next);

/* Traffic key and IV for TLS record protection ("key", "iv").  KEY is
   gq_aead_key_size (AEAD) bytes, IV 12.  */
int gq_traffic_keys (enum gq_aead aead, const uint8_t *secret,
                     uint8_t *key, uint8_t iv[GQ_AEAD_NONCE_LEN]);

/* Resumption PSK for one ticket ("resumption", ticket nonce as context).  */
int gq_resumption_psk (enum gq_hash hash, const uint8_t *res_master,
                       const uint8_t *nonce, size_t nonce_len, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_KEYSCHED_H */
