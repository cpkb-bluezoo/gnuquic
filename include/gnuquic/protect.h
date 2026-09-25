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

/* QUIC packet protection (RFC 9001 section 5, RFC 9369).

   Packets are protected in place.  The caller lays a packet out in one
   buffer (header from packet.h, then payload) and the functions here
   encrypt the payload, append the AEAD tag, and mask the header; the
   reverse on receipt.  Nothing is allocated.

   Key derivation depends on the QUIC version because v2 uses different
   HKDF labels, so every derivation function takes the version.  */

#ifndef GNUQUIC_PROTECT_H
#define GNUQUIC_PROTECT_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/crypto.h>
#include <gnuquic/packet.h>	/* GQ_RETRY_TAG_LEN */

#ifdef __cplusplus
extern "C" {
#endif

/* Keys for one direction and one encryption level.  */
typedef struct gq_packet_keys
{
  enum gq_aead aead;
  uint8_t key[32];
  uint8_t iv[GQ_AEAD_NONCE_LEN];
  uint8_t hp[32];		/* Header protection key.  */
} gq_packet_keys;

/* Wipe the key material.  */
void gq_packet_keys_wipe (gq_packet_keys *k);

/* Derive packet protection key, IV and header protection key from a
   traffic SECRET (HKDF-Expand-Label "quic key", "quic iv", "quic hp";
   "quicv2 ..." for version 2).  The hash is chosen by AEAD.  */
int gq_packet_keys_derive (uint32_t version, enum gq_aead aead,
                           const uint8_t *secret, size_t secret_len,
                           gq_packet_keys *k);

/* Initial keys for both directions, from the Destination Connection ID
   of the client's first Initial packet (RFC 9001 section 5.2).  Either
   output may be NULL.  Initial packets always use AES-128-GCM.  */
int gq_packet_keys_initial (uint32_t version, const uint8_t *dcid,
                            size_t dcid_len, gq_packet_keys *client,
                            gq_packet_keys *server);

/* Key update (RFC 9001 section 6): compute the next traffic secret
   ("quic ku") into NEXT_SECRET (same length as SECRET) and the keys
   derived from it into NEXT.  The header protection key does not change
   and is copied from CUR.  */
int gq_packet_keys_update (uint32_t version, const gq_packet_keys *cur,
                           const uint8_t *secret, size_t secret_len,
                           uint8_t *next_secret, gq_packet_keys *next);

/* Initial traffic secrets, exposed for the TLS engine.  Each is 32 bytes
   (SHA-256).  */
#define GQ_INITIAL_SECRET_LEN 32
int gq_initial_secrets (uint32_t version, const uint8_t *dcid,
                        size_t dcid_len,
                        uint8_t client[GQ_INITIAL_SECRET_LEN],
                        uint8_t server[GQ_INITIAL_SECRET_LEN]);

/* Protect a packet in place.

   PKT holds, in order: the header (with the packet number in the clear,
   PN_LEN bytes at PN_OFFSET, as built by gq_long_header_build or
   gq_short_header_build), then PAYLOAD_LEN bytes of plaintext frames.
   CAP must leave room for GQ_AEAD_TAG_LEN more bytes.  The payload is
   encrypted, the tag appended, and the header masked.  *OUT_LEN receives
   the finished packet size.

   The header protection sample is taken 4 bytes past the start of the
   packet number field, so the payload must be at least 4 - PN_LEN bytes
   long; pad with PADDING frames otherwise (GQ_ERR_RANGE).  */
int gq_packet_seal (const gq_packet_keys *k, uint64_t pn, uint8_t *pkt,
                    size_t pn_offset, size_t pn_len, size_t payload_len,
                    size_t cap, size_t *out_len);

/* Receive side, step 1: remove header protection in place.  This exposes
   the first byte (for example the key phase bit of a short header) and
   the packet number bytes, and returns their count in *PN_LEN.  It does
   not authenticate anything.  LEN is the packet size including the tag.
   GQ_ERR_ENCODING if the packet is too short to sample.  */
int gq_hp_remove (const gq_packet_keys *k, uint8_t *pkt, size_t len,
                  size_t pn_offset, size_t *pn_len);

/* Receive side, step 2: authenticate and decrypt in place.  FULL_PN is
   the packet number reconstructed with gq_pn_decode.  On success the
   plaintext frames are PKT[*PAYLOAD_OFF .. *PAYLOAD_OFF + *PAYLOAD_LEN).
   On failure returns GQ_ERR_CRYPTO and leaves no plaintext behind.  A
   nonzero reserved header bit after decryption is GQ_ERR_ENCODING (the
   connection layer should treat it as a protocol violation).  */
int gq_packet_decrypt (const gq_packet_keys *k, uint64_t full_pn,
                       uint8_t *pkt, size_t len, size_t pn_offset,
                       size_t pn_len, size_t *payload_off,
                       size_t *payload_len);

/* Steps 1 and 2 together, including packet number recovery.
   HAVE_LARGEST / LARGEST_RECEIVED describe the largest packet number
   received so far in this packet number space.  */
int gq_packet_open (const gq_packet_keys *k, int have_largest,
                    uint64_t largest_received, uint8_t *pkt, size_t len,
                    size_t pn_offset, uint64_t *pn, size_t *payload_off,
                    size_t *payload_len);

/* Retry integrity tag (RFC 9001 section 5.8, RFC 9369 section 3.3.3)
   over RETRY_NO_TAG, the Retry packet without its final 16 bytes.  */
int gq_retry_tag (uint32_t version, const uint8_t *odcid, size_t odcid_len,
                  const uint8_t *retry_no_tag, size_t len,
                  uint8_t tag[GQ_RETRY_TAG_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_PROTECT_H */
