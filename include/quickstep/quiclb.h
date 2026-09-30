/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of quickstep.

   quickstep is free software: you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   quickstep is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program.  If not, see
   <https://www.gnu.org/licenses/>.  */

/* QUIC-LB connection IDs (draft-ietf-quic-load-balancers-21): the
   parameters a server behind a stateless load balancer needs to encode a
   routable server ID into every connection ID it issues (section 5.2),
   and to recognise its own IDs again (sections 5.4 and 5.5).  The draft
   is not an RFC and revision 21 has expired, so all wire encoding is
   confined to this module; a later revision replaces it here.

   Layout: a first octet carrying the config id in its three most
   significant bits and either a self-described length or random bits in
   the other five (section 3.3), then the server ID and a nonce.  With a
   key, the server ID and nonce are encrypted with AES-128, in one pass
   when they total exactly 16 octets (section 5.4.1) and by a four-round
   Feistel construction otherwise (section 5.4.2); without one they are
   sent as plaintext (section 5.5), which is linkable and meant only for
   trusted networks or testing.

   A configuration plugs into gq_conn_config.cid_gen (every connection ID
   this endpoint mints, including NEW_CONNECTION_ID) and
   gq_admit_config.cid_gen (the ID chosen in a Retry, RFC 9000 section
   8.1.2, which the draft requires to be routable too) through
   gq_quiclb_cid_gen; set cid_len (or retry_cid_len) to
   gq_quiclb_cid_len so the two agree.  A load balancer or another server
   sharing the same configuration recovers the server ID with
   gq_quiclb_decode_server_id or checks it with gq_quiclb_is_own.  */

#ifndef QUICKSTEP_QUICLB_H
#define QUICKSTEP_QUICLB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GQ_QUICLB_MAX_CONFIG_ID 6	/* 7 marks an unroutable ID.  */
#define GQ_QUICLB_MIN_NONCE_LEN 4	/* Section 5.3.  */
#define GQ_QUICLB_MAX_PLAINTEXT_LEN 19	/* Server ID + nonce, section 5.3.  */
#define GQ_QUICLB_KEY_LEN 16
#define GQ_QUICLB_MAX_CID_LEN (1 + GQ_QUICLB_MAX_PLAINTEXT_LEN)

typedef struct gq_quiclb_config
{
  unsigned config_id;
  uint8_t server_id[GQ_QUICLB_MAX_PLAINTEXT_LEN];
  size_t server_id_len;
  size_t nonce_len;
  uint8_t key[GQ_QUICLB_KEY_LEN];
  int have_key;		/* 0: plaintext IDs (section 5.5).  */
  int encodes_length;		/* First octet self-describes the length
				   (section 3.3), as Envoy requires.  */
} gq_quiclb_config;

/* CONFIG_ID is 0 to GQ_QUICLB_MAX_CONFIG_ID.  SERVER_ID_LEN plus NONCE_LEN
   must not exceed GQ_QUICLB_MAX_PLAINTEXT_LEN and NONCE_LEN must be at
   least GQ_QUICLB_MIN_NONCE_LEN.  KEY may be NULL for plaintext IDs.
   Returns GQ_ERR_INVAL if any of that does not hold.  */
int gq_quiclb_config_init (gq_quiclb_config *cfg, unsigned config_id,
                          const uint8_t *server_id, size_t server_id_len,
                          size_t nonce_len,
                          const uint8_t key[GQ_QUICLB_KEY_LEN],
                          int encodes_length);

/* The length of every connection ID this configuration produces,
   including the first octet; use it as gq_conn_config.cid_len or
   gq_admit_config.retry_cid_len.  */
size_t gq_quiclb_cid_len (const gq_quiclb_config *cfg);

/* Matches the gq_conn_config.cid_gen / gq_admit_config.cid_gen signature
   (USER is a const gq_quiclb_config *): fills OUT (LEN bytes, which must
   equal gq_quiclb_cid_len) with a fresh connection ID with a random
   nonce.  */
int gq_quiclb_cid_gen (void *user, uint8_t *out, size_t len);

/* As gq_quiclb_cid_gen, with an explicit nonce (CFG's nonce_len bytes)
   instead of a random one.  OUT_LEN must equal gq_quiclb_cid_len (CFG).  */
int gq_quiclb_encode (const gq_quiclb_config *cfg, const uint8_t *nonce,
                     uint8_t *out, size_t out_len);

/* Recovers the server ID from CID (CID_LEN bytes) if it uses this
   configuration's config id, and length when ENCODES_LENGTH.  Writes at
   most *OUT_LEN bytes to OUT and sets *OUT_LEN to the server ID length.
   Returns GQ_ERR_ENCODING if CID does not match this configuration
   (a different config id, length, or a corrupt encrypted ID; a load
   balancer routes such an ID by other means, per section 3.1), or
   GQ_ERR_BUFSIZE if OUT is too small.  */
int gq_quiclb_decode_server_id (const gq_quiclb_config *cfg,
                                const uint8_t *cid, size_t cid_len,
                                uint8_t *out, size_t *out_len);

/* Whether CID decodes, under this configuration, to exactly CFG's own
   server ID.  */
int gq_quiclb_is_own (const gq_quiclb_config *cfg, const uint8_t *cid,
                     size_t cid_len);

#ifdef __cplusplus
}
#endif

#endif /* QUICKSTEP_QUICLB_H */
