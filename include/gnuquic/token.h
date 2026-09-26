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

/* Address validation tokens (RFC 9000 section 8.1).

   A token is an authenticated, encrypted blob a server hands to a client
   (in a Retry packet, or in a NEW_TOKEN frame after the handshake) and
   the client returns in a later Initial packet.  It proves the client can
   receive at the address it claims, so the server may lift the
   anti-amplification limit without keeping any state.

   A token is bound to the client's address (an opaque byte string chosen
   by the caller, normally the IP address, plus the port for Retry) as
   AEAD associated data, carries its issue time, and for Retry also the
   original destination connection ID and the connection ID the server
   chose.  Nothing is stored server side.  Keys rotate: the previous key
   still verifies, so tokens survive one rotation.  */

#ifndef GNUQUIC_TOKEN_H
#define GNUQUIC_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/tparams.h>	/* gq_cid */

#ifdef __cplusplus
extern "C" {
#endif

#define GQ_TOKEN_MAX 128
#define GQ_TOKEN_KEY_LEN 32

enum gq_token_kind
{
  GQ_TOKEN_RETRY = 1,
  GQ_TOKEN_NEW_TOKEN
};

typedef struct gq_token_keys
{
  uint8_t key[2][GQ_TOKEN_KEY_LEN];	/* Current, previous.  */
  int have_prev;
} gq_token_keys;

/* Generate a fresh random key.  */
int gq_token_keys_init (gq_token_keys *k);

/* Make the current key the previous one and generate a new one.  */
int gq_token_keys_rotate (gq_token_keys *k);

void gq_token_keys_wipe (gq_token_keys *k);

typedef struct gq_token_info
{
  enum gq_token_kind kind;
  uint64_t issued;		/* Seconds, as given to gq_token_make.  */
  gq_cid odcid;			/* Retry: the client's first destination ID.  */
  gq_cid scid;			/* Retry: the ID the server chose.  */
} gq_token_info;

/* Build a token into OUT (GQ_TOKEN_MAX bytes) and set *LEN.  ODCID and
   SCID matter only for GQ_TOKEN_RETRY and may be NULL otherwise.  NOW_S
   is wall-clock seconds.  */
int gq_token_make (const gq_token_keys *k, enum gq_token_kind kind,
                   const uint8_t *addr, size_t addr_len,
                   const gq_cid *odcid, const gq_cid *scid, uint64_t now_s,
                   uint8_t *out, size_t *len);

/* Verify a token presented by a client at ADDR.  Returns GQ_OK and fills
   INFO; GQ_ERR_CRYPTO if it is not a token of ours for this address (or is
   malformed); GQ_ERR_RANGE if it is genuine but older than LIFETIME_S for
   its kind (RETRY_LIFETIME_S, NEW_LIFETIME_S).  */
int gq_token_check (const gq_token_keys *k, const uint8_t *addr,
                    size_t addr_len, const uint8_t *token, size_t len,
                    uint64_t now_s, uint32_t retry_lifetime_s,
                    uint32_t new_lifetime_s, gq_token_info *info);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TOKEN_H */
