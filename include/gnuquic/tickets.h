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

/* Session tickets: the server's stateless ticket key ring and the session
   state a ticket carries (RFC 8446 section 4.6.1, RFC 5077 in spirit).

   A ticket is the server's session state, encrypted and authenticated
   under a key only the server holds, so the server keeps no per-client
   state: everything needed to resume (the resumption PSK, the cipher
   suite, when it was issued, what it was bound to) is inside.  The layout
   is

       key_name (16) | nonce (12) | AES-256-GCM (state) | tag (16)

   with the key name as associated data.  Keys live in a small ring: one
   active key encrypts, any key in the ring decrypts, and rotating adds a
   new active key while older tickets keep working until their key is
   pushed out.  Servers behind a load balancer share tickets by installing
   the same keys with gq_ticket_keys_add.

   Random 96-bit GCM nonces bound the number of tickets per key at about
   2^32, so rotate at least daily on a busy server.  The key ring is not
   thread safe; guard it if several threads issue tickets.  */

#ifndef GNUQUIC_TICKETS_H
#define GNUQUIC_TICKETS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GQ_TICKET_KEY_LEN 32
#define GQ_TICKET_KEYS_MAX 4
/* Upper bound on a ticket a client is asked to store.  */
#define GQ_TICKET_MAX 2048

/* What a ticket carries.  */
typedef struct gq_session_state
{
  uint16_t cipher_suite;
  uint8_t psk[48];			/* The resumption PSK for this ticket.  */
  size_t psk_len;
  uint64_t created_ms;			/* Issue time, server clock.  */
  uint32_t age_add;			/* Ticket age obfuscation.  */
  uint32_t lifetime;			/* Seconds.  */
  uint32_t max_early_data;		/* 0: no early data.  */
  int client_authenticated;		/* The original handshake verified a
					   client certificate.  */
  char server_name[256];		/* SNI the session was bound to.  */
  size_t server_name_len;
  uint8_t alpn[255];			/* Protocol negotiated originally.  */
  size_t alpn_len;
} gq_session_state;

typedef struct gq_ticket_keys gq_ticket_keys;

/* Create a key ring holding one fresh random active key.  */
int gq_ticket_keys_new (gq_ticket_keys **out);
void gq_ticket_keys_free (gq_ticket_keys *keys);

/* Add a new random active key.  The previous keys keep decrypting; when
   the ring is full the oldest inactive key is dropped.  */
int gq_ticket_keys_rotate (gq_ticket_keys *keys);

/* Install a key chosen by the caller (for sharing between servers).  If
   ACTIVE is nonzero it becomes the encryption key.  */
int gq_ticket_keys_add (gq_ticket_keys *keys,
                        const uint8_t key[GQ_TICKET_KEY_LEN], int active);

/* Encrypt STATE into OUT (CAP bytes); the size is stored in *OUT_LEN.  */
int gq_ticket_seal (const gq_ticket_keys *keys, const gq_session_state *state,
                    uint8_t *out, size_t cap, size_t *out_len);

/* Decrypt and decode a ticket.  GQ_ERR_CRYPTO if no key in the ring
   authenticates it (unknown key, tampering); GQ_ERR_ENCODING if the
   authenticated payload is malformed.  *ACTIVE_KEY, if not NULL, tells
   whether the active key was used, so a server can choose to reissue
   under the current key.  */
int gq_ticket_open (const gq_ticket_keys *keys, const uint8_t *ticket,
                    size_t len, gq_session_state *state, int *active_key);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TICKETS_H */
