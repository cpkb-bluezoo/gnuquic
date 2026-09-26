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

/* Stateless DTLS 1.3 cookie exchange for servers (RFC 9147 section 5.1).

   A DTLS server that allocated an association for every ClientHello could
   be made to hold memory and spend cryptography for spoofed sources, and
   could be used to flood a victim with its first flight.  gq_dtls_listen
   sits in front of the associations: it looks at the first datagram from
   an address that has no association and either

     GQ_DTLS_LISTEN_DROP    ignores it;
     GQ_DTLS_LISTEN_REPLY   fills REPLY with a HelloRetryRequest carrying a
                            cookie bound to the source address and to the
                            ClientHello, and keeps no state at all;
     GQ_DTLS_LISTEN_ACCEPT  the datagram is a ClientHello2 with a valid
                            cookie, so the source can receive at its
                            address: create the association with
                            gq_dtls_server_new (..., PRIME) and give it
                            this same datagram.

   The cookie is 16 bytes of HMAC-SHA256 over the address binding and its
   own contents, which hold the selected suite and group, the hash of
   ClientHello1 (which the transcript needs) and a check that ClientHello2
   repeats what ClientHello1 offered.  Two secrets are kept so that
   cookies survive one rotation.  The reply is always smaller than the
   ClientHello that provoked it, so the server is no amplifier.

   Limits, both consequences of statelessness: ClientHello1 must arrive in
   one datagram (gq_dtls clients send a small one for this reason), and
   in ClientHello2 the cookie extension must lie within its first fragment
   (gq_dtls clients place it first).  A ClientHello that breaks either is
   dropped.  A ticket for a suite other than the one this listener picks
   cannot resume behind the exchange; a full handshake follows.  */

#ifndef GNUQUIC_DTLSCOOKIE_H
#define GNUQUIC_DTLSCOOKIE_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/tls.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_dtls_cookies gq_dtls_cookies;

/* A ring with one random current secret.  */
int gq_dtls_cookies_new (gq_dtls_cookies **out);
void gq_dtls_cookies_free (gq_dtls_cookies *ck);

/* Start using a new random secret; the previous one still verifies.  Call
   it every minute or so.  */
int gq_dtls_cookies_rotate (gq_dtls_cookies *ck);

/* Install secrets chosen by the caller (to share between servers behind
   one address).  PREVIOUS may be NULL.  */
int gq_dtls_cookies_set (gq_dtls_cookies *ck, const uint8_t current[32],
                         const uint8_t previous[32]);

enum gq_dtls_listen_result
{
  GQ_DTLS_LISTEN_DROP = 0,
  GQ_DTLS_LISTEN_REPLY,
  GQ_DTLS_LISTEN_ACCEPT
};

/* BINDING identifies the source address (for example the sockaddr bytes,
   or address and port in network order).  REPLY needs at least
   GQ_DTLS_LISTEN_REPLY_MAX bytes.  PRIME is filled for ACCEPT.
   CONFIG supplies the suite and group preferences the retry will
   apply, the same ones the association will use.  Returns the result, or
   a negative status for bad arguments.  */
#define GQ_DTLS_LISTEN_REPLY_MAX 512
int gq_dtls_listen (gq_dtls_cookies *ck, const gq_tls_server_config *config,
                    const uint8_t *binding, size_t binding_len,
                    const uint8_t *dgram, size_t len, uint8_t *reply,
                    size_t reply_cap, size_t *reply_len,
                    gq_tls_dtls_prime *prime);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_DTLSCOOKIE_H */
