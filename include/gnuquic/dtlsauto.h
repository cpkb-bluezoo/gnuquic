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

/* DTLS that negotiates the protocol version itself: one port serves DTLS
   1.3 and DTLS 1.2, preferring 1.3 (the counterpart of tlsauto.h).

   Server side, statelessly first: gq_dtlsauto_listen looks at a first
   datagram from an address with no association, decides from the
   ClientHello which version it is for (supported_versions; a cookie
   already in the hello names the exchange it answers: a legacy_cookie is a
   DTLS 1.2 HelloVerifyRequest cookie, a cookie extension a DTLS 1.3
   HelloRetryRequest cookie) and hands the datagram to gq_dtls_listen or
   gq_dtls12_listen.  The association then starts with
   gq_dtlsauto_server_new and the prime it filled in.  Without a listener,
   gq_dtlsauto_server_new collects the ClientHello itself from the first
   datagrams and decides.

   Client side: the DTLS 1.3 engine sends a hello that offers both versions
   (a small one, so that a stateless listener can answer it) and the client
   continues with whichever the server chose: a HelloVerifyRequest or a
   ServerHello without supported_versions means DTLS 1.2, and the DTLS 1.2
   engine takes over from that hello, sends its cookie reply with the same
   hello, and refuses the downgrade sentinel (RFC 8446 section 4.1.3).

   As in tlsauto.h nothing about either engine is relaxed; VERSIONS pins one
   of them (0 means both) for deployments that keep a port per version, and a
   peer that offers nothing acceptable is refused.  The version is decided
   once and never revisited: there is no renegotiation.  The events and
   parameters are dtls.h's.  A server that also serves DTLS 1.3 marks its
   DTLS 1.2 ServerHello with the downgrade sentinel.  */

#ifndef GNUQUIC_DTLSAUTO_H
#define GNUQUIC_DTLSAUTO_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/dtls.h>
#include <gnuquic/dtls12.h>
#include <gnuquic/dtlscookie.h>
#include <gnuquic/tlsauto.h>	/* GQ_TLSAUTO_TLS12, GQ_TLSAUTO_TLS13 */

#ifdef __cplusplus
extern "C" {
#endif

/* The same flags select the DTLS versions.  */
#define GQ_DTLSAUTO_DTLS12 GQ_TLSAUTO_TLS12
#define GQ_DTLSAUTO_DTLS13 GQ_TLSAUTO_TLS13

typedef struct gq_dtlsauto gq_dtlsauto;

typedef struct gq_dtlsauto_prime
{
  unsigned version;		/* 0xfefc or 0xfefd.  */
  gq_tls_dtls_prime p13;
  gq_dtls12_prime p12;
} gq_dtlsauto_prime;

/* As gq_dtls_listen and gq_dtls12_listen (whose results it returns), for a
   listener that serves VERSIONS.  PRIME is filled for ACCEPT.  ClientHello1
   must arrive in one datagram when both versions are served, as
   gq_dtls_listen requires.  */
int gq_dtlsauto_listen (gq_dtls_cookies *ck,
                        const gq_tls_server_config *config, unsigned versions,
                        const uint8_t *binding, size_t binding_len,
                        const uint8_t *dgram, size_t len, uint8_t *reply,
                        size_t reply_cap, size_t *reply_len,
                        gq_dtlsauto_prime *prime);

/* PRIME (from gq_dtlsauto_listen) may be NULL, when the version is decided
   from the first datagrams instead.  */
int gq_dtlsauto_server_new (gq_dtlsauto **out,
                            const gq_tls_server_config *config,
                            const gq_dtls_events *events,
                            const gq_dtls_params *params, unsigned versions,
                            const gq_dtlsauto_prime *prime);
int gq_dtlsauto_client_new (gq_dtlsauto **out, const gq_tls_config *config,
                            const gq_dtls_events *events,
                            const gq_dtls_params *params, unsigned versions);
void gq_dtlsauto_free (gq_dtlsauto *c);

int gq_dtlsauto_start (gq_dtlsauto *c, uint64_t now);
int gq_dtlsauto_receive (gq_dtlsauto *c, const uint8_t *dgram, size_t len,
                         uint64_t now);
int gq_dtlsauto_send (gq_dtlsauto *c, const uint8_t *data, size_t len);
size_t gq_dtlsauto_max_payload (const gq_dtlsauto *c);
/* DTLS 1.3 only; GQ_ERR_UNSUPPORTED for DTLS 1.2 and while undecided.  */
int gq_dtlsauto_key_update (gq_dtlsauto *c, int request_peer);
int gq_dtlsauto_close (gq_dtlsauto *c);
uint64_t gq_dtlsauto_deadline (const gq_dtlsauto *c);
int gq_dtlsauto_timeout (gq_dtlsauto *c, uint64_t now);
int gq_dtlsauto_is_connected (const gq_dtlsauto *c);
int gq_dtlsauto_is_closed (const gq_dtlsauto *c);
int gq_dtlsauto_export (const gq_dtlsauto *c, const char *label,
                        const uint8_t *context, size_t context_len,
                        uint8_t *out, size_t out_len);

/* 0xfefc (DTLS 1.3) or 0xfefd (DTLS 1.2); 0 while undecided.  */
unsigned gq_dtlsauto_version (const gq_dtlsauto *c);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_DTLSAUTO_H */
