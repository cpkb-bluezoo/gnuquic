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

/* TLS over a byte stream that negotiates the protocol version itself.

   gq_tlsconn (TLS 1.3) and gq_tls12conn (TLS 1.2) are separate engines with
   their own security profiles.  This module puts a thin front on them so a
   single listener can serve both: it reads the client's first flight, looks
   at supported_versions, hands the connection to the engine that fits and
   replays the bytes.  Nothing about either engine is relaxed: a client that
   ends up in TLS 1.2 gets the TLS 1.2 hardening profile (ECDHE and AEAD
   suites only, extended master secret, secure renegotiation indication), a
   client that offers TLS 1.3 always gets TLS 1.3, and because one endpoint
   then serves both, the TLS 1.2 ServerHello carries the downgrade sentinel of
   RFC 8446 section 4.1.3.

   The configuration and events are those of the engines (tls.h,
   tlsconn.h): each engine uses the parts that apply to it and ignores the
   rest, so one configuration serves both.  Restrict the versions with
   VERSIONS if you want only one; a client that offers nothing acceptable is
   refused with protocol_version by the engine that would have served it.

   The client side offers both versions in one ClientHello and continues with
   whichever the server selects, checking the downgrade sentinel.  */

#ifndef GNUQUIC_TLSAUTO_H
#define GNUQUIC_TLSAUTO_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/tlsconn.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Which protocol versions an endpoint may speak (0 means both).  */
#define GQ_TLSAUTO_TLS12 1
#define GQ_TLSAUTO_TLS13 2

typedef struct gq_tlsauto gq_tlsauto;

int gq_tlsauto_server_new (gq_tlsauto **out,
                           const gq_tls_server_config *config,
                           const gq_tlsconn_events *events,
                           unsigned versions);
int gq_tlsauto_client_new (gq_tlsauto **out, const gq_tls_config *config,
                           const gq_tlsconn_events *events, unsigned versions);
void gq_tlsauto_free (gq_tlsauto *c);

/* Client: send the ClientHello.  A no-op for servers.  */
int gq_tlsauto_start (gq_tlsauto *c);

/* As gq_tlsconn_receive: feed bytes from the transport in any chunking.  */
int gq_tlsauto_receive (gq_tlsauto *c, const uint8_t *data, size_t len);
int gq_tlsauto_send (gq_tlsauto *c, const uint8_t *data, size_t len);
int gq_tlsauto_close (gq_tlsauto *c);
int gq_tlsauto_is_connected (const gq_tlsauto *c);
int gq_tlsauto_is_closed (const gq_tlsauto *c);
/* Ask for a key update of our sending keys (TLS 1.3 only: GQ_ERR_UNSUPPORTED
   for TLS 1.2 and while the version is undecided).  */
int gq_tlsauto_key_update (gq_tlsauto *c, int request_peer);

/* Keying material exporter (RFC 5705), for TLS 1.2 connections; GQ_ERR_UNSUPPORTED
   for TLS 1.3 (gq_tlsconn has none).  */
int gq_tlsauto_export (const gq_tlsauto *c, const char *label,
                       const uint8_t *context, size_t context_len,
                       uint8_t *out, size_t out_len);

/* The version in use: 0x0304 or 0x0303, or 0 while it is undecided.  */
unsigned gq_tlsauto_version (const gq_tlsauto *c);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TLSAUTO_H */
