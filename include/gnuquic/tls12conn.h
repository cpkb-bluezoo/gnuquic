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

/* TLS 1.2 over a byte stream: the engine of tls12.h plus the record layer
   of record12.h, for TCP and STARTTLS.  The counterpart of tlsconn.h and
   used the same way: one connection object per transport, fed with the
   bytes that arrive, calling back with bytes to write and with decrypted
   application data.

   The event structure is gq_tlsconn_events from tlsconn.h; the early_data
   and early_data_result members do not apply (TLS 1.2 has no 0-RTT) and
   are ignored.  TLS 1.2 has no KeyUpdate, so when an AES-GCM direction
   reaches the record limit (GQ_REC12_SEQ_LIMIT) the connection sends
   close_notify and closes with GQ_ERR_RANGE.  A nonzero rekey_records
   lowers that limit (mainly for tests).

   Version pinning: an endpoint is either a TLS 1.3 endpoint (gq_tlsconn)
   or a TLS 1.2 endpoint (this), never both.  A TLS 1.2 server refuses a
   ClientHello that does not offer TLS 1.2 with protocol_version; to serve
   both, run two listeners.  */

#ifndef GNUQUIC_TLS12CONN_H
#define GNUQUIC_TLS12CONN_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/tls12.h>
#include <gnuquic/tlsconn.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_tls12conn gq_tls12conn;

/* Creation follows tls12.h: gq_tls12_client_new and gq_tls12_server_new
   for what the configurations may contain.  */
int gq_tls12conn_client_new (gq_tls12conn **out, const gq_tls_config *config,
                             const gq_tlsconn_events *events);
int gq_tls12conn_server_new (gq_tls12conn **out,
                             const gq_tls_server_config *config,
                             const gq_tlsconn_events *events);
void gq_tls12conn_free (gq_tls12conn *c);

/* Client: send the ClientHello.  A no-op for servers.  */
int gq_tls12conn_start (gq_tls12conn *c);

/* Feed bytes from the transport, in any chunking.  Returns GQ_OK, or the
   negative status the connection closed with.  */
int gq_tls12conn_receive (gq_tls12conn *c, const uint8_t *data, size_t len);

/* Send application data (after the connected callback).  */
int gq_tls12conn_send (gq_tls12conn *c, const uint8_t *data, size_t len);

/* Send close_notify.  The connection closes when the peer's arrives.  */
int gq_tls12conn_close (gq_tls12conn *c);

int gq_tls12conn_is_connected (const gq_tls12conn *c);
int gq_tls12conn_is_closed (const gq_tls12conn *c);

/* Keying material exporter (RFC 5705), once connected.  */
int gq_tls12conn_export (const gq_tls12conn *c, const char *label,
                         const uint8_t *context, size_t context_len,
                         uint8_t *out, size_t out_len);

uint64_t gq_tls12conn_write_seq (const gq_tls12conn *c);
uint64_t gq_tls12conn_read_seq (const gq_tls12conn *c);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TLS12CONN_H */
