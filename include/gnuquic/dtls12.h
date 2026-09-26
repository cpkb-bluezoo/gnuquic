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

/* DTLS 1.2 (RFC 6347): one association over datagrams.

   The counterpart of dtls.h for DTLS 1.2, with the same interface (the
   event and parameter structures are dtls.h's): the application feeds
   received datagrams and the clock, and is called back with datagrams to
   send and with decrypted application data.  Inside, it joins the TLS 1.2
   engine of tls12.h in DTLS mode to the record layer of dtls12rec.h and
   the handshake fragmentation and reassembly of dtlshs.h.

   The security profile is that of TLS 1.2 here (tls12.h): ECDHE on
   secp256r1 with AEAD suites, mandatory extended master secret and secure
   renegotiation indication, RFC 5077 tickets only, no renegotiation.
   There is no rekeying in DTLS 1.2: an AES-GCM direction that reaches
   2^24 records closes the association.

   Reliability follows RFC 6347 section 4.2.4, which is simpler than
   DTLS 1.3's: the last flight is kept and, on a timer (1 s doubling to
   60 s, six retries by default), sent again in full with fresh record
   numbers and the same epoch.  A flight is acknowledged implicitly by the
   peer's next flight.  The final flight of the handshake has no reply, so
   it is kept without a timer and sent again only when the peer repeats
   its own last flight (its Finished, say), which shows the final flight
   was lost.  A ChangeCipherSpec that overtakes the message before it is
   held until the engine can take it.

   Address validation: run gq_dtls12_listen (dtls12cookie.h) in front of
   servers; the HelloVerifyRequest cookie exchange is then stateless.  A
   client answers a HelloVerifyRequest by itself.  */

#ifndef GNUQUIC_DTLS12_H
#define GNUQUIC_DTLS12_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/tls12.h>
#include <gnuquic/dtls.h>	/* gq_dtls_events, gq_dtls_params */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_dtls12 gq_dtls12;

/* What a server that answered ClientHello1 with a HelloVerifyRequest
   statelessly needs to continue: the next plaintext record number (the
   ClientHello2 record's plus one).  */
typedef struct gq_dtls12_prime
{
  uint64_t e0_seq;
} gq_dtls12_prime;

/* The configurations are tls.h's; the dtls field is set here and QUIC and
   early data are refused.  PARAMS may be NULL (rekey_records is ignored).  */
int gq_dtls12_client_new (gq_dtls12 **out, const gq_tls_config *config,
                          const gq_dtls_events *events,
                          const gq_dtls_params *params);

/* PRIME, if not NULL, comes from gq_dtls12_listen; the ClientHello2
   datagram is then given to gq_dtls12_receive as usual.  */
int gq_dtls12_server_new (gq_dtls12 **out, const gq_tls_server_config *config,
                          const gq_dtls_events *events,
                          const gq_dtls_params *params,
                          const gq_dtls12_prime *prime);

void gq_dtls12_free (gq_dtls12 *c);

/* Client: send the ClientHello.  NOW is milliseconds on any monotonic
   clock the caller keeps.  */
int gq_dtls12_start (gq_dtls12 *c, uint64_t now);

/* Client, instead of gq_dtls12_start: continue from a combined ClientHello
   (DTLS 1.3 and 1.2 both on offer) that a DTLS 1.3 association already sent
   as the record numbered NEXT_SEQ - 1.  HELLO is the handshake message
   (4 byte header).  The hello counts as sent: it is kept as the flight to
   repeat, and a HelloVerifyRequest is answered with the same hello and a
   cookie.  As the client offered DTLS 1.3 it refuses a ServerHello with the
   downgrade sentinel (see gq_tls12_client_adopt).  */
int gq_dtls12_client_adopt (gq_dtls12 *c, const uint8_t *hello, size_t len,
                            uint64_t next_seq, uint64_t now);

/* Process one received datagram.  Invalid records are dropped silently
   (RFC 6347 section 4.1.2.7).  Returns GQ_OK or the negative status the
   association closed with.  */
int gq_dtls12_receive (gq_dtls12 *c, const uint8_t *dgram, size_t len,
                       uint64_t now);

/* Send LEN bytes as one record; GQ_ERR_BUFSIZE if more than
   gq_dtls12_max_payload.  Only after the connected event.  */
int gq_dtls12_send (gq_dtls12 *c, const uint8_t *data, size_t len);
size_t gq_dtls12_max_payload (const gq_dtls12 *c);

/* Send close_notify (unreliable) and close.  */
int gq_dtls12_close (gq_dtls12 *c);

/* When the next timer fires; 0 if none.  */
uint64_t gq_dtls12_deadline (const gq_dtls12 *c);
int gq_dtls12_timeout (gq_dtls12 *c, uint64_t now);

int gq_dtls12_is_connected (const gq_dtls12 *c);
int gq_dtls12_is_closed (const gq_dtls12 *c);

int gq_dtls12_export (const gq_dtls12 *c, const char *label,
                      const uint8_t *context, size_t context_len,
                      uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_DTLS12_H */
