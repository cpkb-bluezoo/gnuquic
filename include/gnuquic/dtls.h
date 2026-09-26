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

/* DTLS 1.3 (RFC 9147): one association over datagrams.

   gq_dtls joins the TLS 1.3 handshake engine (tls.h, in DTLS mode) to
   the DTLS record layer (dtlsrec.h), handshake fragmentation and
   reassembly and ACKs (dtlshs.h).  Like the other engines it owns no
   socket, thread or timer.  The application

     - gives it each received datagram (gq_dtls_receive) and is called
       back with each datagram to transmit (events.send);
     - gives it the current time with every call, and asks
       gq_dtls_deadline when to call gq_dtls_timeout;
     - sends application data with gq_dtls_send (one record per call: DTLS
       preserves message boundaries) and receives it through events.data.

   Reliability of the handshake follows RFC 9147 section 5.8: the last
   flight is kept, split into fragments that fit the MTU, and resent with
   exponential backoff (1 s doubling to 60 s by default) until it is
   acknowledged, either by the ACK content type (section 7) or implicitly
   by the peer's reply.  Fragments already acknowledged are not resent.
   Receipt is acknowledged when a flight is incomplete or out of order,
   and always for the final flight of the handshake, NewSessionTicket and
   KeyUpdate.  Post-handshake messages travel in the same machinery.
   KeyUpdate moves both directions to the next epoch; the sender switches
   only after its KeyUpdate is acknowledged (section 8).

   What is not implemented, by design (see the manual): 0-RTT, connection
   IDs, post-handshake client authentication.

   A server should sit behind gq_dtls_listen (dtlscookie.h), which answers
   ClientHellos statelessly with an address-bound cookie, so that no
   association exists for an unverified source.  */

#ifndef GNUQUIC_DTLS_H
#define GNUQUIC_DTLS_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/tls.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Tunables; zero selects the default in parentheses.  */
typedef struct gq_dtls_params
{
  unsigned mtu;			/* Largest datagram we send (1200).  */
  unsigned rto_ms;		/* Initial retransmit timeout (1000).  */
  unsigned max_rto_ms;		/* Backoff ceiling (60000).  */
  unsigned max_retransmits;	/* Then GQ_ERR_TIMEOUT (6).  */
  uint64_t rekey_records;	/* Send KeyUpdate after this many records
				   in one epoch (GQ_DTLS_REKEY_ADVISED).  */
} gq_dtls_params;

typedef struct gq_dtls_events
{
  void *user;
  /* A datagram to transmit.  Required.  Nonzero aborts the association.  */
  int (*send) (void *user, const uint8_t *dgram, size_t len);
  /* Decrypted application data, one call per record.  Required.  */
  int (*data) (void *user, const uint8_t *data, size_t len);
  /* The handshake completed.  */
  int (*connected) (void *user, const gq_tls_info *info);
  /* A session ticket arrived (client).  */
  int (*ticket) (void *user, const gq_tls_ticket *ticket);
  /* Certificate validation; replaces the trust store check (tls.h).  */
  int (*verify_peer) (void *user, const gq_slice *chain, size_t n,
                      const char *server_name);
  /* The association ended.  ERROR is 0 for close_notify, else a negative
     status; ALERT is the TLS alert involved, or -1.  */
  void (*closed) (void *user, int error, int alert);
} gq_dtls_events;

typedef struct gq_dtls gq_dtls;

/* PARAMS may be NULL.  The configurations are those of tls.h; the dtls
   field is set here.  early_data and QUIC settings are refused.  */
int gq_dtls_client_new (gq_dtls **out, const gq_tls_config *config,
                       const gq_dtls_events *events,
                       const gq_dtls_params *params);

/* PRIME, if not NULL, continues a handshake whose first ClientHello was
   answered statelessly by gq_dtls_listen; the ClientHello2 datagram is
   then given to gq_dtls_receive as usual.  */
int gq_dtls_server_new (gq_dtls **out, const gq_tls_server_config *config,
                        const gq_dtls_events *events,
                        const gq_dtls_params *params,
                        const gq_tls_dtls_prime *prime);

void gq_dtls_free (gq_dtls *c);

/* Client: send the ClientHello.  NOW is milliseconds on any monotonic
   clock the caller keeps; use the same clock in every call.  */
int gq_dtls_start (gq_dtls *c, uint64_t now);

/* Process one received datagram.  Returns GQ_OK or the negative status the
   association closed with.  Records that cannot be authenticated or
   parsed are dropped silently (RFC 9147 section 4.5.2).  */
int gq_dtls_receive (gq_dtls *c, const uint8_t *dgram, size_t len,
                     uint64_t now);

/* Send LEN bytes as one record.  GQ_ERR_BUFSIZE if more than
   gq_dtls_max_payload.  Only after the connected event.  */
int gq_dtls_send (gq_dtls *c, const uint8_t *data, size_t len);
size_t gq_dtls_max_payload (const gq_dtls *c);

/* Update our sending keys (and ask the peer to update its too if
   REQUEST_PEER).  GQ_ERR_INVAL if an update is still unacknowledged.  Done
   automatically before the record limit.  */
int gq_dtls_key_update (gq_dtls *c, int request_peer);

/* Send close_notify (unreliable, like every alert) and close.  */
int gq_dtls_close (gq_dtls *c);

/* When the next timer fires, on the caller's clock; 0 if none is set.  */
uint64_t gq_dtls_deadline (const gq_dtls *c);

/* Run whatever timers are due at NOW: retransmit, or send a delayed ACK.
   Returns GQ_OK, or GQ_ERR_TIMEOUT once the retransmissions are used up
   (the association is then closed).  */
int gq_dtls_timeout (gq_dtls *c, uint64_t now);

int gq_dtls_is_connected (const gq_dtls *c);
int gq_dtls_is_closed (const gq_dtls *c);

/* Keying material exporter (RFC 5705, with the "dtls13" labels).  */
int gq_dtls_export (const gq_dtls *c, const char *label,
                    const uint8_t *context, size_t context_len, uint8_t *out,
                    size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_DTLS_H */
