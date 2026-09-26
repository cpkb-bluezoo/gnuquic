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

/* TLS 1.2 handshake engine (RFC 5246, RFC 8422, RFC 5077, RFC 7627,
   RFC 5746, RFC 7905, RFC 7301).

   A separate state machine from the TLS 1.3 engine in tls.h, in the same
   reactive style: it owns no socket, thread or timer, performs no I/O,
   and reports what to do through the callbacks of a gq_tls12_sink, all
   invoked synchronously from inside gq_tls12_start, gq_tls12_feed and
   gq_tls12_change_cipher_spec.  The configuration structures are the ones
   of tls.h (gq_tls_config, gq_tls_server_config); fields that only make
   sense for TLS 1.3 or QUIC (transport parameters, early data, ticket
   counts, HelloRetryRequest cookies, group lists) are refused or ignored
   as documented in each.

   The profile is deliberately narrow, the same as Gumdrop's and Hopf's
   (see the manual's "TLS 1.2 hardening" section):

     key exchange  ECDHE on secp256r1 only; no static RSA, no
                   finite-field DH, no other curve
     suites        ECDHE_ECDSA and ECDHE_RSA with AES-GCM or
                   ChaCha20-Poly1305; no CBC, RC4, 3DES, CCM
     signatures    ECDSA (P-256, P-384) and RSA PKCS#1 v1.5 with SHA-2 are
                   made; RSA-PSS is also accepted from peers; no SHA-1, no
                   Ed25519
     master secret extended (RFC 7627), mandatory: a peer that does not
                   offer or echo it is refused
     renegotiation never; the indication of RFC 5746 is mandatory and any
                   later handshake message is fatal
     compression   none
     resumption    RFC 5077 stateless tickets only, no session IDs

   Transport: the caller carries the bytes.  Handshake bytes come out of
   the sink's send callback and must be framed as handshake records in the
   current write state; the change_keys callback asks for a
   ChangeCipherSpec record and a switch of write keys (or installs read
   keys), which is what gq_tls12conn does with gq_record12.

   The engine sends one alert (sink->alert) when it fails, returns a
   negative status and refuses all further input.

   Ownership as in tls.h: the configuration is copied shallowly, its
   pointers must outlive the engine, and slices handed to callbacks are
   valid only during the callback.  */

#ifndef GNUQUIC_TLS12_H
#define GNUQUIC_TLS12_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/tls.h>
#include <gnuquic/tls12ks.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_tls12_sink
{
  void *user;
  /* Complete handshake messages to send in the current write state.
     Required.  */
  int (*send) (void *user, const uint8_t *data, size_t len);
  /* Required.  DIR is GQ_DIR_WRITE: send a ChangeCipherSpec record now,
     then protect everything after it with these keys.  DIR is
     GQ_DIR_READ: the peer's ChangeCipherSpec was accepted; decrypt
     everything after it with these keys.  IV is the implicit nonce part
     (4 bytes for AES-GCM, 12 for ChaCha20-Poly1305).  */
  int (*change_keys) (void *user, enum gq_dir dir, enum gq_aead aead,
                      const uint8_t *key, size_t key_len, const uint8_t *iv,
                      size_t iv_len);
  /* As gq_tls_sink.verify_peer.  */
  int (*verify_peer) (void *user, const gq_slice *chain, size_t n,
                      const char *server_name);
  /* Client: an RFC 5077 ticket, delivered once the handshake has
     completed.  gq_tls_ticket.psk holds the 48-byte master secret;
     store it with gq_tls_session_store and offer it through
     gq_tls_config.resume.  */
  int (*ticket) (void *user, const gq_tls_ticket *ticket);
  int (*complete) (void *user, const gq_tls_info *info);
  /* The engine is about to fail with this alert.  */
  int (*alert) (void *user, unsigned code);
} gq_tls12_sink;

typedef struct gq_tls12 gq_tls12;

/* Client.  Requires config->trust or sink->verify_peer.  Refuses QUIC
   mode and early data.  config->groups is ignored (secp256r1 only);
   suites and sigschemes are filtered to the TLS 1.2 policy.  If
   config->resume holds a TLS 1.2 session it is offered.  */
int gq_tls12_client_new (gq_tls12 **out, const gq_tls_config *config,
                         const gq_tls12_sink *sink);

/* Server.  Credentials must be RSA or ECDSA (P-256 or P-384) keys.  The
   server config's groups, max_early_data, n_tickets, replay and
   HelloRetryRequest fields are ignored; one ticket is issued per full
   handshake when ticket_keys is set, and none on resumption.  */
int gq_tls12_server_new (gq_tls12 **out, const gq_tls_server_config *config,
                         const gq_tls12_sink *sink);

void gq_tls12_free (gq_tls12 *tls);

/* Client: build and send the ClientHello.  */
int gq_tls12_start (gq_tls12 *tls);

/* For a combined ClientHello (gq_tlsauto): the cipher suites and signature
   schemes a TLS 1.2 client with CFG would offer, after policy filtering.
   Arrays of at least 16 entries.  */
int gq_tls12_client_offer (const gq_tls_config *cfg, uint16_t *suites,
                           size_t *n_suites, uint16_t *sigs, size_t *n_sigs);

/* Client, instead of gq_tls12_start: continue from a ClientHello that a TLS
   1.3 engine already built and sent (HELLO, the handshake message, LEN bytes)
   with both versions on offer.  The engine takes over at the ServerHello, and
   as the client offered TLS 1.3 it refuses a ServerHello carrying the
   downgrade sentinel (RFC 8446 section 4.1.3).  */
int gq_tls12_client_adopt (gq_tls12 *tls, const uint8_t *hello, size_t len);

/* DTLS 1.2 (RFC 6347), used by gq_dtls12: with dtls set in the
   configuration the engine speaks version 0xfefd, keeps the transcript in
   DTLS form (12-byte handshake headers with message_seq), follows a
   HelloVerifyRequest on the client and expects its messages in message_seq
   order, one at a time.  Server side: after the ClientHello1 exchange was
   answered statelessly (dtls12cookie.h) ClientHello2 arrives as message
   RX_SEQ and the first message we send is TX_SEQ (both 1).  Must precede
   the first gq_tls12_feed.  */
int gq_tls12_dtls_prime (gq_tls12 *tls, uint16_t rx_seq, uint16_t tx_seq);

/* Nonzero when the next thing the engine can accept is the peer's
   ChangeCipherSpec (DTLS may deliver it early; the caller then waits).  */
int gq_tls12_expects_ccs (const gq_tls12 *tls);

/* Feed the payload of received handshake records.  Consumes the whole
   buffer (a partial message is held, bounded by max_message_len).  */
int gq_tls12_feed (gq_tls12 *tls, const uint8_t **buf, size_t *len);

/* The peer's ChangeCipherSpec record arrived.  Fails the engine if it is
   not expected here or splits a handshake message.  */
int gq_tls12_change_cipher_spec (gq_tls12 *tls);

int gq_tls12_is_complete (const gq_tls12 *tls);
int gq_tls12_is_failed (const gq_tls12 *tls);

/* The alert the engine failed with, or -1.  */
int gq_tls12_alert (const gq_tls12 *tls);

/* Keying material exporter (RFC 5705).  Valid once complete.  */
int gq_tls12_export (const gq_tls12 *tls, const char *label,
                     const uint8_t *context, size_t context_len,
                     uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TLS12_H */
