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

/* TLS 1.3 over a byte stream: the handshake engine (tls.h) joined to the
   record layer (record.h).

   Like everything else here it does no I/O.  The transport hands it the
   bytes it reads from the socket with gq_tlsconn_receive, and the
   connection calls back with the bytes to write.  All callbacks are
   invoked synchronously from inside the call that caused them.

   What it does for you:
     - fragments handshake messages and application data into records;
     - keeps the record layer's keys in step with the handshake (including
       the compatibility ChangeCipherSpec before the first encrypted
       record);
     - delivers decrypted application data;
     - answers a peer's close_notify with our own;
     - sends the right fatal alert when the engine or the record layer
       fails;
     - rekeys the sending direction before the AEAD record limit.

   Threading: one connection is used from one thread at a time.  */

#ifndef GNUQUIC_TLSCONN_H
#define GNUQUIC_TLSCONN_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/tls.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_tlsconn_events
{
  void *user;
  /* Bytes to write to the transport.  Required.  Return nonzero on
     failure, which fails the connection.  */
  int (*write) (void *user, const uint8_t *data, size_t len);
  /* Decrypted application data.  Required.  */
  int (*data) (void *user, const uint8_t *data, size_t len);
  /* The handshake completed.  */
  int (*connected) (void *user, const gq_tls_info *info);
  /* A session ticket arrived.  */
  int (*ticket) (void *user, const gq_tls_ticket *ticket);
  /* Server: 0-RTT data from the client.  It arrives before the handshake
     is complete and can be replayed by an attacker, so the callback is
     separate from data.  If this is NULL the server accepts no early
     data at all.  */
  int (*early_data) (void *user, const uint8_t *data, size_t len);
  /* Client: the server accepted (1) or rejected (0) our early data.  On
     rejection, resend everything sent early once connected.  */
  void (*early_data_result) (void *user, int accepted);
  /* The connection ended.  ERROR is 0 for an orderly close_notify from the
     peer, otherwise a negative status; ALERT is the alert received or
     sent, or -1.  Called at most once.  */
  void (*closed) (void *user, int error, int alert);
  /* Rekey our sending keys after this many records (0: 2^22).  */
  uint64_t rekey_records;
} gq_tlsconn_events;

typedef struct gq_tlsconn gq_tlsconn;

/* Create a client connection.  CONFIG must not select QUIC.  Pointers in
   CONFIG follow the ownership rules of gq_tls.  */
int gq_tlsconn_client_new (gq_tlsconn **out, const gq_tls_config *config,
                           const gq_tlsconn_events *events);

/* Create a server connection.  It waits for the client's ClientHello;
   gq_tlsconn_start is a no-op.  CONFIG must not select QUIC.  */
int gq_tlsconn_server_new (gq_tlsconn **out,
                           const gq_tls_server_config *config,
                           const gq_tlsconn_events *events);
void gq_tlsconn_free (gq_tlsconn *c);

/* Send the ClientHello (clients only).  */
int gq_tlsconn_start (gq_tlsconn *c);

/* Feed bytes read from the transport.  All of them are consumed; a
   partial record is held internally.  Returns GQ_OK or a negative status
   after which the connection is closed.  */
int gq_tlsconn_receive (gq_tlsconn *c, const uint8_t *data, size_t len);

/* Send application data (allowed once connected).  */
int gq_tlsconn_send (gq_tlsconn *c, const uint8_t *data, size_t len);

/* Client: send 0-RTT data.  Allowed after gq_tlsconn_start when the
   configuration offered early data with a session that permits it (the
   engine then installs the early write keys), and until the handshake
   completes.  The total is limited by the session's max_early_data
   (GQ_ERR_RANGE).  Returns GQ_ERR_INVAL if early data is not in play.  */
int gq_tlsconn_send_early (gq_tlsconn *c, const uint8_t *data, size_t len);

/* Ask for a key update of our sending keys, and optionally the peer's.  */
int gq_tlsconn_key_update (gq_tlsconn *c, int request_peer);

/* Send close_notify.  The connection can still receive until the peer's
   close_notify arrives.  */
int gq_tlsconn_close (gq_tlsconn *c);

int gq_tlsconn_is_connected (const gq_tlsconn *c);
int gq_tlsconn_is_closed (const gq_tlsconn *c);

/* Records protected in each direction since the last key change; mostly
   for tests.  */
uint64_t gq_tlsconn_write_seq (const gq_tlsconn *c);
uint64_t gq_tlsconn_read_seq (const gq_tlsconn *c);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TLSCONN_H */
