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

/* QUIC endpoint: many connections behind one UDP socket.

   Like the connection, the endpoint owns no socket, thread or timer.  The
   caller feeds it every datagram that arrives (gq_endpoint_recv), asks
   for datagrams to transmit (gq_endpoint_send, until it yields none) and
   calls gq_endpoint_on_timeout when gq_endpoint_timeout says so.  What
   it does in between:

     - routes each datagram to its connection by destination connection
       ID (a hash table over the IDs the connections issue);
     - admits new client connections (gq_quic_admit): Version Negotiation,
       Retry (always, or once the endpoint is busy) and token checking,
       then creates the server connection;
     - answers datagrams for unknown connections with a stateless reset,
       its tokens derived from a key so it can do so after state loss, and
       rate limited;
     - remembers which connections have something to send and which have
       timers, so the cost of an idle connection is nil;
     - frees connections when they are done.

   An endpoint can serve, connect or both.  Connections it creates belong
   to it: never call gq_conn_free on them.  All connections of an endpoint
   use the same connection ID length.  */

#ifndef GNUQUIC_ENDPOINT_H
#define GNUQUIC_ENDPOINT_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/conn.h>
#include <gnuquic/listen.h>
#include <gnuquic/replay.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_endpoint gq_endpoint;

typedef struct gq_endpoint_events
{
  void *user;
  /* A client's first Initial passed admission.  Fill EVENTS with the event
     callbacks (and user pointer) of the connection about to be created;
     return nonzero to refuse it (the datagram is dropped).  Required
     for a serving endpoint.  */
  int (*accept) (void *user, const gq_path *from, gq_conn_events *events);
  /* A connection was created, by accept or gq_endpoint_connect.  Optional.  */
  void (*connection) (void *user, gq_conn *conn);
  /* The connection has finished (its closing period is over, or it timed
     out or was reset) and is freed when this returns.  Optional.  */
  void (*done) (void *user, gq_conn *conn);
} gq_endpoint_events;

typedef struct gq_endpoint_config
{
  /* Defaults for every connection (versions, limits, connection ID length,
     wall clock).  The reset_token hook is the endpoint's.  */
  gq_conn_config conn;
  /* Serve with this TLS configuration (must outlive the endpoint); NULL for
     an endpoint that only connects.  */
  const gq_tls_server_config *server;
  gq_admit_config admit;
  size_t max_connections;	/* 0: 1024.  Beyond it Initials are dropped.  */
  /* Ask for a Retry once this many connections exist (0: only if
     admit.require_retry).  */
  size_t retry_above;
  /* Session tickets and 0-RTT for the server.  TICKETS makes the endpoint
     keep a ticket key ring (unless the TLS configuration has one) so
     clients can resume; EARLY_DATA also accepts early data from them, once
     per ticket (RFC 8446 section 8.1: the endpoint keeps a replay cache of
     REPLAY_CAPACITY tickets, 0: 65536, which is fine for one process; a
     cluster must share its own through the TLS configuration).  */
  int tickets, early_data;
  size_t replay_capacity;
  unsigned max_resets_per_second;	/* 0: 100.  */
  int no_stateless_reset;
  /* Key the stateless reset tokens derive from.  If not given a random one
     is used, so tokens do not survive a restart; set it (and keep it the
     same across restarts or servers behind one address) to make them.  */
  uint8_t reset_key[32];
  int have_reset_key;
} gq_endpoint_config;

int gq_endpoint_new (gq_endpoint **out, const gq_endpoint_config *config,
                     const gq_endpoint_events *events);

/* Closes nothing politely: connections are freed where they stand.  Call
   gq_endpoint_close first and drain if that matters.  */
void gq_endpoint_free (gq_endpoint *ep);

/* Start a client connection.  CONN overrides the endpoint's connection
   defaults (NULL keeps them; its connection ID length is ignored).  PATH is
   where the server is (may be NULL if the first datagram received defines
   it).  The ClientHello is queued: call gq_endpoint_send.  */
int gq_endpoint_connect (gq_endpoint *ep, uint64_t now_us,
                         const gq_tls_config *tls, const gq_conn_config *conn,
                         const gq_path *path, const gq_conn_events *events,
                         gq_conn **out);

/* A datagram arrived on FROM (it is modified: packets are decrypted in
   place).  Returns GQ_OK whatever became of it; a negative status only for
   an internal failure.  */
int gq_endpoint_recv (gq_endpoint *ep, uint64_t now_us, const gq_path *from,
                      uint8_t *data, size_t len);

/* The next datagram to transmit into OUT (CAP at least 2048) for path *TO;
   *LEN is 0 when there is none.  Datagrams the endpoint itself answers with
   (Version Negotiation, Retry, stateless reset) come first, then those of
   connections in turn.  */
int gq_endpoint_send (gq_endpoint *ep, uint64_t now_us, uint8_t *out,
                      size_t cap, size_t *len, gq_path *to);

/* When to call gq_endpoint_on_timeout next; 0 if no timer is armed.  */
uint64_t gq_endpoint_timeout (gq_endpoint *ep);
void gq_endpoint_on_timeout (gq_endpoint *ep, uint64_t now_us);

size_t gq_endpoint_connections (const gq_endpoint *ep);

/* Close every connection (CONNECTION_CLOSE); they linger in their closing
   period and are freed as they finish.  New connections are refused
   afterwards.  */
void gq_endpoint_close (gq_endpoint *ep, uint64_t now_us, int application,
                        uint64_t error, const char *reason);

/* Replace the token key (Retry and NEW_TOKEN); tokens from before still
   work until the next rotation.  */
int gq_endpoint_rotate_keys (gq_endpoint *ep);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_ENDPOINT_H */
