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

/* QUIC connection (RFC 9000, RFC 9001, loss detection of RFC 9002).

   A gq_conn is one QUIC connection as a pure state machine.  It owns no
   socket, thread or timer; the caller moves datagrams and time:

     gq_conn_recv     a datagram arrived (from the peer's address);
     gq_conn_send     ask for the next datagram to transmit, until none;
     gq_conn_timeout  when to call gq_conn_on_timeout next;

   Time is a caller-supplied monotonic clock in MICROSECONDS.  Every call
   that can change what to send or when takes the current time, so the
   library behaves identically under a simulated clock in tests.

   What the connection does: the handshake (the TLS 1.3 engine in QUIC
   mode carried in CRYPTO frames over the Initial, Handshake and 1-RTT
   packet number spaces), packet protection and key updates, ACK
   generation, RTT estimation, loss detection and probe timeouts,
   retransmission of lost frames, connection ID management, flow control
   at both levels, streams, idle timeout, connection close and stateless
   reset detection, and the anti-amplification limit of a server.

   Events reach the application through gq_conn_events.  Callbacks run
   synchronously inside the call that caused them and must not call
   gq_conn_free; they may call the stream functions.

   Congestion control is NewReno as in RFC 9002 section 7, without
   pacing or ECN.

   Version negotiation is both RFC 9000 section 6 (a client restarts after
   a Version Negotiation packet) and RFC 9368 (compatible negotiation
   between v1 and v2 during the handshake, with downgrade protection).

   Path validation and migration (RFC 9000 sections 8.2 and 9) work on
   opaque addresses the caller supplies (gq_conn_recv_path,
   gq_conn_send_path): a peer that moves is followed and validated, and a
   client can migrate or probe paths itself.  The server's
   preferred_address is not used.

   Not done here (later steps): 0-RTT, DATAGRAM frames, and the endpoint layer that routes
   datagrams to connections.  */

#ifndef GNUQUIC_CONN_H
#define GNUQUIC_CONN_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/packet.h>
#include <gnuquic/tls.h>
#include <gnuquic/tparams.h>
#include <gnuquic/token.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Transport error codes (RFC 9000 section 20.1).  */
enum gq_transport_error
{
  GQ_QERR_NO_ERROR = 0x0,
  GQ_QERR_INTERNAL = 0x1,
  GQ_QERR_CONNECTION_REFUSED = 0x2,
  GQ_QERR_FLOW_CONTROL = 0x3,
  GQ_QERR_STREAM_LIMIT = 0x4,
  GQ_QERR_STREAM_STATE = 0x5,
  GQ_QERR_FINAL_SIZE = 0x6,
  GQ_QERR_FRAME_ENCODING = 0x7,
  GQ_QERR_TRANSPORT_PARAMETER = 0x8,
  GQ_QERR_CONNECTION_ID_LIMIT = 0x9,
  GQ_QERR_PROTOCOL_VIOLATION = 0xa,
  GQ_QERR_INVALID_TOKEN = 0xb,
  GQ_QERR_APPLICATION = 0xc,
  GQ_QERR_CRYPTO_BUFFER = 0xd,
  GQ_QERR_KEY_UPDATE = 0xe,
  GQ_QERR_AEAD_LIMIT = 0xf,
  GQ_QERR_NO_VIABLE_PATH = 0x10,
  GQ_QERR_VERSION_NEGOTIATION = 0x11,	/* RFC 9368.  */
  GQ_QERR_CRYPTO_BASE = 0x100	/* Plus the TLS alert.  */
};

/* Why a connection ended.  */
enum gq_close_source
{
  GQ_CLOSE_LOCAL = 1,		/* We closed it (gq_conn_close or an error).  */
  GQ_CLOSE_PEER,		/* The peer sent CONNECTION_CLOSE.  */
  GQ_CLOSE_IDLE,		/* The idle timeout expired.  */
  GQ_CLOSE_RESET		/* A stateless reset arrived.  */
};

/* A network path, as opaque bytes the caller chooses (normally the packed IP
   address and port).  The library never interprets them; it only compares
   them.  An empty address (len 0) means unspecified.  */
typedef struct gq_addr
{
  uint8_t len;
  uint8_t data[31];
} gq_addr;

typedef struct gq_path
{
  gq_addr local, remote;
} gq_path;

typedef struct gq_conn_close_info
{
  enum gq_close_source source;
  int application;		/* Error space: application or transport.  */
  uint64_t error;
  uint64_t frame_type;		/* Transport errors from the peer.  */
  const uint8_t *reason;	/* Valid during the callback only.  */
  size_t reason_len;
} gq_conn_close_info;

typedef struct gq_conn_events
{
  void *user;
  /* The handshake completed (for a server, the client's Finished was
     verified).  Streams may be opened from here on.  */
  void (*connected) (void *user, const gq_tls_info *info);
  /* The peer opened a stream (its first frame arrived).  Streams with a
     lower id of the same type are opened first, as the RFC requires.  */
  void (*stream_opened) (void *user, uint64_t id);
  /* Stream data in order, exactly once.  FIN marks the end and may come
     with no data.  Return nonzero to abort the connection.  */
  int (*stream_data) (void *user, uint64_t id, const uint8_t *data,
                      size_t len, int fin);
  /* The peer abandoned its sending side with RESET_STREAM.  */
  void (*stream_reset) (void *user, uint64_t id, uint64_t error);
  /* The peer asked us to stop sending (STOP_SENDING).  The sending side
     has been reset with the same error already.  */
  void (*stream_stopped) (void *user, uint64_t id, uint64_t error);
  /* Room appeared in a stream's send buffer after it had been full.  */
  void (*stream_writable) (void *user, uint64_t id);
  /* Both halves of the stream are finished and its state was released.  */
  void (*stream_closed) (void *user, uint64_t id);
  /* The connection ended (closing or draining).  Called at most once.  */
  void (*closed) (void *user, const gq_conn_close_info *info);
  /* Connection IDs we accept: for the endpoint's routing table.  The
     token is the stateless reset token bound to it.  */
  void (*cid_issued) (void *user, const uint8_t *cid, size_t len,
                      const uint8_t token[GQ_RESET_TOKEN_LEN]);
  void (*cid_retired) (void *user, const uint8_t *cid, size_t len);
  /* Path validation and migration (RFC 9000 sections 8.2 and 9).  A path
     was validated; a path failed validation; the connection now sends on
     PATH (the peer migrated, we did, or we fell back after a failed
     validation).  */
  void (*path_validated) (void *user, const gq_path *path);
  void (*path_failed) (void *user, const gq_path *path);
  void (*migrated) (void *user, const gq_path *path);
  /* Client: NEW_TOKEN from the server, to keep for a later connection.  */
  void (*new_token) (void *user, const uint8_t *token, size_t len);
  /* Client: session ticket for resumption, with the QUIC version of this
     connection.  A ticket is good only for connections of the version it
     came from (RFC 9369 section 5): offer it (gq_tls_config.resume) only
     on a connection that starts in that version; a server refuses it
     otherwise and the handshake runs in full.  */
  void (*ticket) (void *user, const gq_tls_ticket *ticket, uint32_t version);
} gq_conn_events;

/* Zero means the default in every field.  */
typedef struct gq_conn_config
{
  /* Versions (RFC 9369, RFC 9368).  VERSIONS lists those this endpoint
     is willing to use, most preferred first; empty means GQ_VERSION_2 and
     GQ_VERSION_1, newest first, or just VERSION if that is set.  A server
     serves any Initial whose version is listed and then follows the
     client's own order among the compatible versions both list (v1 and v2
     are compatible), switching the connection during the handshake if
     that is not the version the client started with.  A client starts in
     VERSION, or if that is zero in the oldest listed version, the one a
     server is most likely to parse (RFC 9368 section 2.5), offering the
     compatible others; it restarts after a Version Negotiation packet with
     the first listed version the server has, and accepts a compatible
     switch to a listed version.  */
  uint32_t version;
  uint32_t versions[GQ_TP_MAX_VERSIONS];
  size_t n_versions;
  uint64_t idle_timeout_ms;		/* 0: 30000.  */
  uint64_t initial_max_data;		/* 0: 1 MiB.  */
  uint64_t initial_max_stream_data;	/* Each stream type; 0: 256 KiB.  */
  uint64_t initial_max_streams_bidi;	/* 0: 100.  */
  uint64_t initial_max_streams_uni;	/* 0: 100.  */
  size_t send_buffer;			/* Per stream; 0: 256 KiB.  */
  size_t max_udp_payload;		/* Largest datagram sent; 0: 1200.  */
  size_t cid_len;			/* Our connection IDs; 0: 8.  */
  unsigned active_cid_limit;		/* 0: 4 (2 to 8).  */
  int disable_active_migration;
  /* Client: a token from an earlier connection's NEW_TOKEN, sent in the
     first Initial (copied; at most 512 bytes).  */
  const uint8_t *token;
  size_t token_len;
  /* The path the connection starts on, if known: a client's is its socket
     and the server's address.  Otherwise the first datagram received
     defines it.  */
  gq_path path;
  /* Wall clock in seconds, for token ages.  NULL uses time().  */
  uint64_t (*wall_seconds) (void *user);
  void *wall_user;
} gq_conn_config;

/* What the admission step (listen.h) learned about a client's first
   Initial, given to gq_conn_server_accept.  */
typedef struct gq_conn_accept
{
  int validated;		/* The client proved its address (a token).  */
  gq_cid odcid;			/* Original destination ID after a Retry
				   (len 0: no Retry happened).  */
  gq_cid retry_scid;		/* The ID the server chose in the Retry: it
				   becomes our first source ID.  */
  const gq_token_keys *token_keys;	/* Non-NULL: send NEW_TOKEN after the
				   handshake.  Must outlive the connection.  */
  uint8_t addr[64];		/* The client's address, as bound to tokens.  */
  size_t addr_len;
} gq_conn_accept;

typedef struct gq_conn gq_conn;

enum gq_conn_state
{
  GQ_CONN_HANDSHAKE = 1,
  GQ_CONN_ESTABLISHED,
  GQ_CONN_CLOSING,	/* We closed; answering the peer's packets.  */
  GQ_CONN_DRAINING,	/* The peer closed; silent.  */
  GQ_CONN_DONE		/* The closing period ended: free it.  */
};

/* Create a client.  The ClientHello is queued; call gq_conn_send.  TLS
   must have ALPN set; the connection sets the QUIC fields itself.  */
int gq_conn_client_new (gq_conn **out, const gq_conn_config *config,
                        const gq_tls_config *tls,
                        const gq_conn_events *events, uint64_t now_us);

/* Create a server.  The first Initial datagram, passed to gq_conn_recv,
   fixes the connection IDs and Initial keys; the endpoint layer picks
   which connection gets which datagram.  */
int gq_conn_server_new (gq_conn **out, const gq_conn_config *config,
                        const gq_tls_server_config *tls,
                        const gq_conn_events *events, uint64_t now_us);

/* As gq_conn_server_new, with the outcome of address validation: after a
   Retry the connection must use the ID the Retry chose, and it reports the
   original destination ID in its transport parameters.  */
int gq_conn_server_accept (gq_conn **out, const gq_conn_config *config,
                           const gq_tls_server_config *tls,
                           const gq_conn_events *events, uint64_t now_us,
                           const gq_conn_accept *accept);

void gq_conn_free (gq_conn *c);

/* Process one UDP datagram, decrypting it IN PLACE.  Returns GQ_OK when
   it was handled (including when it was ignored, as invalid or
   undecryptable packets are); a negative status only for an internal
   failure.  A protocol violation by the peer closes the connection and
   is reported through the closed event, not the return value.  */
int gq_conn_recv (gq_conn *c, uint64_t now_us, uint8_t *data, size_t len);

/* The same with the network path.  gq_conn_recv_path tells the connection
   where the datagram came from (FROM may be NULL: no path information,
   which disables migration handling).  gq_conn_send_path also reports where
   the datagram must go and from which local address (*TO, which may be
   NULL); most datagrams go to the current path, but probing datagrams
   (PATH_CHALLENGE, and PATH_RESPONSE to a challenge that arrived on another
   path) go elsewhere and must be sent there exactly.  */
int gq_conn_recv_path (gq_conn *c, uint64_t now_us, const gq_path *from,
                       uint8_t *data, size_t len);
int gq_conn_send_path (gq_conn *c, uint64_t now_us, uint8_t *out, size_t cap,
                       size_t *len, gq_path *to);

/* The path the connection currently sends on; GQ_ERR_UNAVAILABLE if it is
   not known yet.  */
int gq_conn_get_path (const gq_conn *c, gq_path *path);

/* Start validating PATH without moving to it: a PATH_CHALLENGE goes out on
   it and the path_validated or path_failed event follows.  Returns GQ_OK,
   GQ_ERR_INVAL (handshake not confirmed, or the path is the current one),
   GQ_ERR_RANGE (no unused peer connection ID, or too many paths under
   validation).  Each new path needs a fresh peer connection ID so the
   paths cannot be linked (RFC 9000 section 9.5).  */
int gq_conn_probe_path (gq_conn *c, uint64_t now_us, const gq_path *path);

/* Client: migrate to PATH (RFC 9000 section 9.2): validate it, then move
   there and retire the old connection ID; the migrated event reports it.
   An already validated path is used at once.  GQ_ERR_UNAVAILABLE if the
   server forbids active migration (disable_active_migration) or this is a
   server; other errors as gq_conn_probe_path.  */
int gq_conn_migrate (gq_conn *c, uint64_t now_us, const gq_path *path);

/* Produce the next datagram into OUT (capacity CAP, which must be at
   least the configured max_udp_payload).  *LEN is 0 when there is
   nothing to send now.  */
int gq_conn_send (gq_conn *c, uint64_t now_us, uint8_t *out, size_t cap,
                  size_t *len);

/* The time at which gq_conn_on_timeout must be called, or 0 if no timer
   is armed.  */
uint64_t gq_conn_timeout (const gq_conn *c);
void gq_conn_on_timeout (gq_conn *c, uint64_t now_us);

/* Close the connection with CONNECTION_CLOSE.  APPLICATION selects the
   error space.  The connection lingers in the closing state (see
   gq_conn_state) so that stray packets get the close again.  */
int gq_conn_close (gq_conn *c, uint64_t now_us, int application,
                   uint64_t error, const char *reason);

enum gq_conn_state gq_conn_state (const gq_conn *c);
int gq_conn_is_established (const gq_conn *c);

/* Version in use.  */
uint32_t gq_conn_version (const gq_conn *c);

/* Our first source connection ID, which a server endpoint routes by.
   Also: the Destination Connection ID of the first Initial (a server
   endpoint routes by it until the client switches).  */
const uint8_t *gq_conn_initial_dcid (const gq_conn *c, size_t *len);

/* ---- Streams ---- */

/* Open a stream we initiate.  Returns GQ_OK and the id, or GQ_ERR_RANGE
   if the peer's stream limit has been reached (retry after more credit
   arrives: the stream_writable-like signal is gq_conn_streams_available).
   Requires an established connection.  */
int gq_conn_stream_open (gq_conn *c, int bidi, uint64_t *id);

/* Streams of this kind we may still open.  */
uint64_t gq_conn_streams_available (const gq_conn *c, int bidi);

/* Queue data on a stream we can send on.  Returns the bytes accepted
   (fewer than LEN when the send buffer is full; wait for stream_writable
   ) or a negative status.  */
long gq_conn_stream_write (gq_conn *c, uint64_t id, const uint8_t *data,
                           size_t len);

/* End the sending side cleanly (FIN).  */
int gq_conn_stream_finish (gq_conn *c, uint64_t id);

/* Abandon the sending side (RESET_STREAM) or ask the peer to stop
   sending (STOP_SENDING).  */
int gq_conn_stream_reset (gq_conn *c, uint64_t id, uint64_t error);
int gq_conn_stream_stop_sending (gq_conn *c, uint64_t id, uint64_t error);

/* Room left in the send buffer of a stream.  */
size_t gq_conn_stream_room (const gq_conn *c, uint64_t id);

/* Ask for our sending keys to be replaced (RFC 9001 section 6).  The
   library also does this by itself before the AEAD limits.  Returns
   GQ_ERR_INVAL when an update is not allowed yet.  */
int gq_conn_update_keys (gq_conn *c, uint64_t now_us);

/* Statistics, mostly for tests.  */
typedef struct gq_conn_stats
{
  uint64_t packets_sent, packets_received, packets_lost;
  uint64_t bytes_sent, bytes_received;
  uint64_t srtt_us, min_rtt_us, rttvar_us;
  uint64_t bytes_in_flight;
  uint64_t cwnd, ssthresh;		/* Congestion controller state.  */
  uint64_t congestion_events;
  uint64_t key_updates;
  unsigned pto_count;
  uint64_t path_validations, path_failures, migrations;
} gq_conn_stats;

void gq_conn_get_stats (const gq_conn *c, gq_conn_stats *st);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_CONN_H */
