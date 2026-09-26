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

/* Internals shared by the QUIC connection source files.  */

#ifndef GNUQUIC_CONN_INT_H
#define GNUQUIC_CONN_INT_H

#include <gnuquic/status.h>
#include <gnuquic/crypto.h>
#include <gnuquic/varint.h>
#include <gnuquic/frame.h>
#include <gnuquic/packet.h>
#include <gnuquic/protect.h>
#include <gnuquic/tparams.h>
#include <gnuquic/ranges.h>
#include <gnuquic/stream.h>
#include <gnuquic/tls.h>
#include <gnuquic/conn.h>

enum { SP_INITIAL, SP_HANDSHAKE, SP_APP, N_SPACES };

/* RFC 9002 constants, in microseconds.  */
#define K_GRANULARITY 1000u
#define K_INITIAL_RTT 333000u
#define K_PACKET_THRESHOLD 3
/* RFC 9002 section 7 (NewReno) constants.  */
#define CC_MAX_DATAGRAM 1200u
#define CC_INITIAL_WINDOW (10u * CC_MAX_DATAGRAM)
#define CC_MIN_WINDOW (2u * CC_MAX_DATAGRAM)
#define K_PERSISTENT_CONGESTION_THRESHOLD 3
#define MAX_FRAMES_PER_PACKET 48
#define MAX_LCID 8
#define MAX_PCID 16
#define MAX_PATHS 4
#define MAX_CANDIDATES 3
#define MAX_CHALLENGES 3

/* What a sent packet carried that must be retransmitted if it is lost.  */
enum sf_type
{
  SF_CRYPTO = 1, SF_STREAM, SF_RESET_STREAM, SF_STOP_SENDING, SF_MAX_DATA,
  SF_MAX_STREAM_DATA, SF_MAX_STREAMS, SF_DATA_BLOCKED,
  SF_STREAM_DATA_BLOCKED, SF_NEW_CID, SF_RETIRE_CID, SF_HANDSHAKE_DONE,
  SF_ACK, SF_PATH_RESPONSE, SF_NEW_TOKEN, SF_PATH_CHALLENGE, SF_DATAGRAM
};

typedef struct sent_frame
{
  uint8_t type;
  uint8_t fin;			/* STREAM; MAX_STREAMS: bidi.  */
  uint32_t len;
  uint64_t a, b;
} sent_frame;

typedef struct sent_pkt
{
  uint64_t pn;
  uint64_t time_us;
  uint32_t size;
  uint8_t ack_eliciting, in_flight, requeued;
  uint32_t nframes;
  sent_frame *frames;
} sent_pkt;

typedef struct space
{
  gq_packet_keys rk, wk;
  uint8_t have_rk, have_wk, discarded;
  uint64_t next_pn;
  uint64_t largest_acked;
  uint8_t have_acked;
  uint64_t largest_recv;
  uint64_t largest_recv_time;
  uint8_t have_recv;
  gq_ranges recv;		/* Packet numbers received.  */
  uint8_t ack_pending;		/* An ACK should go out.  */
  uint8_t ack_now;		/* ...without waiting.  */
  unsigned ae_since_ack;	/* Ack-eliciting packets not yet acked.  */
  uint64_t ack_deadline;	/* 0: none.  */
  gq_sstream cs;		/* CRYPTO send half.  */
  gq_rstream cr;		/* CRYPTO receive half.  */
  sent_pkt *sent;		/* Ordered by pn.  */
  size_t n_sent, cap_sent;
  uint64_t loss_time;		/* 0: none.  */
  uint64_t last_ae_time;	/* Time of the last ack-eliciting send.  */
  gq_ranges acked_pns;		/* Recently acknowledged packet numbers.  */
  uint64_t recv_floor;		/* Packet numbers below this count as seen.  */
  unsigned ae_in_flight;	/* Ack-eliciting packets outstanding.  */
  unsigned probes;		/* Probe packets still to send.  */
} space;

typedef struct lcid
{
  uint64_t seq;
  gq_cid cid;
  uint8_t token[GQ_RESET_TOKEN_LEN];
  uint8_t used;			/* Slot in use.  */
  uint8_t announced;		/* NEW_CONNECTION_ID acked or seq 0.  */
  uint8_t need_send;		/* NEW_CONNECTION_ID must be (re)sent.  */
} lcid;

typedef struct pcid
{
  uint64_t seq;
  gq_cid cid;
  uint8_t token[GQ_RESET_TOKEN_LEN];
  uint8_t used;
  uint8_t retire;		/* 0: active, 1: RETIRE to send, 2: sent.  */
} pcid;

/* One network path (RFC 9000 section 8.2, 9).  */
typedef struct pathinfo
{
  gq_path p;
  uint8_t used;
  uint8_t initial;		/* The path the handshake ran on.  */
  uint8_t validated;
  uint8_t local_init;		/* We started it (probe or migration).  */
  uint8_t auto_switch;		/* Migrate to it once validated.  */
  gq_cid dcid;			/* Peer ID used on this path.  */
  uint64_t dcid_seq;
  uint64_t recv, sent;		/* Bytes, for the amplification limit.  */
  uint8_t chal[MAX_CHALLENGES][8];	/* Outstanding challenge data.  */
  unsigned n_chal;
  uint8_t need_challenge;
  unsigned chal_sent;
  uint64_t chal_next, chal_deadline;
  uint8_t resp[2][8];		/* Responses owed to the peer on this path.  */
  unsigned n_resp;
} pathinfo;

typedef struct stream
{
  uint64_t id;
  uint8_t has_send, has_recv;
  uint8_t opened_notified, full;	/* full: send buffer was full.  */
  gq_sstream s;
  gq_rstream r;
} stream;

struct gq_conn
{
  enum gq_role role;
  enum gq_conn_state state;
  gq_conn_config cfg;
  gq_conn_events ev;
  gq_conn_router router;
  uint32_t version;
  uint32_t orig_version;	/* Version of the first flight.  */
  uint8_t switched;		/* A compatible version switch happened.  */
  uint8_t vn_received;		/* Restarted after Version Negotiation.  */
  gq_packet_keys orig_rk;	/* Server: Initial keys of orig_version.  */
  uint8_t have_orig_rk;

  gq_tls *tls;
  gq_tls_config ctls;		/* Copies of the caller's configuration:  */
  gq_tls_server_config stls;
  gq_ticket_keys *ticket_base;	/* Server: the caller's ring (v1 tickets).  */
  gq_ticket_keys *ticket_v2;	/* ...and the ring derived for v2.  */	/* the engine keeps pointers into them.  */
  uint8_t tp_buf[256];
  size_t tp_len;
  gq_transport_params peer_tp;
  int have_peer_tp;
  int tls_started;

  space sp[N_SPACES];
  uint8_t handshake_complete;		/* TLS finished.  */
  uint8_t handshake_confirmed;
  uint8_t handshake_done_pending;
  uint8_t handshake_done_sent;
  uint8_t connected_notified;
  uint8_t got_first_initial;		/* Server: keys derived.  */
  uint8_t peer_addr_validated;
  uint8_t got_peer_packet;

  gq_cid odcid;			/* Original destination CID (client's).  */
  gq_cid initial_dcid;		/* Destination ID the Initial keys come from.  */
  gq_cid retry_scid;		/* Retry: the ID the server chose (len 0: none).  */
  uint8_t retried;
  uint8_t token[512];		/* Client: token for Initial packets.  */
  size_t token_len;
  const gq_token_keys *token_keys;	/* Server: issue NEW_TOKEN.  */
  uint8_t addr[64];
  size_t addr_len;
  uint8_t new_token_pending;
  gq_cid scid_first;		/* Our first source CID.  */
  lcid l[MAX_LCID];
  pcid p[MAX_PCID];
  uint64_t next_lseq;
  uint64_t peer_retire_prior;
  gq_cid dcid;			/* Current destination CID.  */
  uint8_t dcid_set;
  uint64_t dcid_seq;
  size_t peer_cid_limit;		/* Peer's active_connection_id_limit.  */

  /* Application key state (RFC 9001 section 6).  */
  uint8_t rsec[GQ_MAX_HASH_LEN], wsec[GQ_MAX_HASH_LEN];
  uint8_t rsec_next[GQ_MAX_HASH_LEN];
  size_t rsec_len, wsec_len;
  gq_packet_keys rk_prev, rk_next;
  uint8_t have_rk_prev, have_rk_next;
  uint8_t r_phase, w_phase;
  uint64_t r_first_pn;		/* First pn of the current read phase.  */
  uint64_t w_first_pn;		/* First pn we sent in the write phase.  */
  uint8_t w_phase_acked;
  uint64_t key_updates;

  /* Timing.  */
  uint64_t now;
  uint64_t latest_rtt, srtt, rttvar, min_rtt;
  uint8_t have_rtt;
  unsigned pto_count;
  uint64_t idle_timeout_us;
  uint64_t idle_deadline;
  uint64_t close_deadline;
  uint64_t last_close_sent;
  uint8_t idle_send_reset;
  uint64_t last_sent_ae;
  uint64_t peer_max_ack_delay_us;
  unsigned peer_ack_delay_exp;

  /* Amplification and totals.  */
  uint64_t bytes_recv, bytes_sent;
  uint64_t bytes_in_flight;
  uint64_t cwnd, ssthresh;	/* Congestion window and threshold.  */
  uint64_t recovery_start;	/* Send time that ends recovery; 0: none.  */
  uint64_t ca_acked;		/* Bytes acked in congestion avoidance.  */
  uint64_t congestion_events;
  gq_conn_stats st;

  /* Flow control.  */
  uint64_t max_data_peer, data_sent;	/* What we may send / have sent.  */
  uint64_t blocked_sent_at;
  uint64_t max_data_local, max_data_sent;
  uint64_t data_recv_total, data_consumed;
  uint64_t max_streams_peer[2];		/* [bidi], [uni]: we may open.  */
  uint64_t next_local_stream[2];	/* Next index to open.  */
  uint64_t max_streams_local[2];	/* Peer may open.  */
  uint64_t max_streams_local_sent[2];
  uint64_t next_peer_stream[2];		/* Next peer index expected.  */
  uint64_t closed_peer_streams[2];	/* Peer streams fully closed.  */
  uint8_t streams_blocked_pending[2];

  stream **streams;		/* Sorted by id.  */
  size_t n_streams, cap_streams, rr;

  /* Pending control frames.  */
  /* Queued outgoing DATAGRAMs (RFC 9221).  */
  struct dgram { uint8_t *data; size_t len; uint64_t id; } *dq;
  size_t dq_head, dq_n, dq_cap, dq_bytes;
  uint64_t next_dgram_id;
  uint64_t datagrams_sent, datagrams_received, datagrams_dropped;
  pathinfo paths[MAX_PATHS];
  int cur_path, prev_path;	/* Indices, -1: none.  */
  int tx_path;			/* Where the datagram being built goes.  */
  gq_path bad_path[2];		/* Recently failed candidates,  */
  uint64_t bad_until[2];	/* ignored until then.  */
  unsigned bad_next;
  gq_path rx;			/* Where the datagram being processed came from.  */
  int rx_known;
  uint64_t path_validations, path_failures, migrations;

  /* Closing.  */
  uint8_t close_pending;
  uint8_t close_app;
  uint64_t close_err, close_frame;
  char close_reason[64];
  size_t close_reason_len;
  uint8_t closed_notified;

  /* Set by a handler that decided the connection must close.  */
  int err_set;
  uint64_t err_code;
  const char *err_reason;
};

/* conn.c */
void conn_fail (gq_conn *c, uint64_t code, const char *reason);
void conn_enter_closing (gq_conn *c, gq_conn_close_info *info, int draining);
int conn_server_start (gq_conn *c, const uint8_t *odcid, size_t odcid_len,
                       const uint8_t *client_scid, size_t client_scid_len);
void conn_recompute_idle (gq_conn *c, uint64_t now);
void conn_wake (gq_conn *c);
void conn_peer_token (gq_conn *c, const uint8_t *token);
void conn_cid_retired (gq_conn *c, const gq_cid *cid);
int conn_client_restart (gq_conn *c, uint32_t version);
int conn_version_compatible (uint32_t a, uint32_t b);
int conn_version_listed (const gq_conn *c, uint32_t v);
void conn_abandon (gq_conn *c, uint64_t error, const char *reason);
uint64_t conn_pto_base (const gq_conn *c, int sp);
int conn_new_lcid (gq_conn *c, int announced);
uint64_t conn_wall_seconds (const gq_conn *c);
int conn_apply_peer_params (gq_conn *c);
int conn_discard_space (gq_conn *c, int sp);
void conn_maybe_confirm (gq_conn *c);
void conn_notify_connected (gq_conn *c, const gq_tls_info *info);
size_t conn_max_datagram (const gq_conn *c);

/* conn_loss.c */
void sp_sent_add (gq_conn *c, int sp, const sent_pkt *p);
void sp_sent_clear (gq_conn *c, int sp);
void free_sent_frames (sent_pkt *p);
void process_ack (gq_conn *c, int sp, const gq_frame *f, uint64_t now);
void loss_detect (gq_conn *c, int sp, uint64_t now);
uint64_t conn_loss_deadline (const gq_conn *c);
void on_loss_timeout (gq_conn *c, uint64_t now);
void requeue_frames (gq_conn *c, int sp, sent_pkt *p);
uint64_t pto_interval (const gq_conn *c, int sp);
int conn_can_send_ae (const gq_conn *c);
void cc_init (gq_conn *c);

/* conn_stream.c */
stream *stream_find (const gq_conn *c, uint64_t id);
stream *stream_for_frame (gq_conn *c, uint64_t id, int for_send);
void stream_remove_if_done (gq_conn *c, stream *st);
void streams_free (gq_conn *c);
void streams_apply_peer_params (gq_conn *c);
uint64_t stream_initial_send_credit (const gq_conn *c, uint64_t id);
uint64_t stream_initial_recv_credit (const gq_conn *c, uint64_t id);
int stream_handle_frame (gq_conn *c, const gq_frame *f);
void stream_on_acked (gq_conn *c, uint64_t id);

/* conn_datagram.c */
void datagrams_free (gq_conn *c);
struct dgram *datagram_front (gq_conn *c);
void datagram_pop (gq_conn *c);

/* conn_path.c */
void conn_path_init (gq_conn *c, const gq_path *initial);
void conn_path_rx_begin (gq_conn *c, const gq_path *from);
void conn_path_rx_end (gq_conn *c);
int conn_path_accept_rx (const gq_conn *c);
void conn_path_after_packet (gq_conn *c, uint64_t now, int nonprobing,
                             int highest);
void conn_path_account_recv (gq_conn *c, size_t len);
void conn_path_on_challenge (gq_conn *c, const uint8_t *data);
void conn_path_on_response (gq_conn *c, const uint8_t *data, uint64_t now);
int conn_path_probe_pending (gq_conn *c, uint64_t now);
void conn_path_challenge_data (gq_conn *c, int idx, uint8_t out[8]);
uint64_t conn_path_deadline (const gq_conn *c);
void conn_path_on_timeout (gq_conn *c, uint64_t now);
int conn_path_budget (const gq_conn *c, int idx, uint64_t *budget);
void conn_path_note_sent (gq_conn *c, int idx, size_t len);
void conn_path_dcid_changed (gq_conn *c);
int conn_path_rx_initial (const gq_conn *c);

/* conn_send.c */
int conn_build_datagram (gq_conn *c, uint64_t now, uint8_t *out, size_t cap,
                         size_t *len);
int conn_have_work (gq_conn *c, int sp);

/* conn_recv.c */
int conn_receive_datagram (gq_conn *c, uint64_t now, uint8_t *data,
                           size_t len);
void conn_install_keys (gq_conn *c, const gq_tls_secret *s);

#define SPACE_OF_LEVEL(l) ((l) == GQ_LEVEL_INITIAL ? SP_INITIAL \
                           : (l) == GQ_LEVEL_HANDSHAKE ? SP_HANDSHAKE \
                           : (l) == GQ_LEVEL_APPLICATION ? SP_APP : -1)

#endif /* GNUQUIC_CONN_INT_H */
