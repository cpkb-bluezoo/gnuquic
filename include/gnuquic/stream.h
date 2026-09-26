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

/* QUIC stream state machines (RFC 9000 section 3).

   The two halves of a stream are independent objects.  Neither knows about
   packets or frames; the connection layer moves data between them and the
   wire.

   Send half (gq_sstream).  The application appends bytes; the connection
   asks for chunks to put in STREAM frames and later reports each chunk
   acknowledged or lost.  Only bytes that are not yet acknowledged are
   held, so memory follows the amount in flight, not the amount sent.
   Lost chunks are handed out again before new data, and new data is held
   back by the peer's flow control credit.

   Receive half (gq_rstream).  STREAM frames arrive in any order and are
   pushed in.  Bytes that are contiguous with what was delivered before go
   straight to the delivery callback without being copied; only data that
   arrives ahead of a gap is stored until the gap fills.  The callback sees
   each byte of the stream exactly once, in order.  The final size,
   flow control limit and reset rules of RFC 9000 are enforced here and
   reported as GQ_ERR_FLOW or GQ_ERR_FINAL_SIZE.  */

#ifndef GNUQUIC_STREAM_H
#define GNUQUIC_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/ranges.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stream ids: bit 0 is the initiator (0 client, 1 server), bit 1 the
   direction (0 bidirectional, 1 unidirectional).  */
#define GQ_STREAM_SERVER_INITIATED(id) ((int) ((id) & 1))
#define GQ_STREAM_UNI(id) ((int) (((id) >> 1) & 1))

enum gq_send_state
{
  GQ_SS_READY,		/* Nothing sent yet.  */
  GQ_SS_SEND,		/* Sending data.  */
  GQ_SS_DATA_SENT,	/* FIN sent, waiting for acknowledgement.  */
  GQ_SS_DATA_RECVD,	/* Everything acknowledged.  Terminal.  */
  GQ_SS_RESET_SENT,	/* RESET_STREAM sent, waiting for acknowledgement.  */
  GQ_SS_RESET_RECVD	/* Reset acknowledged.  Terminal.  */
};

typedef struct gq_sstream
{
  uint8_t *buf;			/* Bytes [base, base + len).  */
  size_t cap, limit;
  size_t len;
  uint64_t base;		/* Everything below is acknowledged.  */
  uint64_t sent;		/* Next never-sent offset.  */
  uint64_t max_data;		/* Peer's flow control limit.  */
  uint64_t blocked_at;		/* Limit last reported as blocked, +1.  */
  gq_ranges acked;		/* Acknowledged ranges above base.  */
  gq_ranges lost;		/* Ranges waiting to be sent again.  */
  uint64_t reset_err;
  uint8_t fin_set;		/* Application finished the stream.  */
  uint8_t fin_sent, fin_lost, fin_acked;
  uint8_t reset, reset_pending, reset_acked;
} gq_sstream;

/* LIMIT is the most unacknowledged data to buffer; MAX_DATA the peer's
   initial per-stream credit.  */
void gq_sstream_init (gq_sstream *s, size_t limit, uint64_t max_data);
void gq_sstream_free (gq_sstream *s);

/* Append data; returns the number of bytes accepted (0 when the buffer
   is full), or a negative status if the stream was finished or reset.  */
long gq_sstream_write (gq_sstream *s, const uint8_t *data, size_t len);

/* No more data will be written; a FIN follows the last byte.  */
int gq_sstream_finish (gq_sstream *s);

/* Room left in the buffer.  */
size_t gq_sstream_room (const gq_sstream *s);

/* Abandon the stream and queue a RESET_STREAM carrying ERR.  Buffered data
   is dropped.  */
void gq_sstream_reset (gq_sstream *s, uint64_t err);

/* Peer raised its credit (ignored if lower than the current value).  */
void gq_sstream_set_max (gq_sstream *s, uint64_t max);

/* Choose the next chunk to send, at most MAX bytes.  On success returns 1
   and sets *OFF, *LEN, *FIN and *DATA, which points into the send buffer
   and stays valid until the next call that changes the stream; the chunk
   counts as sent.  New data is limited by the peer's credit and, through
   CONN_CREDIT, by the connection-level credit still available (pass
   UINT64_MAX when not tracking it); *NEW_BYTES reports how much of the
   chunk was sent for the first time, for the connection's accounting.
   Returns 0 if there is nothing to send.  */
int gq_sstream_next (gq_sstream *s, size_t max, uint64_t conn_credit,
                     uint64_t *off, const uint8_t **data, size_t *len,
                     int *fin, uint64_t *new_bytes);

/* Outcome of a chunk given out by gq_sstream_next.  */
void gq_sstream_on_acked (gq_sstream *s, uint64_t off, size_t len, int fin);
void gq_sstream_on_lost (gq_sstream *s, uint64_t off, size_t len, int fin);

/* Take the pending RESET_STREAM, if any: returns 1 and fills the fields
   (the final size is the highest offset ever sent).  */
int gq_sstream_take_reset (gq_sstream *s, uint64_t *err, uint64_t *final);
void gq_sstream_reset_lost (gq_sstream *s);
void gq_sstream_reset_acked (gq_sstream *s);

/* STREAM_DATA_BLOCKED: returns 1 with the limit to report if data is
   waiting on the peer's credit and this limit was not yet reported.  */
int gq_sstream_take_blocked (gq_sstream *s, uint64_t *limit);

/* Nonzero if gq_sstream_next or gq_sstream_take_reset would produce
   something (CONN_CREDIT as above).  */
int gq_sstream_pending (const gq_sstream *s, uint64_t conn_credit);

enum gq_send_state gq_sstream_state (const gq_sstream *s);

enum gq_recv_state
{
  GQ_RS_RECV,		/* Receiving; final size unknown.  */
  GQ_RS_SIZE_KNOWN,	/* Final size known, data still missing.  */
  GQ_RS_DATA_READ,	/* All data delivered.  Terminal.  */
  GQ_RS_RESET_RECVD	/* Peer reset the stream.  Terminal.  */
};

/* Delivery callback: FIN is set on the last call, which may carry no
   data.  Return nonzero to abort (GQ_ERR_HANDLER).  */
typedef int (*gq_rstream_cb) (void *user, uint64_t off, const uint8_t *data,
                              size_t len, int fin);

typedef struct gq_rstream
{
  uint8_t *buf;			/* Out-of-order data, [off, off + cap).  */
  size_t cap;
  gq_ranges have;		/* Stored ranges (absolute offsets).  */
  uint64_t off;			/* Next offset to deliver.  */
  uint64_t highest;		/* Highest offset received.  */
  uint64_t final;
  uint64_t max_data;		/* Credit granted to the peer.  */
  uint64_t max_sent;		/* Last credit put on the wire.  */
  uint64_t reset_err;
  uint64_t stop_err;
  uint8_t final_known, fin_delivered, reset, discard;
  uint8_t stop_pending;
} gq_rstream;

/* MAX_DATA is the initial credit granted to the peer.  */
void gq_rstream_init (gq_rstream *s, uint64_t max_data);
void gq_rstream_free (gq_rstream *s);

/* Push one STREAM frame's payload.  *NEW_BYTES receives how far the
   highest received offset advanced, for connection-level flow control
   (may be NULL).  Data already delivered is ignored.  */
int gq_rstream_push (gq_rstream *s, uint64_t off, const uint8_t *data,
                     size_t len, int fin, gq_rstream_cb cb, void *user,
                     uint64_t *new_bytes);

/* RESET_STREAM received.  */
int gq_rstream_reset (gq_rstream *s, uint64_t err, uint64_t final,
                      uint64_t *new_bytes);

/* The application no longer wants the data: queue STOP_SENDING carrying
   ERR and drop whatever arrives, though flow control still counts it.  */
void gq_rstream_stop (gq_rstream *s, uint64_t err);
int gq_rstream_take_stop (gq_rstream *s, uint64_t *err);
void gq_rstream_stop_lost (gq_rstream *s);

/* Slide the credit window: once at least half of WINDOW has been consumed
   since the last grant, raise the limit to off + WINDOW.  Returns 1 with
   the value to send in MAX_STREAM_DATA when there is one to announce.  */
int gq_rstream_take_update (gq_rstream *s, uint64_t window, uint64_t *max);
void gq_rstream_update_lost (gq_rstream *s, uint64_t max);

enum gq_recv_state gq_rstream_state (const gq_rstream *s);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_STREAM_H */
