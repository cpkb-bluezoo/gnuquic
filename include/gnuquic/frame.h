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

/* QUIC frame codec (RFC 9000 section 19, RFC 9221).

   Parsing follows the push-parser contract used throughout GNU QUIC:

   - The caller hands over a buffer; the parser consumes as many complete
     frames as it can and advances the buffer past them.
   - Each frame is delivered as a transient event (a gq_frame on the
     parser's stack).  Variable-length payloads (CRYPTO, STREAM, DATAGRAM,
     reasons, tokens) are slices that point into the caller's buffer;
     nothing is copied or allocated.  A handler that needs the bytes
     after it returns must copy them.
   - A frame is all-or-nothing: no event is delivered for a frame until
     the whole frame is present and syntactically valid.  If input ends
     in the middle of a frame the parser returns GQ_NEED_MORE and leaves
     the buffer positioned at the start of that frame, so the caller can
     append more data and call again.

   Note that in QUIC a packet payload is normally complete when it is
   decrypted, so GQ_NEED_MORE at the end of a payload is a
   FRAME_ENCODING_ERROR for the connection layer.  The contract exists so
   the same parser can be fed arbitrary chunk splits in tests and used
   over any reassembled byte stream.  STREAM and DATAGRAM frames without
   an explicit length extend to the end of the buffer, so the buffer must
   then end at the packet boundary.  */

#ifndef GNUQUIC_FRAME_H
#define GNUQUIC_FRAME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_slice
{
  const uint8_t *data;
  size_t len;
} gq_slice;

enum gq_frame_type
{
  GQ_FRAME_PADDING = 1,
  GQ_FRAME_PING,
  GQ_FRAME_ACK,
  GQ_FRAME_RESET_STREAM,
  GQ_FRAME_STOP_SENDING,
  GQ_FRAME_CRYPTO,
  GQ_FRAME_NEW_TOKEN,
  GQ_FRAME_STREAM,
  GQ_FRAME_MAX_DATA,
  GQ_FRAME_MAX_STREAM_DATA,
  GQ_FRAME_MAX_STREAMS,
  GQ_FRAME_DATA_BLOCKED,
  GQ_FRAME_STREAM_DATA_BLOCKED,
  GQ_FRAME_STREAMS_BLOCKED,
  GQ_FRAME_NEW_CONNECTION_ID,
  GQ_FRAME_RETIRE_CONNECTION_ID,
  GQ_FRAME_PATH_CHALLENGE,
  GQ_FRAME_PATH_RESPONSE,
  GQ_FRAME_CONNECTION_CLOSE,
  GQ_FRAME_HANDSHAKE_DONE,
  GQ_FRAME_DATAGRAM
};

#define GQ_MAX_CID_LEN 20
#define GQ_RESET_TOKEN_LEN 16

typedef struct gq_frame
{
  enum gq_frame_type type;
  union
  {
    struct { size_t len; } padding;	/* Run of PADDING bytes.  */
    struct
    {
      uint64_t largest;
      uint64_t delay;
      uint64_t range_count;	/* Ranges after the first.  */
      gq_slice ranges;		/* Raw, validated; see gq_ack_foreach.  */
      int has_ecn;
      uint64_t ect0, ect1, ecn_ce;
    } ack;
    struct { uint64_t id, error, final_size; } reset_stream;
    struct { uint64_t id, error; } stop_sending;
    struct { uint64_t offset; gq_slice data; } crypto;
    struct { gq_slice token; } new_token;
    struct { uint64_t id, offset; gq_slice data; int fin; } stream;
    struct { uint64_t max; } max_data;
    struct { uint64_t id, max; } max_stream_data;
    struct { uint64_t max; int bidi; } max_streams;
    struct { uint64_t limit; } data_blocked;
    struct { uint64_t id, limit; } stream_data_blocked;
    struct { uint64_t limit; int bidi; } streams_blocked;
    struct
    {
      uint64_t seq, retire_prior_to;
      uint8_t cid_len;
      uint8_t cid[GQ_MAX_CID_LEN];
      uint8_t reset_token[GQ_RESET_TOKEN_LEN];
    } new_connection_id;
    struct { uint64_t seq; } retire_connection_id;
    struct { uint8_t data[8]; } path_challenge;	/* Also PATH_RESPONSE.  */
    struct
    {
      int application;		/* 0x1d rather than 0x1c.  */
      uint64_t error;
      uint64_t frame_type;	/* Transport close only.  */
      gq_slice reason;
    } connection_close;
    struct { gq_slice data; } datagram;
  } u;
} gq_frame;

/* Frame event handler.  Return 0 to continue, nonzero to stop parsing
   (gq_frame_parse then returns GQ_ERR_HANDLER).  */
typedef int (*gq_frame_cb) (void *user, const gq_frame *frame);

/* Parse frames from *BUF (*LEN bytes), calling CB for each, and advance
   *BUF and *LEN past every frame consumed.  Returns:

   GQ_OK            the buffer was consumed completely;
   GQ_NEED_MORE     a partial frame remains; BUF and LEN describe it;
   GQ_ERR_ENCODING  malformed or unknown frame; BUF and LEN describe it;
   GQ_ERR_HANDLER   CB refused a frame; BUF and LEN are just past it.  */
int gq_frame_parse (const uint8_t **buf, size_t *len,
                    gq_frame_cb cb, void *user);

/* Serialize FRAME into OUT (capacity OUTLEN), storing the byte count in
   *WRITTEN.  STREAM and DATAGRAM are always written in their explicit
   length form.  For ACK, u.ack.ranges must hold the already-encoded
   range section (see gq_ack_ranges_encode).  Returns GQ_OK,
   GQ_ERR_BUFSIZE, GQ_ERR_RANGE or GQ_ERR_INVAL.  */
int gq_frame_write (const gq_frame *frame, uint8_t *out, size_t outlen,
                    size_t *written);

/* An inclusive range of acknowledged packet numbers.  */
typedef struct gq_ack_range
{
  uint64_t lo, hi;
} gq_ack_range;

/* Encode N ranges, sorted by descending HI and non-adjacent (at least
   one unacknowledged number between them), into the wire range section
   (first range length, then gap/length pairs) for a gq_frame ACK.  The
   ack's largest is RANGES[0].hi and range_count is N - 1.  */
int gq_ack_ranges_encode (const gq_ack_range *ranges, size_t n,
                          uint8_t *out, size_t outlen, size_t *written);

/* Walk the ranges of a parsed ACK from highest to lowest.  CB returns 0
   to continue, nonzero to stop (then this returns GQ_ERR_HANDLER).  */
int gq_ack_foreach (const gq_frame *ack,
                    int (*cb) (void *user, uint64_t lo, uint64_t hi),
                    void *user);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_FRAME_H */
