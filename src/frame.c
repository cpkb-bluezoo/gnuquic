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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/varint.h>
#include <gnuquic/frame.h>

/* Frame type codes (RFC 9000 table 3, RFC 9221).  */
enum
{
  T_PADDING = 0x00, T_PING = 0x01, T_ACK = 0x02, T_ACK_ECN = 0x03,
  T_RESET_STREAM = 0x04, T_STOP_SENDING = 0x05, T_CRYPTO = 0x06,
  T_NEW_TOKEN = 0x07, T_STREAM_MIN = 0x08, T_STREAM_MAX = 0x0f,
  T_MAX_DATA = 0x10, T_MAX_STREAM_DATA = 0x11, T_MAX_STREAMS_BIDI = 0x12,
  T_MAX_STREAMS_UNI = 0x13, T_DATA_BLOCKED = 0x14,
  T_STREAM_DATA_BLOCKED = 0x15, T_STREAMS_BLOCKED_BIDI = 0x16,
  T_STREAMS_BLOCKED_UNI = 0x17, T_NEW_CONNECTION_ID = 0x18,
  T_RETIRE_CONNECTION_ID = 0x19, T_PATH_CHALLENGE = 0x1a,
  T_PATH_RESPONSE = 0x1b, T_CONNECTION_CLOSE = 0x1c,
  T_CONNECTION_CLOSE_APP = 0x1d, T_HANDSHAKE_DONE = 0x1e,
  T_DATAGRAM = 0x30, T_DATAGRAM_LEN = 0x31
};

#define STREAM_FIN 0x01
#define STREAM_LEN 0x02
#define STREAM_OFF 0x04

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* ------------------------------------------------------------------ */
/* Reading                                                            */
/* ------------------------------------------------------------------ */

struct cur
{
  const uint8_t *p;
  size_t n;
};

static int
get_vi (struct cur *c, uint64_t *v)
{
  return gq_varint_decode (&c->p, &c->n, v);
}

static int
get_bytes (struct cur *c, uint64_t len, gq_slice *s)
{
  if (len > c->n)
    return GQ_NEED_MORE;
  s->data = c->p;
  s->len = (size_t) len;
  c->p += len;
  c->n -= (size_t) len;
  return GQ_OK;
}

static int
get_fixed (struct cur *c, uint8_t *out, size_t len)
{
  if (len > c->n)
    return GQ_NEED_MORE;
  memcpy (out, c->p, len);
  c->p += len;
  c->n -= len;
  return GQ_OK;
}

static int
get_byte (struct cur *c, uint8_t *out)
{
  return get_fixed (c, out, 1);
}

/* Walk an ACK range section.  C is positioned at the first-range
   varint.  With CB non-NULL each range is reported; the arithmetic is
   validated either way (RFC 9000 section 19.3.1).  */
static int
ack_walk (struct cur *c, uint64_t largest, uint64_t count,
          int (*cb) (void *, uint64_t, uint64_t), void *user)
{
  uint64_t first, gap, len, i;
  uint64_t hi = largest;
  uint64_t lo;

  TRY (get_vi (c, &first));
  if (first > hi)
    return GQ_ERR_ENCODING;
  lo = hi - first;
  if (cb && cb (user, lo, hi))
    return GQ_ERR_HANDLER;

  for (i = 0; i < count; i++)
    {
      TRY (get_vi (c, &gap));
      TRY (get_vi (c, &len));
      /* Next range's largest is lo - gap - 2; gap <= 2^62 so the
         addition cannot overflow.  */
      if (lo < gap + 2)
        return GQ_ERR_ENCODING;
      hi = lo - gap - 2;
      if (len > hi)
        return GQ_ERR_ENCODING;
      lo = hi - len;
      if (cb && cb (user, lo, hi))
        return GQ_ERR_HANDLER;
    }
  return GQ_OK;
}

/* Parse one frame from C into F.  On anything but GQ_OK the cursor
   state is unspecified; the caller restores it.  */
static int
parse_one (struct cur *c, gq_frame *f)
{
  uint64_t t, a, b;
  uint8_t byte;

  memset (f, 0, sizeof *f);
  TRY (get_vi (c, &t));

  switch (t)
    {
    case T_PADDING:
      /* Coalesce a run of zero bytes into one event.  */
      f->type = GQ_FRAME_PADDING;
      f->u.padding.len = 1;
      while (c->n > 0 && c->p[0] == 0)
        {
          c->p++;
          c->n--;
          f->u.padding.len++;
        }
      return GQ_OK;

    case T_PING:
      f->type = GQ_FRAME_PING;
      return GQ_OK;

    case T_ACK:
    case T_ACK_ECN:
      {
        const uint8_t *start;

        f->type = GQ_FRAME_ACK;
        TRY (get_vi (c, &f->u.ack.largest));
        TRY (get_vi (c, &f->u.ack.delay));
        TRY (get_vi (c, &f->u.ack.range_count));
        start = c->p;
        TRY (ack_walk (c, f->u.ack.largest, f->u.ack.range_count,
                       NULL, NULL));
        f->u.ack.ranges.data = start;
        f->u.ack.ranges.len = (size_t) (c->p - start);
        if (t == T_ACK_ECN)
          {
            f->u.ack.has_ecn = 1;
            TRY (get_vi (c, &f->u.ack.ect0));
            TRY (get_vi (c, &f->u.ack.ect1));
            TRY (get_vi (c, &f->u.ack.ecn_ce));
          }
        return GQ_OK;
      }

    case T_RESET_STREAM:
      f->type = GQ_FRAME_RESET_STREAM;
      TRY (get_vi (c, &f->u.reset_stream.id));
      TRY (get_vi (c, &f->u.reset_stream.error));
      return get_vi (c, &f->u.reset_stream.final_size);

    case T_STOP_SENDING:
      f->type = GQ_FRAME_STOP_SENDING;
      TRY (get_vi (c, &f->u.stop_sending.id));
      return get_vi (c, &f->u.stop_sending.error);

    case T_CRYPTO:
      f->type = GQ_FRAME_CRYPTO;
      TRY (get_vi (c, &f->u.crypto.offset));
      TRY (get_vi (c, &a));
      return get_bytes (c, a, &f->u.crypto.data);

    case T_NEW_TOKEN:
      f->type = GQ_FRAME_NEW_TOKEN;
      TRY (get_vi (c, &a));
      if (a == 0)		/* RFC 9000 19.7: empty token is an error.  */
        return GQ_ERR_ENCODING;
      return get_bytes (c, a, &f->u.new_token.token);

    case T_MAX_DATA:
      f->type = GQ_FRAME_MAX_DATA;
      return get_vi (c, &f->u.max_data.max);

    case T_MAX_STREAM_DATA:
      f->type = GQ_FRAME_MAX_STREAM_DATA;
      TRY (get_vi (c, &f->u.max_stream_data.id));
      return get_vi (c, &f->u.max_stream_data.max);

    case T_MAX_STREAMS_BIDI:
    case T_MAX_STREAMS_UNI:
      f->type = GQ_FRAME_MAX_STREAMS;
      f->u.max_streams.bidi = (t == T_MAX_STREAMS_BIDI);
      TRY (get_vi (c, &f->u.max_streams.max));
      /* Limits above 2^60 cannot be expressed as stream IDs.  */
      return f->u.max_streams.max > (UINT64_C (1) << 60)
        ? GQ_ERR_ENCODING : GQ_OK;

    case T_DATA_BLOCKED:
      f->type = GQ_FRAME_DATA_BLOCKED;
      return get_vi (c, &f->u.data_blocked.limit);

    case T_STREAM_DATA_BLOCKED:
      f->type = GQ_FRAME_STREAM_DATA_BLOCKED;
      TRY (get_vi (c, &f->u.stream_data_blocked.id));
      return get_vi (c, &f->u.stream_data_blocked.limit);

    case T_STREAMS_BLOCKED_BIDI:
    case T_STREAMS_BLOCKED_UNI:
      f->type = GQ_FRAME_STREAMS_BLOCKED;
      f->u.streams_blocked.bidi = (t == T_STREAMS_BLOCKED_BIDI);
      TRY (get_vi (c, &f->u.streams_blocked.limit));
      return f->u.streams_blocked.limit > (UINT64_C (1) << 60)
        ? GQ_ERR_ENCODING : GQ_OK;

    case T_NEW_CONNECTION_ID:
      f->type = GQ_FRAME_NEW_CONNECTION_ID;
      TRY (get_vi (c, &f->u.new_connection_id.seq));
      TRY (get_vi (c, &f->u.new_connection_id.retire_prior_to));
      TRY (get_byte (c, &byte));
      if (byte < 1 || byte > GQ_MAX_CID_LEN
          || f->u.new_connection_id.retire_prior_to
             > f->u.new_connection_id.seq)
        return GQ_ERR_ENCODING;
      f->u.new_connection_id.cid_len = byte;
      TRY (get_fixed (c, f->u.new_connection_id.cid, byte));
      return get_fixed (c, f->u.new_connection_id.reset_token,
                        GQ_RESET_TOKEN_LEN);

    case T_RETIRE_CONNECTION_ID:
      f->type = GQ_FRAME_RETIRE_CONNECTION_ID;
      return get_vi (c, &f->u.retire_connection_id.seq);

    case T_PATH_CHALLENGE:
    case T_PATH_RESPONSE:
      f->type = (t == T_PATH_CHALLENGE) ? GQ_FRAME_PATH_CHALLENGE
                                        : GQ_FRAME_PATH_RESPONSE;
      return get_fixed (c, f->u.path_challenge.data, 8);

    case T_CONNECTION_CLOSE:
    case T_CONNECTION_CLOSE_APP:
      f->type = GQ_FRAME_CONNECTION_CLOSE;
      f->u.connection_close.application = (t == T_CONNECTION_CLOSE_APP);
      TRY (get_vi (c, &f->u.connection_close.error));
      if (t == T_CONNECTION_CLOSE)
        TRY (get_vi (c, &f->u.connection_close.frame_type));
      TRY (get_vi (c, &a));
      return get_bytes (c, a, &f->u.connection_close.reason);

    case T_HANDSHAKE_DONE:
      f->type = GQ_FRAME_HANDSHAKE_DONE;
      return GQ_OK;

    case T_DATAGRAM:
      f->type = GQ_FRAME_DATAGRAM;
      return get_bytes (c, c->n, &f->u.datagram.data);

    case T_DATAGRAM_LEN:
      f->type = GQ_FRAME_DATAGRAM;
      TRY (get_vi (c, &a));
      return get_bytes (c, a, &f->u.datagram.data);

    default:
      break;
    }

  if (t >= T_STREAM_MIN && t <= T_STREAM_MAX)
    {
      f->type = GQ_FRAME_STREAM;
      f->u.stream.fin = (t & STREAM_FIN) != 0;
      TRY (get_vi (c, &f->u.stream.id));
      if (t & STREAM_OFF)
        TRY (get_vi (c, &f->u.stream.offset));
      if (t & STREAM_LEN)
        TRY (get_vi (c, &b));
      else
        b = c->n;		/* Extends to the end of the packet.  */
      TRY (get_bytes (c, b, &f->u.stream.data));
      /* The final size must be representable (RFC 9000 4.5).  */
      return f->u.stream.offset + f->u.stream.data.len > GQ_VARINT_MAX
        ? GQ_ERR_ENCODING : GQ_OK;
    }

  return GQ_ERR_ENCODING;
}

int
gq_frame_parse (const uint8_t **buf, size_t *len, gq_frame_cb cb, void *user)
{
  while (*len > 0)
    {
      struct cur c = { *buf, *len };
      gq_frame f;
      int r = parse_one (&c, &f);

      if (r != GQ_OK)
        return r;		/* *buf and *len still at frame start.  */

      *buf = c.p;
      *len = c.n;
      if (cb && cb (user, &f))
        return GQ_ERR_HANDLER;
    }
  return GQ_OK;
}

int
gq_ack_foreach (const gq_frame *ack,
                int (*cb) (void *, uint64_t, uint64_t), void *user)
{
  struct cur c;
  int r;

  if (ack == NULL || ack->type != GQ_FRAME_ACK || cb == NULL)
    return GQ_ERR_INVAL;
  c.p = ack->u.ack.ranges.data;
  c.n = ack->u.ack.ranges.len;
  r = ack_walk (&c, ack->u.ack.largest, ack->u.ack.range_count, cb, user);
  return (r == GQ_NEED_MORE) ? GQ_ERR_INVAL : r;
}

/* ------------------------------------------------------------------ */
/* Writing                                                            */
/* ------------------------------------------------------------------ */

struct wr
{
  uint8_t *p;
  size_t cap;
  size_t off;
};

static int
put_vi (struct wr *w, uint64_t v)
{
  size_t n = gq_varint_size (v);

  if (n == 0)
    return GQ_ERR_RANGE;
  if (w->cap - w->off < n)
    return GQ_ERR_BUFSIZE;
  gq_varint_encode (v, w->p + w->off, n);
  w->off += n;
  return GQ_OK;
}

static int
put_bytes (struct wr *w, const void *src, size_t len)
{
  if (w->cap - w->off < len)
    return GQ_ERR_BUFSIZE;
  if (len)
    memcpy (w->p + w->off, src, len);
  w->off += len;
  return GQ_OK;
}

static int
put_slice (struct wr *w, const gq_slice *s)
{
  TRY (put_vi (w, s->len));
  return put_bytes (w, s->data, s->len);
}

int
gq_frame_write (const gq_frame *f, uint8_t *out, size_t outlen,
                size_t *written)
{
  struct wr w = { out, outlen, 0 };

  if (f == NULL || (out == NULL && outlen > 0) || written == NULL)
    return GQ_ERR_INVAL;

  switch (f->type)
    {
    case GQ_FRAME_PADDING:
      if (f->u.padding.len == 0)
        return GQ_ERR_INVAL;
      if (outlen < f->u.padding.len)
        return GQ_ERR_BUFSIZE;
      memset (out, 0, f->u.padding.len);
      w.off = f->u.padding.len;
      break;

    case GQ_FRAME_PING:
      TRY (put_vi (&w, T_PING));
      break;

    case GQ_FRAME_ACK:
      TRY (put_vi (&w, f->u.ack.has_ecn ? T_ACK_ECN : T_ACK));
      TRY (put_vi (&w, f->u.ack.largest));
      TRY (put_vi (&w, f->u.ack.delay));
      TRY (put_vi (&w, f->u.ack.range_count));
      TRY (put_bytes (&w, f->u.ack.ranges.data, f->u.ack.ranges.len));
      if (f->u.ack.has_ecn)
        {
          TRY (put_vi (&w, f->u.ack.ect0));
          TRY (put_vi (&w, f->u.ack.ect1));
          TRY (put_vi (&w, f->u.ack.ecn_ce));
        }
      break;

    case GQ_FRAME_RESET_STREAM:
      TRY (put_vi (&w, T_RESET_STREAM));
      TRY (put_vi (&w, f->u.reset_stream.id));
      TRY (put_vi (&w, f->u.reset_stream.error));
      TRY (put_vi (&w, f->u.reset_stream.final_size));
      break;

    case GQ_FRAME_STOP_SENDING:
      TRY (put_vi (&w, T_STOP_SENDING));
      TRY (put_vi (&w, f->u.stop_sending.id));
      TRY (put_vi (&w, f->u.stop_sending.error));
      break;

    case GQ_FRAME_CRYPTO:
      TRY (put_vi (&w, T_CRYPTO));
      TRY (put_vi (&w, f->u.crypto.offset));
      TRY (put_slice (&w, &f->u.crypto.data));
      break;

    case GQ_FRAME_NEW_TOKEN:
      if (f->u.new_token.token.len == 0)
        return GQ_ERR_INVAL;
      TRY (put_vi (&w, T_NEW_TOKEN));
      TRY (put_slice (&w, &f->u.new_token.token));
      break;

    case GQ_FRAME_STREAM:
      {
        uint64_t t = T_STREAM_MIN | STREAM_LEN;

        if (f->u.stream.offset)
          t |= STREAM_OFF;
        if (f->u.stream.fin)
          t |= STREAM_FIN;
        TRY (put_vi (&w, t));
        TRY (put_vi (&w, f->u.stream.id));
        if (f->u.stream.offset)
          TRY (put_vi (&w, f->u.stream.offset));
        TRY (put_slice (&w, &f->u.stream.data));
        break;
      }

    case GQ_FRAME_MAX_DATA:
      TRY (put_vi (&w, T_MAX_DATA));
      TRY (put_vi (&w, f->u.max_data.max));
      break;

    case GQ_FRAME_MAX_STREAM_DATA:
      TRY (put_vi (&w, T_MAX_STREAM_DATA));
      TRY (put_vi (&w, f->u.max_stream_data.id));
      TRY (put_vi (&w, f->u.max_stream_data.max));
      break;

    case GQ_FRAME_MAX_STREAMS:
      TRY (put_vi (&w, f->u.max_streams.bidi ? T_MAX_STREAMS_BIDI
                                             : T_MAX_STREAMS_UNI));
      TRY (put_vi (&w, f->u.max_streams.max));
      break;

    case GQ_FRAME_DATA_BLOCKED:
      TRY (put_vi (&w, T_DATA_BLOCKED));
      TRY (put_vi (&w, f->u.data_blocked.limit));
      break;

    case GQ_FRAME_STREAM_DATA_BLOCKED:
      TRY (put_vi (&w, T_STREAM_DATA_BLOCKED));
      TRY (put_vi (&w, f->u.stream_data_blocked.id));
      TRY (put_vi (&w, f->u.stream_data_blocked.limit));
      break;

    case GQ_FRAME_STREAMS_BLOCKED:
      TRY (put_vi (&w, f->u.streams_blocked.bidi ? T_STREAMS_BLOCKED_BIDI
                                                 : T_STREAMS_BLOCKED_UNI));
      TRY (put_vi (&w, f->u.streams_blocked.limit));
      break;

    case GQ_FRAME_NEW_CONNECTION_ID:
      if (f->u.new_connection_id.cid_len < 1
          || f->u.new_connection_id.cid_len > GQ_MAX_CID_LEN)
        return GQ_ERR_INVAL;
      TRY (put_vi (&w, T_NEW_CONNECTION_ID));
      TRY (put_vi (&w, f->u.new_connection_id.seq));
      TRY (put_vi (&w, f->u.new_connection_id.retire_prior_to));
      TRY (put_bytes (&w, &f->u.new_connection_id.cid_len, 1));
      TRY (put_bytes (&w, f->u.new_connection_id.cid,
                      f->u.new_connection_id.cid_len));
      TRY (put_bytes (&w, f->u.new_connection_id.reset_token,
                      GQ_RESET_TOKEN_LEN));
      break;

    case GQ_FRAME_RETIRE_CONNECTION_ID:
      TRY (put_vi (&w, T_RETIRE_CONNECTION_ID));
      TRY (put_vi (&w, f->u.retire_connection_id.seq));
      break;

    case GQ_FRAME_PATH_CHALLENGE:
    case GQ_FRAME_PATH_RESPONSE:
      TRY (put_vi (&w, f->type == GQ_FRAME_PATH_CHALLENGE
                       ? T_PATH_CHALLENGE : T_PATH_RESPONSE));
      TRY (put_bytes (&w, f->u.path_challenge.data, 8));
      break;

    case GQ_FRAME_CONNECTION_CLOSE:
      TRY (put_vi (&w, f->u.connection_close.application
                       ? T_CONNECTION_CLOSE_APP : T_CONNECTION_CLOSE));
      TRY (put_vi (&w, f->u.connection_close.error));
      if (!f->u.connection_close.application)
        TRY (put_vi (&w, f->u.connection_close.frame_type));
      TRY (put_slice (&w, &f->u.connection_close.reason));
      break;

    case GQ_FRAME_HANDSHAKE_DONE:
      TRY (put_vi (&w, T_HANDSHAKE_DONE));
      break;

    case GQ_FRAME_DATAGRAM:
      TRY (put_vi (&w, T_DATAGRAM_LEN));
      TRY (put_slice (&w, &f->u.datagram.data));
      break;

    default:
      return GQ_ERR_INVAL;
    }

  *written = w.off;
  return GQ_OK;
}

int
gq_ack_ranges_encode (const gq_ack_range *r, size_t n,
                      uint8_t *out, size_t outlen, size_t *written)
{
  struct wr w = { out, outlen, 0 };
  size_t i;

  if (r == NULL || n == 0 || (out == NULL && outlen > 0) || written == NULL)
    return GQ_ERR_INVAL;

  for (i = 0; i < n; i++)
    {
      if (r[i].lo > r[i].hi)
        return GQ_ERR_RANGE;
      if (i == 0)
        TRY (put_vi (&w, r[0].hi - r[0].lo));
      else
        {
          /* Need at least one unacknowledged number between ranges.  */
          if (r[i - 1].lo < 2 || r[i].hi > r[i - 1].lo - 2)
            return GQ_ERR_RANGE;
          TRY (put_vi (&w, r[i - 1].lo - r[i].hi - 2));
          TRY (put_vi (&w, r[i].hi - r[i].lo));
        }
    }
  *written = w.off;
  return GQ_OK;
}
