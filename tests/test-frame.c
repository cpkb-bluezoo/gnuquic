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

#include <stdarg.h>

#include <gnuquic/status.h>
#include <gnuquic/frame.h>

#include "tst-util.h"

/* ---- Event log: one line of text per event ---- */

struct log
{
  char text[8192];
  size_t len;
  int stop_after;		/* Abort once this many events were seen.  */
  int count;
};

static void
logf_ (struct log *l, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));

static void
logf_ (struct log *l, const char *fmt, ...)
{
  va_list ap;
  int n;

  va_start (ap, fmt);
  n = vsnprintf (l->text + l->len, sizeof l->text - l->len, fmt, ap);
  va_end (ap);
  if (n > 0 && (size_t) n < sizeof l->text - l->len)
    l->len += (size_t) n;
}

static void
log_hex (struct log *l, gq_slice s)
{
  size_t i;

  for (i = 0; i < s.len; i++)
    logf_ (l, "%02x", s.data[i]);
}

static int
log_range (void *u, uint64_t lo, uint64_t hi)
{
  logf_ (u, " [%llu-%llu]", (unsigned long long) lo, (unsigned long long) hi);
  return 0;
}

#define U(x) ((unsigned long long) (x))

static int
on_frame (void *user, const gq_frame *f)
{
  struct log *l = user;
  size_t i;

  switch (f->type)
    {
    case GQ_FRAME_PADDING:
      for (i = 0; i < f->u.padding.len; i++)	/* Split-invariant.  */
        logf_ (l, "PAD\n");
      break;
    case GQ_FRAME_PING: logf_ (l, "PING\n"); break;
    case GQ_FRAME_ACK:
      logf_ (l, "ACK largest=%llu delay=%llu n=%llu ecn=%d %llu/%llu/%llu:",
             U (f->u.ack.largest), U (f->u.ack.delay),
             U (f->u.ack.range_count), f->u.ack.has_ecn,
             U (f->u.ack.ect0), U (f->u.ack.ect1), U (f->u.ack.ecn_ce));
      gq_ack_foreach (f, log_range, l);
      logf_ (l, "\n");
      break;
    case GQ_FRAME_RESET_STREAM:
      logf_ (l, "RESET %llu %llu %llu\n", U (f->u.reset_stream.id),
             U (f->u.reset_stream.error), U (f->u.reset_stream.final_size));
      break;
    case GQ_FRAME_STOP_SENDING:
      logf_ (l, "STOP %llu %llu\n", U (f->u.stop_sending.id),
             U (f->u.stop_sending.error));
      break;
    case GQ_FRAME_CRYPTO:
      logf_ (l, "CRYPTO %llu ", U (f->u.crypto.offset));
      log_hex (l, f->u.crypto.data);
      logf_ (l, "\n");
      break;
    case GQ_FRAME_NEW_TOKEN:
      logf_ (l, "TOKEN ");
      log_hex (l, f->u.new_token.token);
      logf_ (l, "\n");
      break;
    case GQ_FRAME_STREAM:
      logf_ (l, "STREAM %llu off=%llu fin=%d ", U (f->u.stream.id),
             U (f->u.stream.offset), f->u.stream.fin);
      log_hex (l, f->u.stream.data);
      logf_ (l, "\n");
      break;
    case GQ_FRAME_MAX_DATA: logf_ (l, "MAXDATA %llu\n", U (f->u.max_data.max)); break;
    case GQ_FRAME_MAX_STREAM_DATA:
      logf_ (l, "MAXSD %llu %llu\n", U (f->u.max_stream_data.id),
             U (f->u.max_stream_data.max));
      break;
    case GQ_FRAME_MAX_STREAMS:
      logf_ (l, "MAXSTREAMS %d %llu\n", f->u.max_streams.bidi,
             U (f->u.max_streams.max));
      break;
    case GQ_FRAME_DATA_BLOCKED:
      logf_ (l, "DBLOCKED %llu\n", U (f->u.data_blocked.limit));
      break;
    case GQ_FRAME_STREAM_DATA_BLOCKED:
      logf_ (l, "SDBLOCKED %llu %llu\n", U (f->u.stream_data_blocked.id),
             U (f->u.stream_data_blocked.limit));
      break;
    case GQ_FRAME_STREAMS_BLOCKED:
      logf_ (l, "SBLOCKED %d %llu\n", f->u.streams_blocked.bidi,
             U (f->u.streams_blocked.limit));
      break;
    case GQ_FRAME_NEW_CONNECTION_ID:
      logf_ (l, "NCID %llu %llu ", U (f->u.new_connection_id.seq),
             U (f->u.new_connection_id.retire_prior_to));
      for (i = 0; i < f->u.new_connection_id.cid_len; i++)
        logf_ (l, "%02x", f->u.new_connection_id.cid[i]);
      logf_ (l, " %02x%02x\n", f->u.new_connection_id.reset_token[0],
             f->u.new_connection_id.reset_token[15]);
      break;
    case GQ_FRAME_RETIRE_CONNECTION_ID:
      logf_ (l, "RCID %llu\n", U (f->u.retire_connection_id.seq));
      break;
    case GQ_FRAME_PATH_CHALLENGE:
    case GQ_FRAME_PATH_RESPONSE:
      logf_ (l, "PATH%d ", f->type == GQ_FRAME_PATH_CHALLENGE);
      for (i = 0; i < 8; i++)
        logf_ (l, "%02x", f->u.path_challenge.data[i]);
      logf_ (l, "\n");
      break;
    case GQ_FRAME_CONNECTION_CLOSE:
      logf_ (l, "CLOSE app=%d %llu %llu ", f->u.connection_close.application,
             U (f->u.connection_close.error),
             U (f->u.connection_close.frame_type));
      log_hex (l, f->u.connection_close.reason);
      logf_ (l, "\n");
      break;
    case GQ_FRAME_HANDSHAKE_DONE: logf_ (l, "HSDONE\n"); break;
    case GQ_FRAME_DATAGRAM:
      logf_ (l, "DGRAM ");
      log_hex (l, f->u.datagram.data);
      logf_ (l, "\n");
      break;
    }
  l->count++;
  return l->stop_after && l->count >= l->stop_after;
}

/* ---- Building a corpus containing every frame type ---- */

static size_t
build_corpus (uint8_t *out, size_t cap)
{
  static const uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef, 0x01 };
  static const gq_ack_range ranges[] = { { 90, 100 }, { 70, 80 }, { 10, 10 } };
  uint8_t rsec[32];
  size_t rlen, off = 0, w;
  gq_frame f;
  gq_slice d = { data, sizeof data };
  int r;

#define EMIT() \
  do { \
    r = gq_frame_write (&f, out + off, cap - off, &w); \
    CHECK_EQ (r, GQ_OK); \
    off += w; \
  } while (0)

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_PADDING; f.u.padding.len = 1; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_PING; EMIT ();

  CHECK_EQ (gq_ack_ranges_encode (ranges, 3, rsec, sizeof rsec, &rlen), GQ_OK);
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_ACK;
  f.u.ack.largest = 100; f.u.ack.delay = 25; f.u.ack.range_count = 2;
  f.u.ack.ranges.data = rsec; f.u.ack.ranges.len = rlen;
  f.u.ack.has_ecn = 1; f.u.ack.ect0 = 1; f.u.ack.ect1 = 2; f.u.ack.ecn_ce = 3;
  EMIT ();

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_RESET_STREAM;
  f.u.reset_stream.id = 4; f.u.reset_stream.error = 300;
  f.u.reset_stream.final_size = 70000; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_STOP_SENDING;
  f.u.stop_sending.id = 8; f.u.stop_sending.error = 7; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_CRYPTO; f.u.crypto.offset = 1000; f.u.crypto.data = d; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_NEW_TOKEN; f.u.new_token.token = d; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_STREAM; f.u.stream.id = 12; f.u.stream.offset = 5;
  f.u.stream.data = d; f.u.stream.fin = 1; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_STREAM; f.u.stream.id = 0; f.u.stream.data = d; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_MAX_DATA; f.u.max_data.max = 1 << 20; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_MAX_STREAM_DATA;
  f.u.max_stream_data.id = 4; f.u.max_stream_data.max = 99999; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_MAX_STREAMS; f.u.max_streams.max = 100; EMIT ();
  f.u.max_streams.bidi = 1; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_DATA_BLOCKED; f.u.data_blocked.limit = 5000; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_STREAM_DATA_BLOCKED;
  f.u.stream_data_blocked.id = 16; f.u.stream_data_blocked.limit = 42; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_STREAMS_BLOCKED; f.u.streams_blocked.bidi = 1;
  f.u.streams_blocked.limit = 3; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_NEW_CONNECTION_ID;
  f.u.new_connection_id.seq = 2; f.u.new_connection_id.retire_prior_to = 1;
  f.u.new_connection_id.cid_len = 8;
  memcpy (f.u.new_connection_id.cid, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
  memset (f.u.new_connection_id.reset_token, 0xab, 16);
  f.u.new_connection_id.reset_token[0] = 0x11; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_RETIRE_CONNECTION_ID;
  f.u.retire_connection_id.seq = 1; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_PATH_CHALLENGE;
  memcpy (f.u.path_challenge.data, "12345678", 8); EMIT ();
  f.type = GQ_FRAME_PATH_RESPONSE; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_CONNECTION_CLOSE; f.u.connection_close.error = 0x0a;
  f.u.connection_close.frame_type = 0x06; f.u.connection_close.reason = d; EMIT ();
  f.u.connection_close.application = 1; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_HANDSHAKE_DONE; EMIT ();
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_DATAGRAM; f.u.datagram.data = d; EMIT ();
  return off;
}

/* Feed CORPUS in chunks of CHUNK bytes, carrying the unconsumed tail
   across calls exactly as a real caller would.  */
static int
feed_chunked (const uint8_t *corpus, size_t n, size_t chunk, struct log *l)
{
  uint8_t pending[2048];
  size_t plen = 0, pos = 0;

  while (pos < n)
    {
      size_t take = n - pos < chunk ? n - pos : chunk;
      const uint8_t *p;
      size_t len, used;
      int r;

      memcpy (pending + plen, corpus + pos, take);
      plen += take;
      pos += take;

      p = pending;
      len = plen;
      r = gq_frame_parse (&p, &len, on_frame, l);
      if (r != GQ_OK && r != GQ_NEED_MORE)
        return r;
      used = plen - len;
      memmove (pending, pending + used, len);
      plen = len;
    }
  return plen == 0 ? GQ_OK : GQ_NEED_MORE;
}

static void
test_chunk_splits (void)
{
  uint8_t corpus[2048];
  static struct log whole, split;
  size_t n = build_corpus (corpus, sizeof corpus);
  size_t chunk;

  CHECK (n > 100);
  CHECK_EQ (feed_chunked (corpus, n, n, &whole), GQ_OK);
  CHECK (whole.count == 24);

  for (chunk = 1; chunk <= 64; chunk++)
    {
      memset (&split, 0, sizeof split);
      CHECK_EQ (feed_chunked (corpus, n, chunk, &split), GQ_OK);
      if (strcmp (whole.text, split.text) != 0)
        {
          fprintf (stderr, "chunk size %zu diverged\n", chunk);
          tst_failures++;
          break;
        }
    }

  /* Golden spot checks so a symmetric bug in writer+parser is caught.  */
  CHECK (strstr (whole.text, "ACK largest=100 delay=25 n=2 ecn=1 1/2/3: "
                             "[90-100] [70-80] [10-10]\n"));
  CHECK (strstr (whole.text, "STREAM 12 off=5 fin=1 deadbeef01\n"));
  CHECK (strstr (whole.text, "NCID 2 1 0102030405060708 11ab\n"));
}

static int
parse_all (const char *hex, size_t *left, struct log *l)
{
  static uint8_t b[256];
  size_t n = tst_unhex (hex, b, sizeof b);
  const uint8_t *p = b;
  int r = gq_frame_parse (&p, &n, on_frame, l);

  if (left)
    *left = n;
  return r;
}

static void
test_errors (void)
{
  static struct log l;
  size_t left;

  /* ACK whose first range is longer than largest.  */
  CHECK_EQ (parse_all ("02050000""06", &left, &l), GQ_ERR_ENCODING);
  /* ACK whose gap runs below zero.  */
  CHECK_EQ (parse_all ("020a00010a00""00", &left, &l), GQ_ERR_ENCODING);
  /* Reserved/unknown type.  */
  CHECK_EQ (parse_all ("1f", &left, &l), GQ_ERR_ENCODING);
  CHECK_EQ (parse_all ("2f", &left, &l), GQ_ERR_ENCODING);
  /* Empty NEW_TOKEN.  */
  CHECK_EQ (parse_all ("0700", &left, &l), GQ_ERR_ENCODING);
  /* NEW_CONNECTION_ID with zero-length CID.  */
  CHECK_EQ (parse_all ("18010000""00000000000000000000000000000000", &left, &l),
            GQ_ERR_ENCODING);
  /* MAX_STREAMS above 2^60.  */
  CHECK_EQ (parse_all ("12d000000000000001", &left, &l), GQ_ERR_ENCODING);

  /* Truncated CRYPTO: NEED_MORE and the buffer stays at frame start.  */
  memset (&l, 0, sizeof l);
  CHECK_EQ (parse_all ("01""060005aabb", &left, &l), GQ_NEED_MORE);
  CHECK_EQ (left, 5);
  CHECK (strstr (l.text, "PING") != NULL);

  /* STREAM without a length runs to the end of the buffer.  */
  memset (&l, 0, sizeof l);
  CHECK_EQ (parse_all ("0800aabbcc", &left, &l), GQ_OK);
  CHECK (strstr (l.text, "STREAM 0 off=0 fin=0 aabbcc\n"));

  /* Handler abort.  */
  memset (&l, 0, sizeof l);
  l.stop_after = 1;
  CHECK_EQ (parse_all ("010101", &left, &l), GQ_ERR_HANDLER);
  CHECK_EQ (left, 2);
}

static void
test_ack_encode_validation (void)
{
  uint8_t out[16];
  size_t w;
  gq_ack_range adj[] = { { 5, 9 }, { 1, 4 } };	/* Adjacent: illegal.  */
  gq_ack_range ok[] = { { 5, 9 }, { 1, 3 } };
  gq_ack_range backwards[] = { { 9, 5 } };

  CHECK_EQ (gq_ack_ranges_encode (adj, 2, out, sizeof out, &w), GQ_ERR_RANGE);
  CHECK_EQ (gq_ack_ranges_encode (ok, 2, out, sizeof out, &w), GQ_OK);
  CHECK_EQ (gq_ack_ranges_encode (backwards, 1, out, sizeof out, &w),
            GQ_ERR_RANGE);
  CHECK_EQ (gq_ack_ranges_encode (ok, 2, out, 2, &w), GQ_ERR_BUFSIZE);
}

int
main (void)
{
  test_chunk_splits ();
  test_errors ();
  test_ack_encode_validation ();
  TST_DONE ();
}
