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

/* DTLS 1.3 handshake codecs: fragment events, reassembly under every
   fragmentation and delivery order, and ACK encoding.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/dtlshs.h>

#include "tst-util.h"

/* ---- Fragment events ---- */

struct frags
{
  int n;
  gq_dtls_hs_frag f[8];
};

static int
on_frag (void *u, const gq_dtls_hs_frag *f)
{
  struct frags *l = u;

  if (l->n < 8)
    l->f[l->n++] = *f;
  return 0;
}

static void
test_parse (void)
{
  uint8_t d[200], body[30];
  gq_wbuf w;
  struct frags l;
  size_t i, n;

  for (i = 0; i < sizeof body; i++)
    body[i] = (uint8_t) i;
  gq_wbuf_init (&w, d, sizeof d);
  gq_dtls_put_hs_frag (&w, 11, 100, 5, 0, body, 30);
  gq_dtls_put_hs_frag (&w, 11, 100, 5, 30, body, 10);
  gq_dtls_put_hs_frag (&w, 20, 4, 6, 0, body, 4);
  CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
  n = w.len;
  CHECK_EQ (n, (size_t) (12 * 3 + 44));

  memset (&l, 0, sizeof l);
  CHECK_EQ (gq_dtls_hs_parse ((gq_slice) { d, n }, 65536, on_frag, &l), GQ_OK);
  CHECK_EQ (l.n, 3);
  CHECK (l.f[0].type == 11 && l.f[0].length == 100 && l.f[0].message_seq == 5
         && l.f[0].frag_off == 0 && l.f[0].frag_len == 30
         && l.f[0].data.data == d + 12);
  CHECK (l.f[1].frag_off == 30 && l.f[1].frag_len == 10);
  CHECK (l.f[2].type == 20 && l.f[2].message_seq == 6);

  /* Every truncation is refused, never delivered half.  */
  for (i = 1; i < n; i++)
    {
      int r;

      memset (&l, 0, sizeof l);
      r = gq_dtls_hs_parse ((gq_slice) { d, i }, 65536, on_frag, &l);
      if (i == 12 + 30 || i == 12 + 30 + 12 + 10)
        CHECK_EQ (r, GQ_OK);
      else
        CHECK_EQ (r, GQ_ERR_ENCODING);
    }
  /* Fragment beyond its message, and a message over the limit.  */
  gq_wbuf_init (&w, d, sizeof d);
  gq_dtls_put_hs_frag (&w, 11, 20, 0, 15, body, 10);
  CHECK_EQ (gq_dtls_hs_parse ((gq_slice) { d, w.len }, 65536, on_frag, &l),
            GQ_ERR_ENCODING);
  gq_wbuf_init (&w, d, sizeof d);
  gq_dtls_put_hs_frag (&w, 11, 70000, 0, 0, body, 10);
  CHECK_EQ (gq_dtls_hs_parse ((gq_slice) { d, w.len }, 65536, on_frag, &l),
            GQ_ERR_PROTOCOL);
}

/* ---- Reassembly ---- */

struct delivered
{
  int n;
  unsigned type[4];
  uint8_t data[4][3000];
  size_t len[4];
};

static int
on_msg (void *u, unsigned type, gq_slice m)
{
  struct delivered *d = u;

  if (d->n < 4)
    {
      d->type[d->n] = type;
      memcpy (d->data[d->n], m.data, m.len);
      d->len[d->n++] = m.len;
    }
  return 0;
}

/* The TLS-format message for BODY (LEN bytes).  */
static size_t
tls_msg (uint8_t *out, unsigned type, const uint8_t *body, size_t len)
{
  out[0] = (uint8_t) type;
  out[1] = (uint8_t) (len >> 16);
  out[2] = (uint8_t) (len >> 8);
  out[3] = (uint8_t) len;
  memcpy (out + 4, body, len);
  return 4 + len;
}

static void
push (gq_dtls_reasm *r, struct delivered *d, unsigned type, uint32_t len,
      uint16_t seq, uint32_t off, const uint8_t *body, size_t n, int expect)
{
  gq_dtls_hs_frag f;

  f.type = type;
  f.length = len;
  f.message_seq = seq;
  f.frag_off = off;
  f.frag_len = (uint32_t) n;
  f.data.data = body + off;
  f.data.len = n;
  CHECK_EQ (gq_dtls_reasm_push (r, &f, on_msg, d), expect);
}

static uint32_t rng = 99;

static uint32_t
rnd (void)
{
  rng = rng * 1103515245u + 12345u;
  return rng >> 8;
}

static void
test_reassembly (void)
{
  static uint8_t body[2500];
  uint8_t want[2504];
  size_t i, fs;
  int round;

  for (i = 0; i < sizeof body; i++)
    body[i] = (uint8_t) (i * 13 + i / 256);
  tls_msg (want, 11, body, sizeof body);

  /* In order, for every fragment size from 1 (sampled) to whole.  */
  for (fs = 1; fs <= sizeof body; fs += (fs < 40 ? 1 : 97))
    {
      gq_dtls_reasm r;
      struct delivered d;
      size_t off;

      memset (&d, 0, sizeof d);
      gq_dtls_reasm_init (&r, 65536, 4);
      for (off = 0; off < sizeof body; off += fs)
        {
          size_t n = sizeof body - off < fs ? sizeof body - off : fs;
          int last = off + n == sizeof body;

          push (&r, &d, 11, sizeof body, 4, (uint32_t) off, body, n,
                last ? GQ_DRX_DELIVERED : GQ_DRX_BUFFERED);
        }
      CHECK_EQ (d.n, 1);
      CHECK (d.type[0] == 11 && d.len[0] == sizeof want
             && memcmp (d.data[0], want, sizeof want) == 0);
      CHECK (!gq_dtls_reasm_partial (&r));
      CHECK_EQ (r.next_seq, 5);
      gq_dtls_reasm_free (&r);
    }

  /* Shuffled fragments with duplicates and overlaps: same result.  */
  for (round = 0; round < 300; round++)
    {
      gq_dtls_reasm r;
      struct delivered d;
      uint32_t piece[64], plen[64];
      size_t np = 0, off = 0, k, j;
      int fin = 0;

      memset (&d, 0, sizeof d);
      gq_dtls_reasm_init (&r, 65536, 0);
      fs = 60 + rnd () % 400;
      while (off < sizeof body)
        {
          piece[np] = (uint32_t) off;
          plen[np] = (uint32_t) (sizeof body - off < fs ? sizeof body - off : fs);
          off += plen[np++];
        }
      /* Overlapping extra pieces (retransmission with other sizes).  */
      for (k = 0; k < 6 && np < 64; k++)
        {
          piece[np] = rnd () % (uint32_t) sizeof body;
          plen[np] = 1 + rnd () % 300;
          if (piece[np] + plen[np] > sizeof body)
            plen[np] = (uint32_t) sizeof body - piece[np];
          np++;
        }
      for (k = np; k > 1; k--)		/* Fisher-Yates.  */
        {
          j = rnd () % k;
          { uint32_t a = piece[j], b = plen[j];
            piece[j] = piece[k - 1]; plen[j] = plen[k - 1];
            piece[k - 1] = a; plen[k - 1] = b; }
        }
      for (k = 0; k < np && !fin; k++)
        {
          gq_dtls_hs_frag f;
          int rc;

          f.type = 11; f.length = sizeof body; f.message_seq = 0;
          f.frag_off = piece[k]; f.frag_len = plen[k];
          f.data.data = body + piece[k]; f.data.len = plen[k];
          rc = gq_dtls_reasm_push (&r, &f, on_msg, &d);
          CHECK (rc == GQ_DRX_BUFFERED || rc == GQ_DRX_DUPLICATE
                 || rc == GQ_DRX_DELIVERED || rc == GQ_DRX_DROPPED);
          fin = rc == GQ_DRX_DELIVERED;
        }
      if (!fin)
        {
          /* Too fragmented for the range list: a clean resend finishes it.  */
          push (&r, &d, 11, sizeof body, 0, 0, body, sizeof body,
                GQ_DRX_DELIVERED);
        }
      CHECK_EQ (d.n, 1);
      CHECK (d.len[0] == sizeof want && memcmp (d.data[0], want, sizeof want) == 0);
      gq_dtls_reasm_free (&r);
    }
}

static void
test_ordering (void)
{
  static uint8_t a[100], b[10];
  gq_dtls_reasm r;
  struct delivered d;
  size_t i;

  for (i = 0; i < sizeof a; i++)
    a[i] = (uint8_t) i;
  memset (b, 0x5a, sizeof b);
  memset (&d, 0, sizeof d);
  gq_dtls_reasm_init (&r, 1000, 0);

  /* A later message is dropped (not ackable), and does not disturb the
     current one.  */
  push (&r, &d, 8, 10, 1, 0, b, 10, GQ_DRX_DROPPED);
  push (&r, &d, 11, 100, 0, 0, a, 60, GQ_DRX_BUFFERED);
  CHECK (gq_dtls_reasm_partial (&r));
  push (&r, &d, 8, 10, 1, 0, b, 10, GQ_DRX_DROPPED);
  /* Fragment of the current message that disagrees: type, length, bytes.  */
  {
    gq_dtls_hs_frag f;

    f.type = 12; f.length = 100; f.message_seq = 0; f.frag_off = 60;
    f.frag_len = 40; f.data.data = a + 60; f.data.len = 40;
    CHECK_EQ (gq_dtls_reasm_push (&r, &f, on_msg, &d), GQ_ERR_PROTOCOL);
    f.type = 11; f.length = 101;
    CHECK_EQ (gq_dtls_reasm_push (&r, &f, on_msg, &d), GQ_ERR_PROTOCOL);
    f.length = 100; f.frag_off = 50; f.frag_len = 20; f.data.data = b;
    f.data.len = 10;
    f.frag_len = 10;
    CHECK_EQ (gq_dtls_reasm_push (&r, &f, on_msg, &d), GQ_ERR_PROTOCOL);
  }
  push (&r, &d, 11, 100, 0, 60, a, 40, GQ_DRX_DELIVERED);
  CHECK_EQ (d.n, 1);
  CHECK_EQ (r.next_seq, 1);
  /* A repeat of it is a duplicate; then the next message goes in.  */
  push (&r, &d, 11, 100, 0, 0, a, 100, GQ_DRX_DUPLICATE);
  push (&r, &d, 8, 10, 1, 0, b, 10, GQ_DRX_DELIVERED);
  CHECK_EQ (d.n, 2);
  CHECK (d.type[1] == 8 && d.len[1] == 14);

  /* A zero-length message and the message_seq wrap.  */
  gq_dtls_reasm_init (&r, 1000, 0xffff);
  push (&r, &d, 20, 0, 0xffff, 0, b, 0, GQ_DRX_DELIVERED);
  CHECK_EQ (r.next_seq, 0);
  push (&r, &d, 20, 0, 0xffff, 0, b, 0, GQ_DRX_DUPLICATE);
  CHECK_EQ (d.n, 3);

  /* Messages over the limit.  */
  {
    gq_dtls_hs_frag f = { 11, 2000, 0, 0, 10, { b, 10 } };

    CHECK_EQ (gq_dtls_reasm_push (&r, &f, on_msg, &d), GQ_ERR_PROTOCOL);
  }
  gq_dtls_reasm_free (&r);
}

/* More disjoint pieces than the range list holds: dropped, never wrong.  */
static void
test_range_limit (void)
{
  static uint8_t body[400];
  gq_dtls_reasm r;
  struct delivered d;
  uint32_t off;
  int dropped = 0;

  memset (&d, 0, sizeof d);
  gq_dtls_reasm_init (&r, 1000, 0);
  for (off = 0; off < 400; off++)
    body[off] = (uint8_t) off;
  /* Ten separated 10-byte pieces (every other 20 bytes).  */
  for (off = 0; off < 400; off += 40)
    {
      gq_dtls_hs_frag f = { 11, 400, 0, off, 10, { body + off, 10 } };
      int rc = gq_dtls_reasm_push (&r, &f, on_msg, &d);

      if (rc == GQ_DRX_DROPPED)
        dropped++;
      else
        CHECK_EQ (rc, GQ_DRX_BUFFERED);
    }
  CHECK_EQ (dropped, 2);
  CHECK_EQ (d.n, 0);
  /* Fill the gaps in the retained pieces; the dropped ones come again.  */
  for (off = 10; off < 400; off += 10)
    {
      gq_dtls_hs_frag f = { 11, 400, 0, off, 10, { body + off, 10 } };
      int rc = gq_dtls_reasm_push (&r, &f, on_msg, &d);

      CHECK (rc == GQ_DRX_BUFFERED || rc == GQ_DRX_DUPLICATE
             || rc == GQ_DRX_DELIVERED);
    }
  {
    gq_dtls_hs_frag f = { 11, 400, 0, 0, 400, { body, 400 } };

    if (d.n == 0)
      CHECK_EQ (gq_dtls_reasm_push (&r, &f, on_msg, &d), GQ_DRX_DELIVERED);
  }
  CHECK_EQ (d.n, 1);
  CHECK (memcmp (d.data[0] + 4, body, 400) == 0);
  gq_dtls_reasm_free (&r);
}

static int
count_ack (void *u, gq_dtls_recno n)
{
  gq_dtls_recno *v = u;
  static int i;

  v[i++] = n;
  return 0;
}

static void
test_acks (void)
{
  gq_dtls_recno in[3] = { { 2, 0 }, { 3, 0x123456789abcull }, { 5, 1 } }, out[4];
  uint8_t d[100];
  gq_wbuf w;

  gq_wbuf_init (&w, d, sizeof d);
  gq_dtls_put_acks (&w, in, 3);
  CHECK_EQ (w.len, (size_t) 50);
  CHECK_EQ (gq_dtls_acks ((gq_slice) { d, w.len }, count_ack, out), GQ_OK);
  CHECK (out[0].epoch == 2 && out[1].seq == 0x123456789abcull
         && out[2].epoch == 5);
  /* An empty ACK, and malformed ones.  */
  gq_wbuf_init (&w, d, sizeof d);
  gq_dtls_put_acks (&w, in, 0);
  CHECK_EQ (gq_dtls_acks ((gq_slice) { d, w.len }, count_ack, out), GQ_OK);
  CHECK_EQ (gq_dtls_acks ((gq_slice) { d, 1 }, count_ack, out), GQ_ERR_ENCODING);
  d[1] = 15;
  CHECK_EQ (gq_dtls_acks ((gq_slice) { d, 17 }, count_ack, out), GQ_ERR_ENCODING);
  d[0] = 0; d[1] = 16;
  CHECK_EQ (gq_dtls_acks ((gq_slice) { d, 10 }, count_ack, out), GQ_ERR_ENCODING);
}

int
main (void)
{
  test_parse ();
  test_reassembly ();
  test_ordering ();
  test_range_limit ();
  test_acks ();
  TST_DONE ();
}
