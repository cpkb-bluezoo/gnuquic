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

/* Stream state machines: a lossy, reordering "network" between a send half
   and a receive half must deliver exactly the bytes written, once and in
   order; plus the flow control, final size and reset rules.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdint.h>

#include <gnuquic/status.h>
#include <gnuquic/stream.h>

#include "tst-util.h"

static uint32_t rng = 99;

static uint32_t
rnd (void)
{
  rng = rng * 1664525u + 1013904223u;
  return rng >> 8;
}

typedef struct sink
{
  uint8_t data[70000];
  uint64_t got;
  int fin, calls, bad;
} sink;

static int
on_data (void *user, uint64_t off, const uint8_t *d, size_t n, int fin)
{
  sink *k = user;

  if (off != k->got || k->fin)
    k->bad++;
  memcpy (k->data + off, d, n);
  k->got += n;
  k->calls++;
  if (fin)
    k->fin = 1;
  return 0;
}

typedef struct pkt
{
  uint64_t off;
  uint8_t data[1300];
  size_t len;
  int fin;
} pkt;

/* Drive one transfer; LOSS is the percentage of chunks dropped.  */
static void
transfer (size_t total, unsigned loss, size_t chunk, uint64_t credit,
          uint64_t window)
{
  gq_sstream s;
  gq_rstream r;
  static uint8_t src[70000];
  static sink k;
  pkt q[64];
  size_t nq = 0, written = 0, i;
  int rounds, finished = 0;
  uint64_t off, nb;
  const uint8_t *d;
  size_t n;
  int fin;

  for (i = 0; i < total; i++)
    src[i] = (uint8_t) (i * 7 + i / 251);
  memset (&k, 0, sizeof k);
  gq_sstream_init (&s, 2000, credit);
  gq_rstream_init (&r, window ? window : credit);

  for (rounds = 0; rounds < 200000 && !(k.fin && gq_sstream_state (&s)
                                        == GQ_SS_DATA_RECVD); rounds++)
    {
      long w;

      if (written < total)
        {
          size_t want = total - written;

          w = gq_sstream_write (&s, src + written, want > 700 ? 700 : want);
          CHECK (w >= 0);
          if (w > 0)
            written += (size_t) w;
        }
      if (written == total && !finished)
        {
          gq_sstream_finish (&s);
          finished = 1;
        }
      /* Sender emits a few chunks.  */
      while (nq < 60 && gq_sstream_next (&s, chunk, UINT64_MAX, &off, &d, &n,
                                         &fin, &nb))
        {
          if (rnd () % 100 < loss)
            gq_sstream_on_lost (&s, off, n, fin);	/* "Detected" lost.  */
          else
            {
              q[nq].off = off;
              q[nq].len = n;
              q[nq].fin = fin;
              memcpy (q[nq].data, d, n);
              nq++;
            }
        }
      /* Deliver in random order, sometimes duplicated.  */
      while (nq)
        {
          size_t j = rnd () % nq;
          int rc, dup = rnd () % 10 == 0;
          uint64_t up;

          rc = gq_rstream_push (&r, q[j].off, q[j].data, q[j].len, q[j].fin,
                                on_data, &k, &nb);
          CHECK_EQ (rc, GQ_OK);
          if (dup)
            CHECK_EQ (gq_rstream_push (&r, q[j].off, q[j].data, q[j].len,
                                       q[j].fin, on_data, &k, &nb), GQ_OK);
          gq_sstream_on_acked (&s, q[j].off, q[j].len, q[j].fin);
          q[j] = q[--nq];
          if (gq_rstream_take_update (&r, window ? window : credit, &up))
            gq_sstream_set_max (&s, up);
        }
    }
  CHECK (rounds < 200000);
  CHECK_EQ (k.got, total);
  CHECK_EQ (k.bad, 0);
  CHECK (k.fin);
  CHECK (memcmp (k.data, src, total) == 0);
  CHECK_EQ (gq_sstream_state (&s), GQ_SS_DATA_RECVD);
  CHECK_EQ (gq_rstream_state (&r), GQ_RS_DATA_READ);
  CHECK_EQ (s.len, 0);
  CHECK_EQ (r.have.n, 0);
  gq_sstream_free (&s);
  gq_rstream_free (&r);
}

static void
test_transfers (void)
{
  transfer (0, 0, 100, 1000, 1000);
  transfer (1, 0, 100, 1000, 1000);
  transfer (5000, 0, 100, 1u << 20, 0);
  transfer (60000, 20, 173, 1u << 20, 0);
  transfer (60000, 50, 1200, 1u << 20, 0);
  /* Tight flow control: credit is extended as data is consumed.  */
  transfer (40000, 10, 300, 1000, 1000);
  transfer (40000, 30, 50, 4000, 4000);
}

static void
test_send_states (void)
{
  gq_sstream s;
  uint64_t off, nb, err, fin_size;
  const uint8_t *d;
  size_t n;
  int fin;

  gq_sstream_init (&s, 100, 10);
  CHECK_EQ (gq_sstream_state (&s), GQ_SS_READY);
  CHECK_EQ (gq_sstream_write (&s, (const uint8_t *) "0123456789abcdef", 16), 16);
  CHECK_EQ (gq_sstream_state (&s), GQ_SS_SEND);
  /* Credit of 10 holds the rest back and reports blocked once.  */
  CHECK (gq_sstream_next (&s, 100, UINT64_MAX, &off, &d, &n, &fin, &nb));
  CHECK (off == 0 && n == 10 && !fin && nb == 10);
  CHECK (!gq_sstream_next (&s, 100, UINT64_MAX, &off, &d, &n, &fin, &nb));
  CHECK (gq_sstream_take_blocked (&s, &err) && err == 10);
  CHECK (!gq_sstream_take_blocked (&s, &err));
  CHECK (!gq_sstream_pending (&s, UINT64_MAX));
  gq_sstream_set_max (&s, 5);			/* Lower: ignored.  */
  CHECK_EQ (s.max_data, 10);
  gq_sstream_set_max (&s, 40);
  CHECK (gq_sstream_pending (&s, UINT64_MAX));
  /* Connection-level credit also limits new data.  */
  CHECK (gq_sstream_next (&s, 100, 2, &off, &d, &n, &fin, &nb));
  CHECK (off == 10 && n == 2 && nb == 2);
  CHECK (gq_sstream_next (&s, 100, UINT64_MAX, &off, &d, &n, &fin, &nb));
  CHECK (off == 12 && n == 4);
  gq_sstream_finish (&s);
  CHECK_EQ (gq_sstream_write (&s, (const uint8_t *) "x", 1), GQ_ERR_INVAL);
  /* FIN alone, since all data was already sent.  */
  CHECK (gq_sstream_next (&s, 100, UINT64_MAX, &off, &d, &n, &fin, &nb));
  CHECK (off == 16 && n == 0 && fin);
  CHECK_EQ (gq_sstream_state (&s), GQ_SS_DATA_SENT);
  /* The FIN is lost and comes back; middle chunk lost too.  */
  gq_sstream_on_lost (&s, 16, 0, 1);
  gq_sstream_on_acked (&s, 0, 10, 0);
  CHECK_EQ (s.base, 10);
  gq_sstream_on_lost (&s, 10, 6, 0);
  CHECK (gq_sstream_next (&s, 100, UINT64_MAX, &off, &d, &n, &fin, &nb));
  CHECK (off == 10 && n == 6 && fin && nb == 0);	/* FIN rides along.  */
  CHECK (memcmp (d, "abcdef", 6) == 0);
  CHECK (!gq_sstream_next (&s, 100, UINT64_MAX, &off, &d, &n, &fin, &nb));
  gq_sstream_on_acked (&s, 10, 6, 1);
  CHECK_EQ (gq_sstream_state (&s), GQ_SS_DATA_RECVD);
  gq_sstream_free (&s);

  /* A late ack cancels a queued retransmission.  */
  gq_sstream_init (&s, 100, 100);
  gq_sstream_write (&s, (const uint8_t *) "abcdefgh", 8);
  gq_sstream_next (&s, 4, UINT64_MAX, &off, &d, &n, &fin, &nb);
  gq_sstream_on_lost (&s, 0, 4, 0);
  gq_sstream_on_acked (&s, 0, 4, 0);
  CHECK (gq_sstream_next (&s, 100, UINT64_MAX, &off, &d, &n, &fin, &nb));
  CHECK (off == 4 && n == 4);			/* Not the lost bytes.  */
  gq_sstream_free (&s);

  /* Reset: final size is what was sent; data is dropped; loss re-queues.  */
  gq_sstream_init (&s, 100, 100);
  gq_sstream_write (&s, (const uint8_t *) "abcdefgh", 8);
  gq_sstream_next (&s, 5, UINT64_MAX, &off, &d, &n, &fin, &nb);
  gq_sstream_reset (&s, 77);
  CHECK_EQ (gq_sstream_state (&s), GQ_SS_RESET_SENT);
  CHECK (gq_sstream_pending (&s, UINT64_MAX));
  CHECK (!gq_sstream_next (&s, 100, UINT64_MAX, &off, &d, &n, &fin, &nb));
  CHECK (gq_sstream_take_reset (&s, &err, &fin_size));
  CHECK (err == 77 && fin_size == 5);
  CHECK (!gq_sstream_take_reset (&s, &err, &fin_size));
  gq_sstream_reset_lost (&s);
  CHECK (gq_sstream_take_reset (&s, &err, &fin_size));
  gq_sstream_reset_acked (&s);
  CHECK_EQ (gq_sstream_state (&s), GQ_SS_RESET_RECVD);
  CHECK_EQ (gq_sstream_write (&s, (const uint8_t *) "x", 1), GQ_ERR_INVAL);
  gq_sstream_free (&s);

  /* The buffer limit is honoured.  */
  gq_sstream_init (&s, 10, 100);
  CHECK_EQ (gq_sstream_write (&s, (const uint8_t *) "0123456789abc", 13), 10);
  CHECK_EQ (gq_sstream_write (&s, (const uint8_t *) "x", 1), 0);
  CHECK_EQ (gq_sstream_room (&s), 0);
  gq_sstream_next (&s, 4, UINT64_MAX, &off, &d, &n, &fin, &nb);
  gq_sstream_on_acked (&s, 0, 4, 0);
  CHECK_EQ (gq_sstream_room (&s), 4);
  gq_sstream_free (&s);
}

static void
test_recv_rules (void)
{
  gq_rstream r;
  static sink k;
  uint64_t nb, err;

  /* Flow control.  */
  memset (&k, 0, sizeof k);
  gq_rstream_init (&r, 10);
  CHECK_EQ (gq_rstream_push (&r, 0, (const uint8_t *) "01234567890", 11, 0,
                             on_data, &k, &nb), GQ_ERR_FLOW);
  CHECK_EQ (gq_rstream_push (&r, 8, (const uint8_t *) "ab", 2, 0, on_data,
                             &k, &nb), GQ_OK);
  CHECK (nb == 10 && k.got == 0);		/* Held: a gap before it.  */
  CHECK_EQ (gq_rstream_push (&r, 0, (const uint8_t *) "01234567", 8, 0,
                             on_data, &k, &nb), GQ_OK);
  CHECK (nb == 0 && k.got == 10 && k.calls == 1);
  CHECK (memcmp (k.data, "01234567ab", 10) == 0);
  /* Final size: a FIN below what was seen, data past it, a change.  */
  CHECK_EQ (gq_rstream_push (&r, 0, (const uint8_t *) "01", 2, 1, on_data,
                             &k, &nb), GQ_ERR_FINAL_SIZE);
  CHECK_EQ (gq_rstream_push (&r, 10, NULL, 0, 1, on_data, &k, &nb), GQ_OK);
  CHECK (k.fin && gq_rstream_state (&r) == GQ_RS_DATA_READ);
  CHECK_EQ (gq_rstream_push (&r, 10, NULL, 0, 1, on_data, &k, &nb), GQ_OK);
  CHECK_EQ (k.calls, 2);			/* FIN reported once.  */
  r.max_data = 100;
  CHECK_EQ (gq_rstream_push (&r, 9, (const uint8_t *) "bc", 2, 0, on_data,
                             &k, &nb), GQ_ERR_FINAL_SIZE);
  CHECK_EQ (gq_rstream_push (&r, 0, NULL, 0, 1, on_data, &k, &nb),
            GQ_ERR_FINAL_SIZE);
  gq_rstream_free (&r);

  /* FIN arrives before the missing data.  */
  memset (&k, 0, sizeof k);
  gq_rstream_init (&r, 100);
  gq_rstream_push (&r, 3, (const uint8_t *) "def", 3, 1, on_data, &k, &nb);
  CHECK (gq_rstream_state (&r) == GQ_RS_SIZE_KNOWN && !k.fin);
  gq_rstream_push (&r, 0, (const uint8_t *) "abc", 3, 0, on_data, &k, &nb);
  CHECK (k.fin && k.got == 6 && memcmp (k.data, "abcdef", 6) == 0);
  gq_rstream_free (&r);

  /* Reset: counts against credit, drops stored data, rechecks size.  */
  memset (&k, 0, sizeof k);
  gq_rstream_init (&r, 100);
  gq_rstream_push (&r, 10, (const uint8_t *) "xxxxx", 5, 0, on_data, &k, &nb);
  CHECK_EQ (gq_rstream_reset (&r, 5, 8, &nb), GQ_ERR_FINAL_SIZE);
  CHECK_EQ (gq_rstream_reset (&r, 5, 200, &nb), GQ_ERR_FLOW);
  CHECK_EQ (gq_rstream_reset (&r, 5, 40, &nb), GQ_OK);
  CHECK (nb == 25 && gq_rstream_state (&r) == GQ_RS_RESET_RECVD);
  CHECK_EQ (gq_rstream_push (&r, 0, (const uint8_t *) "y", 1, 0, on_data, &k,
                             &nb), GQ_OK);
  CHECK_EQ (k.calls, 0);
  CHECK_EQ (gq_rstream_reset (&r, 5, 41, &nb), GQ_ERR_FINAL_SIZE);
  gq_rstream_free (&r);

  /* STOP_SENDING discards data but the size is still enforced.  */
  memset (&k, 0, sizeof k);
  gq_rstream_init (&r, 100);
  gq_rstream_push (&r, 0, (const uint8_t *) "abc", 3, 0, on_data, &k, &nb);
  gq_rstream_stop (&r, 9);
  CHECK (gq_rstream_take_stop (&r, &err) && err == 9);
  CHECK (!gq_rstream_take_stop (&r, &err));
  gq_rstream_stop_lost (&r);
  CHECK (gq_rstream_take_stop (&r, &err));
  gq_rstream_push (&r, 3, (const uint8_t *) "def", 3, 1, on_data, &k, &nb);
  CHECK (k.got == 3 && gq_rstream_state (&r) == GQ_RS_DATA_READ);
  gq_rstream_free (&r);

  /* Window updates: none until half is used; lost ones repeat.  */
  gq_rstream_init (&r, 100);
  memset (&k, 0, sizeof k);
  CHECK (!gq_rstream_take_update (&r, 100, &nb));
  gq_rstream_push (&r, 0, (const uint8_t *) "0123456789", 10, 0, on_data, &k, &nb);
  CHECK (!gq_rstream_take_update (&r, 100, &nb));
  {
    uint8_t big[60];

    memset (big, 1, sizeof big);
    gq_rstream_push (&r, 10, big, 60, 0, on_data, &k, &nb);
  }
  CHECK (gq_rstream_take_update (&r, 100, &nb) && nb == 170);
  CHECK (!gq_rstream_take_update (&r, 100, &nb));
  gq_rstream_update_lost (&r, 170);
  CHECK (gq_rstream_take_update (&r, 100, &nb) && nb == 170);
  gq_rstream_free (&r);
}

int
main (void)
{
  test_transfers ();
  test_send_states ();
  test_recv_rules ();
  TST_DONE ();
}
