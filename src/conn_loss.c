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

/* Sent-packet tracking, acknowledgement processing, RTT estimation, loss
   detection, probe timeouts and NewReno congestion control (RFC 9002
   sections 5 to 7).  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "conn_int.h"

void
free_sent_frames (sent_pkt *p)
{
  free (p->frames);
  p->frames = NULL;
  p->nframes = 0;
}

/* ---- Congestion control (RFC 9002 section 7) ---- */

void
cc_init (gq_conn *c)
{
  c->cwnd = CC_INITIAL_WINDOW;
  c->ssthresh = UINT64_MAX;
  c->recovery_start = 0;
  c->ca_acked = 0;
}

/* LIMITED: the window was in use when the ACK arrived, so growing it is
   justified.  */
static void
cc_on_ack (gq_conn *c, const sent_pkt *p, int limited)
{
  if (!p->in_flight)
    return;
  if (c->recovery_start && p->time_us <= c->recovery_start)
    return;			/* Sent before recovery began.  */
  if (!limited)
    return;
  if (c->cwnd < c->ssthresh)
    c->cwnd += p->size;
  else
    {
      c->ca_acked += p->size;
      if (c->ca_acked >= c->cwnd)
        {
          c->ca_acked -= c->cwnd;
          c->cwnd += CC_MAX_DATAGRAM;
        }
    }
}

/* LOST_SENT: send time of the newest packet lost in this round.  */
static void
cc_on_loss (gq_conn *c, uint64_t lost_sent, uint64_t now)
{
  if (c->recovery_start && lost_sent <= c->recovery_start)
    return;			/* Already in recovery for this loss.  */
  c->recovery_start = now;
  c->congestion_events++;
  c->ssthresh = c->cwnd / 2;
  if (c->ssthresh < CC_MIN_WINDOW)
    c->ssthresh = CC_MIN_WINDOW;
  c->cwnd = c->ssthresh;
  c->ca_acked = 0;
}

static void
cc_persistent (gq_conn *c)
{
  c->cwnd = CC_MIN_WINDOW;
  c->recovery_start = 0;
  c->ca_acked = 0;
}

void
sp_sent_add (gq_conn *c, int sp, const sent_pkt *p)
{
  space *s = &c->sp[sp];

  if (s->n_sent == s->cap_sent)
    {
      size_t cap = s->cap_sent ? s->cap_sent * 2 : 32;
      sent_pkt *nv = realloc (s->sent, cap * sizeof *nv);

      if (nv == NULL)
        {
          free ((void *) p->frames);
          conn_fail (c, GQ_QERR_INTERNAL, "out of memory");
          return;
        }
      s->sent = nv;
      s->cap_sent = cap;
    }
  s->sent[s->n_sent++] = *p;
  if (p->in_flight)
    c->bytes_in_flight += p->size;
  if (p->ack_eliciting)
    {
      s->ae_in_flight++;
      s->last_ae_time = p->time_us;
      c->last_sent_ae = p->time_us;
    }
}

/* Forget everything outstanding in a space (keys were discarded).  */
void
sp_sent_clear (gq_conn *c, int sp)
{
  space *s = &c->sp[sp];
  size_t i;

  for (i = 0; i < s->n_sent; i++)
    {
      if (s->sent[i].in_flight)
        c->bytes_in_flight -= s->sent[i].size;
      free_sent_frames (&s->sent[i]);
    }
  s->n_sent = 0;
  s->ae_in_flight = 0;
}

/* Index of the first packet with number >= PN.  */
static size_t
sent_lower_bound (const space *s, uint64_t pn)
{
  size_t lo = 0, hi = s->n_sent;

  while (lo < hi)
    {
      size_t mid = lo + (hi - lo) / 2;

      if (s->sent[mid].pn < pn)
        lo = mid + 1;
      else
        hi = mid;
    }
  return lo;
}

/* What a lost packet carried goes back on the queues.  */
void
requeue_frames (gq_conn *c, int sp, sent_pkt *p)
{
  space *s = &c->sp[sp];
  uint32_t i;

  for (i = 0; i < p->nframes; i++)
    {
      const sent_frame *f = &p->frames[i];
      stream *st;
      size_t k;

      switch (f->type)
        {
        case SF_CRYPTO:
          if (!s->discarded)
            gq_sstream_on_lost (&s->cs, f->a, f->len, 0);
          break;
        case SF_STREAM:
          st = stream_find (c, f->a);
          if (st && st->has_send)
            gq_sstream_on_lost (&st->s, f->b, f->len, f->fin);
          break;
        case SF_RESET_STREAM:
          st = stream_find (c, f->a);
          if (st && st->has_send)
            gq_sstream_reset_lost (&st->s);
          break;
        case SF_STOP_SENDING:
          st = stream_find (c, f->a);
          if (st && st->has_recv)
            gq_rstream_stop_lost (&st->r);
          break;
        case SF_MAX_DATA:
          if (f->a == c->max_data_sent)
            c->max_data_sent = 0;
          break;
        case SF_MAX_STREAM_DATA:
          st = stream_find (c, f->a);
          if (st && st->has_recv)
            gq_rstream_update_lost (&st->r, f->b);
          break;
        case SF_MAX_STREAMS:
          if (c->max_streams_local_sent[f->a ? 1 : 0] == f->b)
            c->max_streams_local_sent[f->a ? 1 : 0] = 0;
          break;
        case SF_DATA_BLOCKED:
          c->blocked_sent_at = 0;
          break;
        case SF_STREAM_DATA_BLOCKED:
          st = stream_find (c, f->a);
          if (st && st->has_send)
            st->s.blocked_at = 0;
          break;
        case SF_NEW_CID:
          for (k = 0; k < MAX_LCID; k++)
            if (c->l[k].used && c->l[k].seq == f->a && !c->l[k].announced)
              c->l[k].need_send = 1;
          break;
        case SF_RETIRE_CID:
          for (k = 0; k < MAX_PCID; k++)
            if (c->p[k].used && c->p[k].seq == f->a && c->p[k].retire == 2)
              c->p[k].retire = 1;
          break;
        case SF_HANDSHAKE_DONE:
          c->handshake_done_pending = 1;
          break;
        case SF_NEW_TOKEN:
          if (c->token_keys)
            c->new_token_pending = 1;
          break;
        default:
          break;
        }
    }
}

static void
frames_acked (gq_conn *c, int sp, const sent_pkt *p)
{
  space *s = &c->sp[sp];
  uint32_t i;

  for (i = 0; i < p->nframes; i++)
    {
      const sent_frame *f = &p->frames[i];
      stream *st;
      size_t k;

      switch (f->type)
        {
        case SF_CRYPTO:
          if (!s->discarded)
            gq_sstream_on_acked (&s->cs, f->a, f->len, 0);
          break;
        case SF_STREAM:
          st = stream_find (c, f->a);
          if (st && st->has_send)
            {
              gq_sstream_on_acked (&st->s, f->b, f->len, f->fin);
              stream_on_acked (c, f->a);
            }
          break;
        case SF_RESET_STREAM:
          st = stream_find (c, f->a);
          if (st && st->has_send)
            {
              gq_sstream_reset_acked (&st->s);
              stream_on_acked (c, f->a);
            }
          break;
        case SF_NEW_CID:
          for (k = 0; k < MAX_LCID; k++)
            if (c->l[k].used && c->l[k].seq == f->a)
              c->l[k].announced = 1;
          break;
        case SF_RETIRE_CID:
          for (k = 0; k < MAX_PCID; k++)
            if (c->p[k].used && c->p[k].seq == f->a && c->p[k].retire)
              c->p[k].used = 0;
          break;
        default:
          break;
        }
    }
}

static void
update_rtt (gq_conn *c, uint64_t latest, uint64_t ack_delay)
{
  uint64_t adj, diff;

  c->latest_rtt = latest;
  if (!c->have_rtt)
    {
      c->min_rtt = latest;
      c->srtt = latest;
      c->rttvar = latest / 2;
      c->have_rtt = 1;
      return;
    }
  if (latest < c->min_rtt)
    c->min_rtt = latest;
  adj = latest;
  if (latest >= c->min_rtt + ack_delay)
    adj -= ack_delay;
  diff = c->srtt > adj ? c->srtt - adj : adj - c->srtt;
  c->rttvar = (3 * c->rttvar + diff) / 4;
  c->srtt = (7 * c->srtt + adj) / 8;
}

typedef struct ack_ctx
{
  gq_conn *c;
  space *s;
  sent_pkt *got;		/* Newly acknowledged, in descending order.  */
  size_t n, cap;
  int fail;
} ack_ctx;

static int
ack_range (void *user, uint64_t lo, uint64_t hi)
{
  ack_ctx *x = user;
  space *s = x->s;
  size_t i, j;

  gq_ranges_add (&s->acked_pns, lo, hi + 1, 1);
  i = j = sent_lower_bound (s, lo);

  while (j < s->n_sent && s->sent[j].pn <= hi)
    j++;
  if (j == i)
    return 0;
  if (x->n + (j - i) > x->cap)
    {
      size_t cap = x->cap ? x->cap * 2 : 16;
      sent_pkt *nv;

      while (cap < x->n + (j - i))
        cap *= 2;
      nv = realloc (x->got, cap * sizeof *nv);
      if (nv == NULL)
        {
          x->fail = 1;
          return 1;
        }
      x->got = nv;
      x->cap = cap;
    }
  memcpy (x->got + x->n, s->sent + i, (j - i) * sizeof *s->sent);
  x->n += j - i;
  memmove (s->sent + i, s->sent + j, (s->n_sent - j) * sizeof *s->sent);
  s->n_sent -= j - i;
  return 0;
}

void
process_ack (gq_conn *c, int sp, const gq_frame *f, uint64_t now)
{
  space *s = &c->sp[sp];
  ack_ctx x;
  size_t i;
  int have_largest = 0, ae = 0, limited;
  uint64_t largest_time = 0, before = c->bytes_in_flight;

  if (s->discarded)
    return;
  x.c = c;
  x.s = s;
  x.got = NULL;
  x.n = x.cap = 0;
  x.fail = 0;
  gq_ack_foreach (f, ack_range, &x);
  if (x.fail)
    conn_fail (c, GQ_QERR_INTERNAL, "out of memory");
  if (x.n == 0)
    {
      free (x.got);
      return;
    }
  if (!s->have_acked || f->u.ack.largest > s->largest_acked)
    {
      s->largest_acked = f->u.ack.largest;
      s->have_acked = 1;
    }
  for (i = 0; i < x.n; i++)
    {
      if (x.got[i].pn == f->u.ack.largest)
        {
          have_largest = 1;
          largest_time = x.got[i].time_us;
        }
      if (x.got[i].ack_eliciting)
        ae = 1;
    }
  if (have_largest && ae)
    {
      uint64_t delay = 0;

      if (sp == SP_APP)
        {
          unsigned e = c->peer_ack_delay_exp > 20 ? 20 : c->peer_ack_delay_exp;

          delay = f->u.ack.delay << e;
          if (c->handshake_confirmed && delay > c->peer_max_ack_delay_us)
            delay = c->peer_max_ack_delay_us;
        }
      update_rtt (c, now > largest_time ? now - largest_time : 0, delay);
    }
  limited = c->cwnd < c->ssthresh ? before >= c->cwnd / 2
                                  : before + CC_MAX_DATAGRAM >= c->cwnd;
  for (i = 0; i < x.n; i++)
    {
      sent_pkt *p = &x.got[i];

      cc_on_ack (c, p, limited);
      if (p->in_flight)
        c->bytes_in_flight -= p->size;
      if (p->ack_eliciting && s->ae_in_flight)
        s->ae_in_flight--;
      if (sp == SP_APP && p->pn >= c->w_first_pn && !c->w_phase_acked)
        c->w_phase_acked = 1;
      frames_acked (c, sp, p);
      free_sent_frames (p);
      if (c->state >= GQ_CONN_CLOSING)
        break;
    }
  for (; i < x.n; i++)
    free_sent_frames (&x.got[i]);
  free (x.got);
  c->pto_count = 0;
  loss_detect (c, sp, now);
}

void
loss_detect (gq_conn *c, int sp, uint64_t now)
{
  space *s = &c->sp[sp];
  uint64_t base, delay, lost_before;
  uint64_t first_lost = 0, last_lost = 0, first_pn = 0, last_pn = 0;
  int any_lost = 0;
  size_t i, j = 0;

  s->loss_time = 0;
  if (!s->have_acked || s->discarded)
    return;
  base = c->latest_rtt > c->srtt ? c->latest_rtt : c->srtt;
  delay = base + base / 8;
  if (delay < K_GRANULARITY)
    delay = K_GRANULARITY;
  lost_before = now > delay ? now - delay : 0;
  for (i = 0; i < s->n_sent; i++)
    {
      sent_pkt *p = &s->sent[i];

      if (p->pn > s->largest_acked)
        {
          s->sent[j++] = *p;
          continue;
        }
      if (p->pn + K_PACKET_THRESHOLD <= s->largest_acked
          || (now > delay && p->time_us <= lost_before))
        {
          if (p->in_flight)
            {
              c->bytes_in_flight -= p->size;
              if (!any_lost)
                {
                  first_lost = p->time_us;
                  first_pn = p->pn;
                }
              last_lost = p->time_us;
              last_pn = p->pn;
              any_lost = 1;
            }
          if (p->ack_eliciting && s->ae_in_flight)
            s->ae_in_flight--;
          c->st.packets_lost++;
          if (!p->requeued)
            requeue_frames (c, sp, p);
          free_sent_frames (p);
        }
      else
        {
          uint64_t t = p->time_us + delay;

          if (s->loss_time == 0 || t < s->loss_time)
            s->loss_time = t;
          s->sent[j++] = *p;
        }
    }
  s->n_sent = j;
  if (any_lost)
    {
      cc_on_loss (c, last_lost, now);
      /* Persistent congestion: losses spanning several probe timeouts
         with nothing acknowledged in between.  */
      if (c->have_rtt && last_lost > first_lost
          && last_lost - first_lost
             >= K_PERSISTENT_CONGESTION_THRESHOLD * conn_pto_base (c, SP_APP))
        {
          size_t k;
          int between = 0;

          for (k = 0; k < s->acked_pns.n; k++)
            if (s->acked_pns.r[k].lo < last_pn
                && s->acked_pns.r[k].hi > first_pn + 1)
              between = 1;
          if (!between)
            cc_persistent (c);
        }
    }
}

uint64_t
pto_interval (const gq_conn *c, int sp)
{
  unsigned e = c->pto_count > 16 ? 16 : c->pto_count;

  return conn_pto_base (c, sp) << e;
}

/* The space a probe timeout applies to, or -1.  */
static int
pto_space (const gq_conn *c, uint64_t *when)
{
  int sp, best = -1;
  uint64_t t, bt = 0;
  int any = 0;

  if (c->role == GQ_ROLE_SERVER && !c->peer_addr_validated
      && c->bytes_sent >= 3 * c->bytes_recv)
    return -1;			/* Nothing may be sent anyway.  */
  for (sp = 0; sp < N_SPACES; sp++)
    if (!c->sp[sp].discarded && c->sp[sp].ae_in_flight)
      any = 1;
  if (!any)
    {
      /* A client keeps probing until the server has validated it.  */
      if (c->role == GQ_ROLE_CLIENT && !c->handshake_confirmed)
        {
          sp = c->sp[SP_HANDSHAKE].have_wk && !c->sp[SP_HANDSHAKE].discarded
               ? SP_HANDSHAKE : SP_INITIAL;
          if (c->sp[sp].discarded)
            return -1;
          *when = c->last_sent_ae + pto_interval (c, sp);
          return sp;
        }
      return -1;
    }
  for (sp = 0; sp < N_SPACES; sp++)
    {
      const space *s = &c->sp[sp];

      if (s->discarded || s->ae_in_flight == 0)
        continue;
      if (sp == SP_APP && !c->handshake_confirmed)
        continue;
      t = s->last_ae_time + pto_interval (c, sp);
      if (best < 0 || t < bt)
        {
          best = sp;
          bt = t;
        }
    }
  if (best >= 0)
    *when = bt;
  return best;
}

uint64_t
conn_loss_deadline (const gq_conn *c)
{
  uint64_t t = 0, when;
  int sp;

  for (sp = 0; sp < N_SPACES; sp++)
    if (!c->sp[sp].discarded && c->sp[sp].loss_time
        && (t == 0 || c->sp[sp].loss_time < t))
      t = c->sp[sp].loss_time;
  if (t)
    return t;
  if (pto_space (c, &when) >= 0)
    return when;
  return 0;
}

void
on_loss_timeout (gq_conn *c, uint64_t now)
{
  uint64_t t = 0, when = 0;
  int sp, best = -1;
  space *s;
  size_t i;

  for (sp = 0; sp < N_SPACES; sp++)
    if (!c->sp[sp].discarded && c->sp[sp].loss_time
        && (best < 0 || c->sp[sp].loss_time < t))
      {
        best = sp;
        t = c->sp[sp].loss_time;
      }
  if (best >= 0)
    {
      if (now >= t)
        loss_detect (c, best, now);
      return;
    }
  sp = pto_space (c, &when);
  if (sp < 0 || now < when)
    return;
  c->pto_count++;
  s = &c->sp[sp];
  s->probes = 2;
  /* Retransmit what the oldest outstanding packet carried: it is the one
     most likely to be lost.  */
  for (i = 0; i < s->n_sent; i++)
    if (s->sent[i].ack_eliciting && !s->sent[i].requeued)
      {
        requeue_frames (c, sp, &s->sent[i]);
        s->sent[i].requeued = 1;
        break;
      }
}

int
conn_can_send_ae (const gq_conn *c)
{
  return c->bytes_in_flight < c->cwnd;
}
