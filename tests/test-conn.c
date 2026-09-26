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

/* QUIC connections against each other over a simulated network: virtual
   clock (microseconds), latency, and loss, reordering and corruption
   chosen per test.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/conn.h>
#include <gnuquic/listen.h>
#include <gnuquic/packet.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"

#define MAXQ 8192
#define MAXS 64

struct net;

struct sbuf
{
  int used;
  uint64_t id;
  size_t n;			/* Bytes received (pattern verified).  */
  int fin, reset, stopped;
  uint64_t err;
  size_t out_total, out_done;	/* What we are sending on it.  */
  int out_fin;
  int closed;
};

struct app
{
  gq_conn *c;
  struct net *net;
  int idx;			/* 0 client, 1 server.  */
  struct sbuf sb[MAXS];
  int connected, closed, bad;
  gq_conn_close_info ci;
  int cids, retired, opened;
  size_t respond;		/* Server: bytes to answer each request with.  */
  size_t total_in;
  gq_tls_info info;
  uint8_t token[512];
  size_t token_len;
  int tokens;
  gq_tls_session sess;
  int have_sess;
  uint32_t sess_version;
};

struct pkt
{
  int to;
  uint64_t at;
  size_t len;
  uint8_t d[2048];
};

struct net
{
  struct pkt q[MAXQ];
  int nq;
  uint64_t now, latency;
  unsigned loss_pct;
  int reorder, corrupt;
  int total;
  uint32_t rng;
  struct app *app[2];
  int dropped;
  int drop_index;		/* Drop this datagram only (or -1).  */
  /* Server admission (NULL keys: the server exists from the start).  */
  gq_token_keys *keys;
  gq_admit_config admit;
  uint8_t addr[6];
  int replies, accepts;
  int (*make_srv) (struct net *, const gq_conn_accept *);
  /* Congestion controller observations, sender side of stream 0.  */
  int64_t max_over;
  uint64_t max_cwnd, min_cwnd, events;
};

static uint32_t
rnd (struct net *n)
{
  n->rng = n->rng * 1664525u + 1013904223u;
  return n->rng >> 8;
}

static uint8_t
pat (uint64_t id, uint64_t off)
{
  return (uint8_t) (id * 31 + off * 7 + (off >> 8));
}

static struct sbuf *
sb_get (struct app *a, uint64_t id)
{
  int i;

  for (i = 0; i < MAXS; i++)
    if (a->sb[i].used && a->sb[i].id == id)
      return &a->sb[i];
  for (i = 0; i < MAXS; i++)
    if (!a->sb[i].used)
      {
        a->sb[i].used = 1;
        a->sb[i].id = id;
        return &a->sb[i];
      }
  CHECK (0);
  return &a->sb[0];
}

/* ---- Events ---- */

static void
ev_connected (void *u, const gq_tls_info *i)
{
  struct app *a = u;

  a->connected = 1;
  a->info = *i;
}

static void
ev_opened (void *u, uint64_t id)
{
  struct app *a = u;

  a->opened++;
  sb_get (a, id);
}

static int
ev_data (void *u, uint64_t id, const uint8_t *d, size_t n, int fin)
{
  struct app *a = u;
  struct sbuf *s = sb_get (a, id);
  size_t i;

  for (i = 0; i < n; i++)
    if (d[i] != pat (id, s->n + i))
      {
        a->bad++;
        break;
      }
  s->n += n;
  a->total_in += n;
  CHECK (!s->fin);
  if (fin)
    {
      s->fin = 1;
      /* Server: a complete request on a bidirectional stream is answered.  */
      if (a->idx == 1 && !(id & 2) && a->respond)
        {
          s->out_total = a->respond;
          s->out_fin = 1;
        }
    }
  return 0;
}

static void
ev_reset (void *u, uint64_t id, uint64_t err)
{
  struct sbuf *s = sb_get (u, id);

  s->reset = 1;
  s->err = err;
}

static void
ev_stopped (void *u, uint64_t id, uint64_t err)
{
  struct sbuf *s = sb_get (u, id);

  s->stopped = 1;
  s->err = err;
}

static void
ev_stream_closed (void *u, uint64_t id)
{
  sb_get (u, id)->closed = 1;
}

static void
ev_new_token (void *u, const uint8_t *t, size_t n)
{
  struct app *a = u;

  CHECK (n <= sizeof a->token);
  memcpy (a->token, t, n);
  a->token_len = n;
  a->tokens++;
}

/* Set by the resumption test.  */
static gq_ticket_keys *g_ring;
static const gq_tls_session *g_resume;

static void
ev_ticket (void *u, const gq_tls_ticket *t, uint32_t version)
{
  struct app *a = u;

  if (a->have_sess)
    return;
  CHECK_EQ (gq_tls_session_store (&a->sess, t), GQ_OK);
  a->have_sess = 1;
  a->sess_version = version;
}

static void
ev_closed (void *u, const gq_conn_close_info *i)
{
  struct app *a = u;

  a->closed++;
  if (getenv ("QDBG"))
    fprintf (stderr, "%s closed: src=%d app=%d err=%llx reason=%.*s\n", a->idx ? "srv" : "cli", i->source, i->application, (unsigned long long) i->error, (int) i->reason_len, i->reason ? (const char *) i->reason : "");
  a->ci = *i;
  a->ci.reason = NULL;
}

static void
ev_cid (void *u, const uint8_t *cid, size_t len, const uint8_t *tok)
{
  (void) cid;
  (void) len;
  (void) tok;
  ((struct app *) u)->cids++;
}

static void
ev_cid_retired (void *u, const uint8_t *cid, size_t len)
{
  (void) cid;
  (void) len;
  ((struct app *) u)->retired++;
}

/* Write whatever each stream still owes.  */
static void
pump (struct app *a)
{
  int i;

  if (a->c == NULL || a->closed || gq_conn_state (a->c) >= GQ_CONN_CLOSING)
    return;
  for (i = 0; i < MAXS; i++)
    {
      struct sbuf *s = &a->sb[i];

      while (s->used && s->out_done < s->out_total)
        {
          uint8_t buf[3000];
          size_t n = s->out_total - s->out_done, k;
          long w;

          if (n > sizeof buf)
            n = sizeof buf;
          for (k = 0; k < n; k++)
            buf[k] = pat (s->id, s->out_done + k);
          w = gq_conn_stream_write (a->c, s->id, buf, n);
          CHECK (w >= 0);
          if (w <= 0)
            break;
          s->out_done += (size_t) w;
        }
      if (s->used && s->out_fin && s->out_done == s->out_total
)
        {
          gq_conn_stream_finish (a->c, s->id);
          s->out_fin = 0;
        }
    }
}

/* ---- The network ---- */

static void
enqueue (struct net *n, int from, const uint8_t *d, size_t len)
{
  struct pkt *p;
  int index = n->total++;

  if (index == n->drop_index || (n->loss_pct && rnd (n) % 100 < n->loss_pct))
    {
      n->dropped++;
      return;
    }
  if (getenv ("QDBG"))
    fprintf (stderr, "%llu: %s sends %zu bytes first=%02x%s\n",
             (unsigned long long) n->now, from ? "srv" : "cli", len, d[0],
             n->drop_index == index ? " DROPPED" : "");
  CHECK (n->nq < MAXQ);
  if (n->nq >= MAXQ)
    return;
  p = &n->q[n->nq++];
  p->to = 1 - from;
  p->at = n->now + n->latency + (n->reorder && rnd (n) % 4 == 0 ? 7000 : 0);
  p->len = len;
  memcpy (p->d, d, len);
  if (n->corrupt && index % n->corrupt == 0)
    p->d[rnd (n) % len] ^= 0x20;
}

static void
flush (struct net *n)
{
  int s;

  for (s = 0; s < 2; s++)
    {
      struct app *a = n->app[s];
      uint8_t buf[2048];
      size_t len;
      int guard = 0;

      if (a == NULL || a->c == NULL)
        continue;
      {
        gq_conn_stats st;

        gq_conn_get_stats (a->c, &st);
        if ((int64_t) st.bytes_in_flight - (int64_t) st.cwnd > n->max_over)
          n->max_over = (int64_t) st.bytes_in_flight - (int64_t) st.cwnd;
        if (st.cwnd > n->max_cwnd)
          n->max_cwnd = st.cwnd;
        if (st.cwnd < n->min_cwnd || n->min_cwnd == 0)
          n->min_cwnd = st.cwnd;
        if (st.congestion_events > n->events)
          n->events = st.congestion_events;
      }
      while (guard++ < 200)
        {
          CHECK_EQ (gq_conn_send (a->c, n->now, buf, sizeof buf, &len), GQ_OK);
          if (len == 0)
            break;
          CHECK (len <= 1200);
          enqueue (n, s, buf, len);
        }
    }
}

/* Run until DONE says so or the time budget is spent.  */
static int
run (struct net *n, int (*done) (struct net *), uint64_t budget_us)
{
  uint64_t end = n->now + budget_us;
  int steps = 0;

  while (n->now < end && steps++ < 2000000)
    {
      uint64_t t = 0;
      int i, best = -1, s;

      pump (n->app[0]);
      pump (n->app[1]);
      flush (n);
      if (done && done (n))
        return 1;
      for (i = 0; i < n->nq; i++)
        if (best < 0 || n->q[i].at < n->q[best].at)
          best = i;
      if (best >= 0)
        t = n->q[best].at;
      for (s = 0; s < 2; s++)
        if (n->app[s]->c)
          {
            uint64_t tt = gq_conn_timeout (n->app[s]->c);

            if (tt && (t == 0 || tt < t))
              t = tt;
          }
      if (t == 0 || t > end)
        {
          if (t > end)
            n->now = end;
          return done ? done (n) : 1;
        }
      if (t > n->now)
        n->now = t;
      if (best >= 0 && n->q[best].at <= n->now)
        {
          struct pkt p = n->q[best];

          memmove (&n->q[best], &n->q[best + 1],
                   (size_t) (n->nq - best - 1) * sizeof n->q[0]);
          n->nq--;
          if (p.to == 1 && n->app[1]->c == NULL && n->keys)
            {
              uint8_t reply[1500];
              size_t rl = 0;
              gq_conn_accept acc;
              int act = gq_quic_admit (n->keys, &n->admit, n->addr,
                                       sizeof n->addr, p.d, p.len,
                                       n->now / 1000000, reply, sizeof reply,
                                       &rl, &acc);

              if (act == GQ_ADMIT_REPLY)
                {
                  n->replies++;
                  enqueue (n, 1, reply, rl);
                }
              else if (act == GQ_ADMIT_ACCEPT)
                {
                  n->accepts++;
                  CHECK_EQ (n->make_srv (n, &acc), GQ_OK);
                  gq_conn_recv (n->app[1]->c, n->now, p.d, p.len);
                }
              continue;
            }
          if (n->app[p.to]->c)
            gq_conn_recv (n->app[p.to]->c, n->now, p.d, p.len);
          continue;
        }
      for (s = 0; s < 2; s++)
        if (n->app[s]->c)
          {
            uint64_t tt = gq_conn_timeout (n->app[s]->c);

            if (tt && tt <= n->now)
              gq_conn_on_timeout (n->app[s]->c, n->now);
          }
    }
  return done ? done (n) : 0;
}

/* ---- Setup ---- */

static const uint8_t alpn_hq[2] = { 'h', 'q' };
static gq_slice alpn_list[1] = { { alpn_hq, 2 } };

struct pair
{
  struct net net;
  struct app cli, srv;
  gq_tls_config ccfg;
  gq_tls_server_config scfg;
  gq_conn_events cev, sev;
  gq_conn_config scfg_conn;
  gq_token_keys keys;
};

static void
fill_events (gq_conn_events *e, struct app *a)
{
  memset (e, 0, sizeof *e);
  e->user = a;
  e->connected = ev_connected;
  e->stream_opened = ev_opened;
  e->stream_data = ev_data;
  e->stream_reset = ev_reset;
  e->stream_stopped = ev_stopped;
  e->stream_closed = ev_stream_closed;
  e->closed = ev_closed;
  e->cid_issued = ev_cid;
  e->cid_retired = ev_cid_retired;
  e->new_token = ev_new_token;
  e->ticket = ev_ticket;
}

static struct pair *
pair_new (const gq_conn_config *ccfg, const gq_conn_config *scfg,
          unsigned loss_pct, uint32_t seed)
{
  struct pair *p = calloc (1, sizeof *p);

  p->net.now = 1000000;
  p->net.latency = 10000;
  p->net.loss_pct = loss_pct;
  p->net.rng = seed;
  p->net.drop_index = -1;
  p->net.app[0] = &p->cli;
  p->net.app[1] = &p->srv;
  p->cli.net = p->srv.net = &p->net;
  p->cli.idx = 0;
  p->srv.idx = 1;
  p->ccfg.server_name = "example.test";
  p->ccfg.trust = fx_trust;
  p->ccfg.alpn = alpn_list;
  p->ccfg.n_alpn = 1;
  p->scfg.credentials.chain = fx_ec.chain;
  p->scfg.credentials.n_chain = 1;
  p->scfg.credentials.key = fx_ec.key;
  p->scfg.alpn = alpn_list;
  p->scfg.n_alpn = 1;
  p->scfg.ticket_keys = g_ring;
  p->ccfg.resume = g_resume;
  fill_events (&p->cev, &p->cli);
  fill_events (&p->sev, &p->srv);
  CHECK_EQ (gq_conn_client_new (&p->cli.c, ccfg, &p->ccfg, &p->cev,
                                p->net.now), GQ_OK);
  CHECK_EQ (gq_conn_server_new (&p->srv.c, scfg, &p->scfg, &p->sev,
                                p->net.now), GQ_OK);
  return p;
}

static uint64_t
sim_wall (void *u)
{
  return ((struct net *) u)->now / 1000000;
}

static int
make_srv (struct net *n, const gq_conn_accept *acc)
{
  struct pair *p = (struct pair *) n;

  return gq_conn_server_accept (&p->srv.c, &p->scfg_conn, &p->scfg, &p->sev,
                                n->now, acc);
}

/* A pair whose server exists only once the admission step accepts.  */
static struct pair *
pair_new_admit (const gq_conn_config *ccfg, unsigned loss, uint32_t seed,
                int require_retry, const uint8_t *token, size_t token_len)
{
  struct pair *p = calloc (1, sizeof *p);
  gq_conn_config cc;

  p->net.now = 1000000;
  p->net.latency = 10000;
  p->net.loss_pct = loss;
  p->net.rng = seed;
  p->net.drop_index = -1;
  p->net.app[0] = &p->cli;
  p->net.app[1] = &p->srv;
  p->cli.net = p->srv.net = &p->net;
  p->srv.idx = 1;
  p->ccfg.server_name = "example.test";
  p->ccfg.trust = fx_trust;
  p->ccfg.alpn = alpn_list;
  p->ccfg.n_alpn = 1;
  p->scfg.credentials.chain = fx_ec.chain;
  p->scfg.credentials.n_chain = 1;
  p->scfg.credentials.key = fx_ec.key;
  p->scfg.alpn = alpn_list;
  p->scfg.n_alpn = 1;
  p->scfg.ticket_keys = g_ring;
  p->ccfg.resume = g_resume;
  fill_events (&p->cev, &p->cli);
  fill_events (&p->sev, &p->srv);
  CHECK_EQ (gq_token_keys_init (&p->keys), GQ_OK);
  p->net.keys = &p->keys;
  p->net.admit.require_retry = require_retry;
  p->net.make_srv = make_srv;
  memcpy (p->net.addr, "\x7f\0\0\1\x11\x5c", 6);
  memset (&p->scfg_conn, 0, sizeof p->scfg_conn);
  p->scfg_conn.wall_seconds = sim_wall;
  p->scfg_conn.wall_user = &p->net;
  cc = ccfg ? *ccfg : p->scfg_conn;
  cc.token = token;
  cc.token_len = token_len;
  CHECK_EQ (gq_conn_client_new (&p->cli.c, &cc, &p->ccfg, &p->cev,
                                p->net.now), GQ_OK);
  return p;
}

static void
pair_free (struct pair *p)
{
  gq_conn_free (p->cli.c);
  gq_conn_free (p->srv.c);
  free (p);
}

static int
both_connected (struct net *n)
{
  return n->app[0]->connected && n->app[1]->connected;
}

/* ---- Tests ---- */

static void
test_handshake (uint32_t version, unsigned loss, uint32_t seed)
{
  struct pair *p;
  gq_conn_config cfg;
  gq_conn_stats st;

  memset (&cfg, 0, sizeof cfg);
  cfg.version = version;
  p = pair_new (&cfg, &cfg, loss, seed);
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK (p->cli.connected && p->srv.connected);
  CHECK_EQ (p->cli.info.alpn_len, 2);
  CHECK (gq_conn_is_established (p->cli.c));
  CHECK (gq_conn_is_established (p->srv.c));
  CHECK_EQ (gq_conn_version (p->cli.c), version ? version : GQ_VERSION_2);
  /* Let the handshake finish being confirmed and CIDs be exchanged.  */
  run (&p->net, NULL, 2000000);
  CHECK (p->cli.cids >= 2 && p->srv.cids >= 2);
  gq_conn_get_stats (p->cli.c, &st);
  CHECK (st.packets_sent > 0 && st.srtt_us > 0);
  if (!loss)
    CHECK (st.srtt_us < 100000 && st.srtt_us > 10000);
  pair_free (p);
}

/* NREQ requests of REQ bytes, each answered with RESP bytes.  */
static void
test_requests (unsigned loss, uint32_t seed, int nreq, size_t req,
               size_t resp, const gq_conn_config *ccfg,
               const gq_conn_config *scfg, int reorder)
{
  struct pair *p = pair_new (ccfg, scfg, loss, seed);
  int i, opened = 0;
  uint64_t deadline;

  p->net.reorder = reorder;
  p->srv.respond = resp;
  CHECK (run (&p->net, both_connected, 30000000));
  deadline = p->net.now + 600000000;
  while (opened < nreq && p->net.now < deadline)
    {
      uint64_t id;
      int r = gq_conn_stream_open (p->cli.c, 1, &id);

      if (r == GQ_OK)
        {
          struct sbuf *s = sb_get (&p->cli, id);

          s->out_total = req;
          s->out_fin = 1;
          opened++;
        }
      else
        run (&p->net, NULL, 100000);
    }
  CHECK_EQ (opened, nreq);
  {
    int ok = 0;

    while (p->net.now < deadline)
      {
        run (&p->net, NULL, 200000);
        ok = 1;
        for (i = 0; i < MAXS; i++)
          if (p->cli.sb[i].used && (p->cli.sb[i].id & 3) == 0
              && !(p->cli.sb[i].fin && p->cli.sb[i].n == resp))
            ok = 0;
        if (ok && opened == nreq)
          break;
      }
    CHECK (ok);
  }
  CHECK_EQ (p->cli.bad, 0);
  CHECK_EQ (p->srv.bad, 0);
  for (i = 0; i < MAXS; i++)
    if (p->cli.sb[i].used)
      CHECK_EQ (p->cli.sb[i].n, resp);
  /* Everything is acknowledged in the end and streams are released.  */
  run (&p->net, NULL, 5000000);
  for (i = 0; i < MAXS; i++)
    if (p->cli.sb[i].used && p->cli.sb[i].id < 4 * (uint64_t) nreq)
      CHECK (p->cli.sb[i].closed);
  CHECK_EQ (p->cli.closed, 0);
  CHECK_EQ (p->srv.closed, 0);
  pair_free (p);
}

/* The server sends SIZE bytes; LOSS_PCT random loss, and optionally a
   blackout of BLACKOUT_US starting once BLACKOUT_AT bytes have arrived.  */
static void
test_congestion (size_t size, unsigned loss, uint64_t blackout_at,
                 uint64_t blackout_us, int expect_events, int expect_min)
{
  gq_conn_config cfg;
  struct pair *p;
  uint64_t id, until = 0, deadline;
  struct sbuf *s;
  int done = 0;

  if (getenv ("QDBG"))
    fprintf (stderr, "--- congestion size=%zu loss=%u\n", size, loss);
  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  p = pair_new (&cfg, &cfg, 0, 21);
  p->srv.respond = size;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 500000);
  p->net.min_cwnd = 0;
  p->net.max_cwnd = 0;
  p->net.loss_pct = loss;
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 10;
  s->out_fin = 1;
  deadline = p->net.now + 300000000;
  while (p->net.now < deadline && !done)
    {
      run (&p->net, NULL, 20000);
      if (blackout_us && !until && s->n >= blackout_at)
        {
          until = p->net.now + blackout_us;
          p->net.loss_pct = 100;
        }
      if (until && p->net.now >= until)
        {
          p->net.loss_pct = loss;
          until = 0;
          blackout_us = 0;
        }
      done = s->fin && s->n == size;
    }
  CHECK (done);
  CHECK_EQ (p->cli.bad, 0);
  /* The window starts at ten datagrams, grows, and never lets more than one
     datagram beyond it into flight.  */
  CHECK (p->net.max_cwnd > 12000);
  if (!loss && !blackout_us)
    CHECK (p->net.max_over < 1200);
  if (expect_events)
    CHECK (p->net.events > 0);
  else
    CHECK_EQ (p->net.events, 0);
  if (expect_min)
    CHECK_EQ (p->net.min_cwnd, 2400);
  else
    CHECK (p->net.min_cwnd > 2400);
  pair_free (p);
}

static int
one_stream_done (struct net *n)
{
  return n->app[0]->sb[0].used && n->app[0]->sb[0].fin;
}

/* A request over a connection made through the admission step.  */
static void
exchange (struct pair *p)
{
  uint64_t id;
  struct sbuf *s;

  p->srv.respond = 5000;
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 20;
  s->out_fin = 1;
  CHECK (run (&p->net, one_stream_done, 30000000));
  CHECK_EQ (s->n, 5000);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
}

static void
test_retry (uint32_t version, unsigned loss, uint32_t seed)
{
  struct pair *p;
  gq_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  cfg.version = version;
  cfg.wall_seconds = sim_wall;
  p = pair_new_admit (&cfg, loss, seed, 1, NULL, 0);
  cfg.wall_seconds = sim_wall;
  p->scfg_conn.version = version;
  p->net.admit.retry_lifetime_s = 30;
  exchange (p);
  /* Exactly one Retry (with loss, retransmitted Initials may draw more),
     and the server connection only exists after the token came back.  */
  if (!loss)
    /* The client's first flight is two datagrams, so two Retries go out; it
     obeys the first and ignores the second.  */
  CHECK (p->net.replies >= 1 && p->net.accepts == 1);
  /* NEW_TOKEN arrived.  */
  run (&p->net, NULL, 1000000);
  CHECK_EQ (p->cli.tokens, 1);
  pair_free (p);
}

static void
test_tokens (void)
{
  struct pair *p, *q;
  uint8_t token[512];
  size_t tl;
  gq_token_keys saved;
  gq_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  cfg.wall_seconds = sim_wall;
  /* No Retry needed when not required: unvalidated at first, token issued.  */
  p = pair_new_admit (&cfg, 0, 30, 0, NULL, 0);
  exchange (p);
  CHECK_EQ (p->net.replies, 0);
  run (&p->net, NULL, 1000000);
  CHECK_EQ (p->cli.tokens, 1);
  memcpy (token, p->cli.token, p->cli.token_len);
  tl = p->cli.token_len;
  saved = p->keys;
  pair_free (p);
  /* With Retry required, a NEW_TOKEN from before skips the Retry.  */
  q = pair_new_admit (&cfg, 0, 31, 1, token, tl);
  q->keys = saved;
  exchange (q);
  CHECK_EQ (q->net.replies, 0);
  pair_free (q);
  /* From another address it is worthless: the client gets a Retry.  */
  q = pair_new_admit (&cfg, 0, 32, 1, token, tl);
  q->keys = saved;
  q->net.addr[3] = 9;
  exchange (q);
  CHECK (q->net.replies >= 1);
  pair_free (q);
  /* Garbage as a token is treated as no token.  */
  {
    uint8_t junk[60];

    memset (junk, 0x5a, sizeof junk);
    q = pair_new_admit (&cfg, 0, 33, 1, junk, sizeof junk);
  q->keys = saved;
    exchange (q);
    CHECK (q->net.replies >= 1);
    pair_free (q);
  }
  /* An expired token (a day and more later) is refused too.  */
  q = pair_new_admit (&cfg, 0, 34, 1, token, tl);
  q->keys = saved;
  q->net.now += (uint64_t) 90000 * 1000000;
  exchange (q);
  CHECK (q->net.replies >= 1);
  pair_free (q);
}

/* Anything that is not a first Initial is dropped without an answer, and
   unknown versions get Version Negotiation.  */
static void
test_admit_input (void)
{
  gq_token_keys keys;
  gq_admit_config ac;
  gq_conn_accept acc;
  uint8_t dg[1300], out[1500], addr[4] = { 1, 2, 3, 4 };
  size_t rl, hl;
  int act;

  memset (&ac, 0, sizeof ac);
  gq_token_keys_init (&keys);
  memset (dg, 0, sizeof dg);
  /* A real-looking Initial: build a header with room for 1200 bytes.  */
  {
    uint8_t dcid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, scid[4] = { 9, 9, 9, 9 };

    CHECK_EQ (gq_long_header_build (GQ_PKT_INITIAL, GQ_VERSION_1, dcid, 8,
                                    scid, 4, NULL, 0, 0, 1, 1100, dg,
                                    sizeof dg, &hl), GQ_OK);
  }
  act = gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out, &rl,
                       &acc);
  CHECK_EQ (act, GQ_ADMIT_ACCEPT);
  CHECK (!acc.validated && acc.token_keys == &keys && acc.addr_len == 4);
  ac.require_retry = 1;
  act = gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out, &rl,
                       &acc);
  CHECK_EQ (act, GQ_ADMIT_REPLY);
  CHECK (rl > 30 && rl < 200 && (out[0] & 0x80));
  /* Too short a datagram, a short-header packet, junk: dropped.  */
  CHECK_EQ (gq_quic_admit (&keys, &ac, addr, 4, dg, 1199, 5, out, sizeof out,
                           &rl, &acc), GQ_ADMIT_DROP);
  dg[0] &= 0x7f;
  CHECK_EQ (gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out,
                           &rl, &acc), GQ_ADMIT_DROP);
  dg[0] |= 0x80;
  /* An unknown version draws Version Negotiation listing 1 and 2, but a
     Version Negotiation packet itself does not.  */
  dg[1] = 0x1a; dg[2] = 0x2a; dg[3] = 0x3a; dg[4] = 0x4a;
  act = gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out, &rl,
                       &acc);
  CHECK_EQ (act, GQ_ADMIT_REPLY);
  {
    gq_long_header h;

    CHECK_EQ (gq_long_header_parse (out, rl, &h), GQ_OK);
    CHECK (h.type == GQ_PKT_VERSION_NEGOTIATION && gq_vn_count (&h) == 2);
    CHECK (gq_vn_get (&h, 0) == GQ_VERSION_1 && gq_vn_get (&h, 1)
           == GQ_VERSION_2);
  }
  dg[1] = dg[2] = dg[3] = dg[4] = 0;
  CHECK_EQ (gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out,
                           &rl, &acc), GQ_ADMIT_DROP);
  gq_token_keys_wipe (&keys);
}

/* A Retry with a bad integrity tag changes nothing; a good one restarts the
   Initial flight with the token, and the server sees the original ID.  */
static void
test_retry_tamper (void)
{
  struct pair *p = pair_new_admit (NULL, 0, 50, 1, NULL, 0);
  uint8_t d1[1500], d2[1500], retry[1500], bad[1500], again[1500];
  size_t l1, l2, lr = 0, la;
  gq_conn_accept acc;
  const uint8_t *odcid;
  size_t odlen;

  odcid = gq_conn_initial_dcid (p->cli.c, &odlen);
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, d1, sizeof d1, &l1), GQ_OK);
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, d2, sizeof d2, &l2), GQ_OK);
  CHECK (l1 == 1200 && l2 > 0);
  CHECK_EQ (gq_quic_admit (&p->keys, &p->net.admit, p->net.addr, 6, d1, l1,
                           1, retry, sizeof retry, &lr, &acc), GQ_ADMIT_REPLY);
  memcpy (bad, retry, lr);
  bad[lr - 1] ^= 1;
  gq_conn_recv (p->cli.c, p->net.now, bad, lr);
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, again, sizeof again, &la),
            GQ_OK);
  CHECK_EQ (la, 0);
  {
    uint8_t odsave[GQ_MAX_CID_LEN];

    memcpy (odsave, odcid, odlen);
    gq_conn_recv (p->cli.c, p->net.now, retry, lr);
    CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, again, sizeof again, &la),
              GQ_OK);
    CHECK_EQ (la, 1200);
    CHECK_EQ (gq_quic_admit (&p->keys, &p->net.admit, p->net.addr, 6, again,
                             la, 1, retry, sizeof retry, &lr, &acc),
              GQ_ADMIT_ACCEPT);
    CHECK (acc.validated && acc.odcid.len == odlen
           && !memcmp (acc.odcid.data, odsave, odlen));
    /* The same token from another address is not accepted.  */
    p->net.addr[0] ^= 1;
    CHECK_EQ (gq_quic_admit (&p->keys, &p->net.admit, p->net.addr, 6, again,
                             la, 1, retry, sizeof retry, &lr, &acc),
              GQ_ADMIT_REPLY);
  }
  pair_free (p);
}

/* Compatible version negotiation (RFC 9368): the version both ends end up
   with.  CV is the client's first flight, CLIST its preference order, SLIST
   the server's versions; the server follows the client's order.  */
static void
compat_run (uint32_t cv, const uint32_t *clist, size_t nc,
            const uint32_t *slist, size_t ns, unsigned loss, uint32_t seed,
            uint32_t expect)
{
  gq_conn_config cc, sc;
  struct pair *p;

  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  cc.version = cv;
  memcpy (cc.versions, clist, nc * sizeof *clist);
  cc.n_versions = nc;
  memcpy (sc.versions, slist, ns * sizeof *slist);
  sc.n_versions = ns;
  p = pair_new (&cc, &sc, loss, seed);
  exchange (p);
  CHECK_EQ (gq_conn_version (p->cli.c), expect);
  CHECK_EQ (gq_conn_version (p->srv.c), expect);
  pair_free (p);
}

static void
test_compat (void)
{
  static const uint32_t v12[2] = { GQ_VERSION_1, GQ_VERSION_2 };
  static const uint32_t v21[2] = { GQ_VERSION_2, GQ_VERSION_1 };
  static const uint32_t v1[1] = { GQ_VERSION_1 };
  static const uint32_t v2[1] = { GQ_VERSION_2 };

  /* The client starts in v1 but prefers v2: it is moved up, whatever the
     server's own order.  */
  compat_run (GQ_VERSION_1, v21, 2, v12, 2, 0, 60, GQ_VERSION_2);
  compat_run (GQ_VERSION_1, v21, 2, v21, 2, 0, 61, GQ_VERSION_2);
  /* ...and one that prefers v1 stays there even if the server likes v2.  */
  compat_run (GQ_VERSION_1, v12, 2, v21, 2, 0, 62, GQ_VERSION_1);
  compat_run (GQ_VERSION_2, v12, 2, v21, 2, 0, 63, GQ_VERSION_1);
  compat_run (GQ_VERSION_2, v21, 2, v12, 2, 0, 64, GQ_VERSION_2);
  /* A server that speaks only one keeps it.  */
  compat_run (GQ_VERSION_1, v21, 2, v1, 1, 0, 65, GQ_VERSION_1);
  compat_run (GQ_VERSION_2, v12, 2, v2, 1, 0, 66, GQ_VERSION_2);
  /* A pinned client gets what it asked for.  */
  compat_run (GQ_VERSION_1, v1, 1, v21, 2, 0, 67, GQ_VERSION_1);
  compat_run (GQ_VERSION_2, v2, 1, v21, 2, 0, 68, GQ_VERSION_2);
  /* Under loss the switch still completes.  */
  compat_run (GQ_VERSION_1, v21, 2, v12, 2, 20, 69, GQ_VERSION_2);
  compat_run (GQ_VERSION_2, v12, 2, v21, 2, 20, 70, GQ_VERSION_1);
  /* With nothing configured a client starts in v1 and both end in v2.  */
  {
    gq_conn_config none;
    struct pair *p;

    memset (&none, 0, sizeof none);
    p = pair_new (&none, &none, 0, 71);
    exchange (p);
    CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_2);
    CHECK_EQ (gq_conn_version (p->srv.c), GQ_VERSION_2);
    pair_free (p);
  }
}

/* An incompatible mismatch: Version Negotiation and a restart.  */
static void
test_version_negotiation (void)
{
  gq_conn_config cc;
  struct pair *p;
  static const uint32_t v1[1] = { GQ_VERSION_1 };

  memset (&cc, 0, sizeof cc);
  cc.version = GQ_VERSION_2;
  cc.versions[0] = GQ_VERSION_2;
  cc.versions[1] = GQ_VERSION_1;
  cc.n_versions = 2;
  cc.wall_seconds = sim_wall;
  p = pair_new_admit (&cc, 0, 70, 0, NULL, 0);
  memcpy (p->net.admit.versions, v1, sizeof v1);
  p->net.admit.n_versions = 1;
  p->scfg_conn.versions[0] = GQ_VERSION_1;
  p->scfg_conn.n_versions = 1;
  p->scfg_conn.version = GQ_VERSION_1;
  exchange (p);
  CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_1);
  CHECK_EQ (gq_conn_version (p->srv.c), GQ_VERSION_1);
  CHECK (p->net.replies >= 1);
  pair_free (p);

  /* No version in common: the client gives up.  */
  cc.versions[1] = GQ_VERSION_2;
  cc.n_versions = 1;
  p = pair_new_admit (&cc, 0, 71, 0, NULL, 0);
  memcpy (p->net.admit.versions, v1, sizeof v1);
  p->net.admit.n_versions = 1;
  run (&p->net, NULL, 2000000);
  CHECK_EQ (p->cli.closed, 1);
  CHECK (p->cli.ci.error == GQ_QERR_VERSION_NEGOTIATION
         && !p->cli.connected);
  CHECK_EQ (gq_conn_state (p->cli.c), GQ_CONN_DONE);
  pair_free (p);
}

/* A forged Version Negotiation packet cannot downgrade the connection: the
   restarted handshake lets the server move it back to the version the
   client prefers (RFC 9368 sections 2 and 4).  */
static void
test_downgrade (void)
{
  gq_conn_config cc;
  struct pair *p;
  uint8_t d1[1500], vn[200], junk[1500];
  size_t l1, vl, jl;
  gq_long_header h;
  static const uint32_t only1[1] = { GQ_VERSION_1 };
  static const uint32_t only2[1] = { GQ_VERSION_2 };

  memset (&cc, 0, sizeof cc);
  cc.version = GQ_VERSION_2;
  cc.versions[0] = GQ_VERSION_2;
  cc.versions[1] = GQ_VERSION_1;
  cc.n_versions = 2;
  cc.wall_seconds = sim_wall;
  p = pair_new_admit (&cc, 0, 72, 0, NULL, 0);
  p->scfg_conn.versions[0] = GQ_VERSION_1;
  p->scfg_conn.versions[1] = GQ_VERSION_2;
  p->scfg_conn.n_versions = 2;
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, d1, sizeof d1, &l1), GQ_OK);
  CHECK_EQ (gq_long_header_parse (d1, l1, &h), GQ_OK);
  while (gq_conn_send (p->cli.c, p->net.now, junk, sizeof junk, &jl) == GQ_OK
         && jl)
    ;
  /* One that lists the version in use is not a real one; nor one that does
     not echo our IDs.  */
  CHECK_EQ (gq_vn_build (h.scid.data, h.scid.len, h.dcid.data, h.dcid.len,
                         only2, 1, 0, vn, sizeof vn, &vl), GQ_OK);
  gq_conn_recv (p->cli.c, p->net.now, vn, vl);
  CHECK_EQ (gq_vn_build (h.dcid.data, h.dcid.len, h.scid.data, h.scid.len,
                         only1, 1, 0, vn, sizeof vn, &vl), GQ_OK);
  gq_conn_recv (p->cli.c, p->net.now, vn, vl);
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, junk, sizeof junk, &jl),
            GQ_OK);
  CHECK_EQ (jl, 0);
  CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_2);
  /* A well-formed forgery that hides v2 from the client.  */
  CHECK_EQ (gq_vn_build (h.scid.data, h.scid.len, h.dcid.data, h.dcid.len,
                         only1, 1, 0, vn, sizeof vn, &vl), GQ_OK);
  gq_conn_recv (p->cli.c, p->net.now, vn, vl);
  CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_1);
  /* The server, seeing a client that started in v1 and prefers v2, moves
     the connection to v2 by compatible negotiation: the forgery achieves
     nothing.  */
  run (&p->net, NULL, 3000000);
  CHECK (p->cli.connected && p->srv.connected);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_2);
  CHECK_EQ (gq_conn_version (p->srv.c), GQ_VERSION_2);
  pair_free (p);
}

/* Tickets are bound to the QUIC version (RFC 9369 section 5): a session
   resumes on a connection of the version that issued it, and on no other.  */
static void
resume_case (uint32_t first, uint32_t second, int expect_resumed)
{
  gq_conn_config c1, c2;
  struct pair *p;
  gq_tls_session sess;
  uint32_t ver;
  static const uint32_t v21[2] = { GQ_VERSION_2, GQ_VERSION_1 };

  memset (&c1, 0, sizeof c1);
  c1.version = first;
  p = pair_new (&c1, &c1, 0, 90);
  exchange (p);
  run (&p->net, NULL, 1000000);
  CHECK (p->cli.have_sess);
  CHECK_EQ (p->cli.sess_version, first);
  CHECK (!p->cli.info.resumed);
  sess = p->cli.sess;
  ver = p->cli.sess_version;
  pair_free (p);

  memset (&c2, 0, sizeof c2);
  if (second)
    c2.version = second;
  else
    {
      /* Starts in v1, prefers v2: the connection ends up in v2.  */
      c2.version = GQ_VERSION_1;
      memcpy (c2.versions, v21, sizeof v21);
      c2.n_versions = 2;
    }
  g_resume = &sess;
  p = pair_new (&c2, &c2, 0, 91);
  g_resume = NULL;
  exchange (p);
  CHECK_EQ (p->cli.info.resumed, expect_resumed);
  CHECK_EQ (p->srv.info.resumed, expect_resumed);
  (void) ver;
  pair_free (p);
}

static void
test_resumption (void)
{
  CHECK_EQ (gq_ticket_keys_new (&g_ring), GQ_OK);
  resume_case (GQ_VERSION_1, GQ_VERSION_1, 1);
  resume_case (GQ_VERSION_2, GQ_VERSION_2, 1);
  resume_case (GQ_VERSION_1, GQ_VERSION_2, 0);
  resume_case (GQ_VERSION_2, GQ_VERSION_1, 0);
  /* Offered in v1, but the server moves the connection to v2.  */
  resume_case (GQ_VERSION_1, 0, 0);
  gq_ticket_keys_free (g_ring);
  g_ring = NULL;
}

static void
test_close (void)
{
  struct pair *p;
  gq_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new (&cfg, &cfg, 0, 5);
  CHECK (run (&p->net, both_connected, 30000000));
  gq_conn_close (p->cli.c, p->net.now, 1, 4242, "bye");
  CHECK_EQ (p->cli.closed, 1);
  CHECK (p->cli.ci.source == GQ_CLOSE_LOCAL && p->cli.ci.application);
  run (&p->net, NULL, 1000000);
  CHECK_EQ (p->srv.closed, 1);
  CHECK (p->srv.ci.source == GQ_CLOSE_PEER && p->srv.ci.application
         && p->srv.ci.error == 4242);
  CHECK (gq_conn_state (p->srv.c) >= GQ_CONN_DRAINING);
  /* The closing period ends.  */
  run (&p->net, NULL, 20000000);
  CHECK_EQ (gq_conn_state (p->cli.c), GQ_CONN_DONE);
  CHECK_EQ (gq_conn_state (p->srv.c), GQ_CONN_DONE);
  pair_free (p);
}

static void
test_idle (void)
{
  struct pair *p;
  gq_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  cfg.idle_timeout_ms = 2000;
  p = pair_new (&cfg, &cfg, 0, 6);
  CHECK (run (&p->net, both_connected, 30000000));
  p->net.loss_pct = 100;		/* The network goes away.  */
  run (&p->net, NULL, 30000000);
  CHECK_EQ (p->cli.closed, 1);
  CHECK (p->cli.ci.source == GQ_CLOSE_IDLE);
  CHECK_EQ (p->srv.closed, 1);
  pair_free (p);
}

static void
test_streams_misc (void)
{
  struct pair *p;
  gq_conn_config cfg;
  uint64_t id, uid;
  struct sbuf *s;
  int i;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new (&cfg, &cfg, 0, 7);
  CHECK (run (&p->net, both_connected, 30000000));
  /* A unidirectional stream: id 2 from the client.  */
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 0, &uid), GQ_OK);
  CHECK_EQ (uid, 2);
  s = sb_get (&p->cli, uid);
  s->out_total = 5000;
  s->out_fin = 1;
  /* A bidirectional stream the client resets, and one the server asks
     it to stop sending on.  */
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  CHECK_EQ (id, 0);
  s = sb_get (&p->cli, id);
  gq_conn_stream_write (p->cli.c, id, (const uint8_t *) "abc", 3);
  run (&p->net, NULL, 500000);
  CHECK (p->srv.opened >= 2);
  gq_conn_stream_reset (p->cli.c, id, 77);
  run (&p->net, NULL, 500000);
  s = sb_get (&p->srv, id);
  CHECK (s->reset && s->err == 77);
  {
    struct sbuf *u = sb_get (&p->srv, uid);

    CHECK (u->fin && u->n == 5000);
  }
  /* Server-side STOP_SENDING: the client's stream 4 gets stopped.  */
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  gq_conn_stream_write (p->cli.c, id, (const uint8_t *) "x", 1);
  run (&p->net, NULL, 500000);
  CHECK_EQ (gq_conn_stream_stop_sending (p->srv.c, id, 55), GQ_OK);
  run (&p->net, NULL, 500000);
  s = sb_get (&p->cli, id);
  CHECK (s->stopped && s->err == 55);
  /* The stream limit is enforced: only 100 bidirectional streams.  */
  for (i = 0; i < 200; i++)
    if (gq_conn_stream_open (p->cli.c, 1, &id) != GQ_OK)
      break;
  CHECK (i < 200 && i > 90);
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_ERR_RANGE);
  /* A server cannot write on a client unidirectional stream.  */
  CHECK_EQ (gq_conn_stream_write (p->srv.c, uid, (const uint8_t *) "x", 1),
            GQ_ERR_INVAL);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  pair_free (p);
}

static void
test_key_update (uint32_t version)
{
  struct pair *p;
  gq_conn_config cfg;
  gq_conn_stats st;
  uint64_t id;
  int round;

  memset (&cfg, 0, sizeof cfg);
  cfg.version = version;
  p = pair_new (&cfg, &cfg, 0, 8);
  p->srv.respond = 20000;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 1000000);
  for (round = 0; round < 4; round++)
    {
      struct sbuf *s;

      CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
      s = sb_get (&p->cli, id);
      s->out_total = 10;
      s->out_fin = 1;
      run (&p->net, NULL, 1000000);
      CHECK (s->fin && s->n == 20000);
      /* Each side updates in turn; the peer follows.  */
      CHECK_EQ (gq_conn_update_keys (p->cli.c, p->net.now), GQ_OK);
    }
  /* The server can start one too, once the last exchange settled.  */
  run (&p->net, NULL, 1000000);
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  sb_get (&p->cli, id)->out_total = 10;
  sb_get (&p->cli, id)->out_fin = 1;
  run (&p->net, NULL, 1000000);
  CHECK_EQ (gq_conn_update_keys (p->srv.c, p->net.now), GQ_OK);
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  sb_get (&p->cli, id)->out_total = 10;
  sb_get (&p->cli, id)->out_fin = 1;
  run (&p->net, NULL, 1000000);
  CHECK (sb_get (&p->cli, id)->fin);
  gq_conn_get_stats (p->cli.c, &st);
  CHECK (st.key_updates >= 5);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  pair_free (p);
}

static void
test_garbage (void)
{
  struct pair *p;
  gq_conn_config cfg;
  uint8_t junk[1300];
  size_t i;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new (&cfg, &cfg, 0, 9);
  p->net.corrupt = 3;		/* Every third datagram is damaged.  */
  for (i = 0; i < sizeof junk; i++)
    junk[i] = (uint8_t) (i * 13);
  /* Junk of every shape at the server before and during the handshake.  */
  for (i = 1; i < 1300; i += 37)
    {
      junk[0] = (uint8_t) (i & 1 ? 0xc0 : 0x40);
      gq_conn_recv (p->srv.c, p->net.now, junk, i);
    }
  run (&p->net, NULL, 60000000);
  CHECK (p->cli.connected && p->srv.connected);
  pair_free (p);
}

int
main (void)
{
  gq_crypto_init ();
  fx_setup ();
  test_handshake (0, 0, 1);		/* Both speak v2 by default.  */
  test_handshake (GQ_VERSION_1, 0, 4);
  test_handshake (GQ_VERSION_2, 0, 2);
  test_handshake (0, 20, 3);
  test_requests (0, 11, 1, 20, 100, NULL, NULL, 0);
  test_requests (0, 12, 10, 50, 300000, NULL, NULL, 0);
  test_requests (5, 13, 8, 5000, 100000, NULL, NULL, 0);
  test_requests (20, 14, 5, 100, 60000, NULL, NULL, 1);
  {
    /* Tight flow control forces credit to be re-granted many times.  */
    gq_conn_config small;

    memset (&small, 0, sizeof small);
    small.initial_max_data = 20000;
    small.initial_max_stream_data = 6000;
    small.send_buffer = 4000;
    test_requests (10, 15, 12, 30, 90000, &small, &small, 0);
  }
  test_congestion (2000000, 0, 0, 0, 0, 0);
  test_congestion (2000000, 3, 0, 0, 1, 0);
  test_congestion (4000000, 0, 1000000, 3000000, 1, 1);
  test_retry (0, 0, 40);
  test_retry (GQ_VERSION_2, 0, 41);
  test_retry (0, 20, 42);
  test_tokens ();
  test_retry_tamper ();
  test_admit_input ();
  test_compat ();
  test_resumption ();
  test_version_negotiation ();
  test_downgrade ();
  test_close ();
  test_idle ();
  test_streams_misc ();
  test_key_update (0);
  test_key_update (GQ_VERSION_2);
  {
    /* Everything again on version 2, with loss and tight flow control.  */
    gq_conn_config v2;

    memset (&v2, 0, sizeof v2);
    v2.version = GQ_VERSION_2;
    v2.initial_max_data = 20000;
    v2.initial_max_stream_data = 6000;
    v2.send_buffer = 4000;
    test_requests (10, 80, 12, 30, 90000, &v2, &v2, 1);
    test_requests (0, 81, 4, 50, 300000, &v2, &v2, 0);
  }
  test_garbage ();
  TST_DONE ();
}

#endif
