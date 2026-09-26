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

  if (a->closed || gq_conn_state (a->c) >= GQ_CONN_CLOSING)
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

          n->q[best] = n->q[--n->nq];
          /* Keep delivery order stable among equal times.  */
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
  fill_events (&p->cev, &p->cli);
  fill_events (&p->sev, &p->srv);
  CHECK_EQ (gq_conn_client_new (&p->cli.c, ccfg, &p->ccfg, &p->cev,
                                p->net.now), GQ_OK);
  CHECK_EQ (gq_conn_server_new (&p->srv.c, scfg, &p->scfg, &p->sev,
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
  CHECK_EQ (gq_conn_version (p->cli.c), version ? version : GQ_VERSION_1);
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
test_key_update (void)
{
  struct pair *p;
  gq_conn_config cfg;
  gq_conn_stats st;
  uint64_t id;
  int round;

  memset (&cfg, 0, sizeof cfg);
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
  test_handshake (0, 0, 1);
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
  test_close ();
  test_idle ();
  test_streams_misc ();
  test_key_update ();
  test_garbage ();
  TST_DONE ();
}

#endif
