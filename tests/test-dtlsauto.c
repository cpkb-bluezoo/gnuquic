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

/* Version negotiation over DTLS (dtlsauto.h): every pairing of a client
   and a server that offer both or one version, with the stateless front
   door and without, over a simulated network with loss.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/dtlsauto.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"

#define MAXQ 256
#define BOTH 0

struct net;

struct side
{
  gq_dtlsauto *a;
  gq_dtls12 *raw;		/* Instead of A: a bare DTLS 1.2 engine.  */
  struct net *net;
  int idx;
  int connected, closed, close_err;
  int n_app;
  char app[16][32];
};

struct pkt
{
  int to;
  uint64_t at;
  size_t len;
  uint8_t data[1500];
};

struct net
{
  struct side s[2];
  struct pkt q[MAXQ];
  int nq;
  uint64_t now;
  int total;
  int lose_every;		/* Drop every Nth datagram (0: none).  */
  gq_dtls_cookies *ck;		/* The front door, if not NULL.  */
  gq_tls_server_config sc;
  gq_dtls_events sev;
  unsigned sver;
  int replies, accepts, drops;
};

static int
ev_send (void *u, const uint8_t *d, size_t n)
{
  struct side *s = u;
  struct net *net = s->net;
  int index = net->total++;
  struct pkt *p;

  if (net->lose_every && index % net->lose_every == 1)
    return 0;
  CHECK (net->nq < MAXQ);
  p = &net->q[net->nq++];
  p->to = 1 - s->idx;
  p->at = net->now + 10;
  p->len = n;
  memcpy (p->data, d, n);
  return 0;
}

static int
ev_data (void *u, const uint8_t *d, size_t n)
{
  struct side *s = u;

  if (s->n_app < 16 && n < 32)
    {
      memcpy (s->app[s->n_app], d, n);
      s->app[s->n_app][n] = 0;
    }
  s->n_app++;
  return 0;
}

static int
ev_connected (void *u, const gq_tls_info *i)
{
  struct side *s = u;

  (void) i;
  s->connected = 1;
  return 0;
}

static void
ev_closed (void *u, int error, int alert)
{
  struct side *s = u;

  (void) alert;
  s->closed++;
  s->close_err = error;
}

/* CLIENT and SERVER are the version flags each end is allowed.  */
static struct net *
net_new (unsigned client, unsigned server, int front)
{
  struct net *n = calloc (1, sizeof *n);
  gq_dtls_events ev;
  gq_tls_config cc;
  static gq_tls_credentials creds;

  n->now = 1000;
  n->s[0].net = n;
  n->s[1].net = n;
  n->s[1].idx = 1;
  memset (&ev, 0, sizeof ev);
  ev.send = ev_send;
  ev.data = ev_data;
  ev.connected = ev_connected;
  ev.closed = ev_closed;

  memset (&cc, 0, sizeof cc);
  cc.server_name = "example.test";
  cc.trust = fx_trust;
  ev.user = &n->s[0];
  CHECK_EQ (gq_dtlsauto_client_new (&n->s[0].a, &cc, &ev, NULL, client),
            GQ_OK);

  memset (&creds, 0, sizeof creds);
  creds.chain = fx_ec.chain;
  creds.n_chain = 1;
  creds.key = fx_ec.key;
  memset (&n->sc, 0, sizeof n->sc);
  n->sc.credentials = creds;
  ev.user = &n->s[1];
  n->sev = ev;
  n->sver = server;
  if (front)
    CHECK_EQ (gq_dtls_cookies_new (&n->ck), GQ_OK);
  else
    CHECK_EQ (gq_dtlsauto_server_new (&n->s[1].a, &n->sc, &ev, NULL, server,
                                      NULL), GQ_OK);
  return n;
}

static void
net_free (struct net *n)
{
  gq_dtlsauto_free (n->s[0].a);
  gq_dtlsauto_free (n->s[1].a);
  gq_dtls12_free (n->s[1].raw);
  gq_dtls_cookies_free (n->ck);
  free (n);
}

static void
front_door (struct net *n, const uint8_t *d, size_t len)
{
  static const uint8_t binding[] = "192.0.2.1:4433";
  uint8_t reply[GQ_DTLS_LISTEN_REPLY_MAX];
  size_t rl;
  gq_dtlsauto_prime prime;
  int r = gq_dtlsauto_listen (n->ck, &n->sc, n->sver, binding,
                              sizeof binding - 1, d, len, reply,
                              sizeof reply, &rl, &prime);

  if (r == GQ_DTLS_LISTEN_REPLY)
    {
      struct pkt *p;

      n->replies++;
      CHECK (rl < len);
      p = &n->q[n->nq++];
      p->to = 0;
      p->at = n->now + 10;
      p->len = rl;
      memcpy (p->data, reply, rl);
      n->total++;
    }
  else if (r == GQ_DTLS_LISTEN_ACCEPT)
    {
      n->accepts++;
      CHECK_EQ (gq_dtlsauto_server_new (&n->s[1].a, &n->sc, &n->sev, NULL,
                                        n->sver, &prime), GQ_OK);
      gq_dtlsauto_receive (n->s[1].a, d, len, n->now);
    }
  else
    {
      CHECK (r == GQ_DTLS_LISTEN_DROP);
      n->drops++;
    }
}

static void
run (struct net *n, uint64_t limit)
{
  uint64_t start = n->now;
  int guard = 0;

  for (;;)
    {
      uint64_t best = 0;
      int bi = -1, kind = 0, i;

      if (++guard > 100000)
        {
          CHECK (!"simulation did not settle");
          break;
        }
      for (i = 0; i < n->nq; i++)
        if (bi < 0 || n->q[i].at < n->q[bi].at)
          bi = i;
      if (bi >= 0)
        {
          best = n->q[bi].at;
          kind = 1;
        }
      for (i = 0; i < 2; i++)
        {
          uint64_t d = n->s[i].raw ? gq_dtls12_deadline (n->s[i].raw)
                       : n->s[i].a ? gq_dtlsauto_deadline (n->s[i].a) : 0;

          if (d && (kind == 0 || d < best))
            {
              best = d;
              kind = 2 + i;
            }
        }
      if (kind == 0 || best - start > limit)
        break;
      if (best > n->now)
        n->now = best;
      if (kind == 1)
        {
          struct pkt p = n->q[bi];

          memmove (&n->q[bi], &n->q[bi + 1],
                   (size_t) (n->nq - bi - 1) * sizeof n->q[0]);
          n->nq--;
          if (n->s[p.to].raw)
            gq_dtls12_receive (n->s[p.to].raw, p.data, p.len, n->now);
          else if (n->s[p.to].a)
            gq_dtlsauto_receive (n->s[p.to].a, p.data, p.len, n->now);
          else if (p.to == 1 && n->ck)
            front_door (n, p.data, p.len);
        }
      else if (n->s[kind - 2].raw)
        gq_dtls12_timeout (n->s[kind - 2].raw, n->now);
      else
        gq_dtlsauto_timeout (n->s[kind - 2].a, n->now);
    }
}

/* Expect a completed association of VERSION, and data both ways.  */
static void
check_connected (struct net *n, unsigned version)
{
  n->lose_every = 0;		/* Application data is not retransmitted.  */
  static const uint8_t m1[] = "hello", m2[] = "world";
  uint8_t a[16], b[16];

  CHECK (n->s[0].connected && n->s[1].connected);
  CHECK_EQ (n->s[0].closed + n->s[1].closed, 0);
  CHECK_EQ (gq_dtlsauto_version (n->s[0].a), version);
  CHECK_EQ (gq_dtlsauto_version (n->s[1].a), version);
  CHECK_EQ (gq_dtlsauto_send (n->s[0].a, m1, 5), GQ_OK);
  CHECK_EQ (gq_dtlsauto_send (n->s[1].a, m2, 5), GQ_OK);
  run (n, 5000);
  CHECK_EQ (n->s[1].n_app, 1);
  CHECK_EQ (n->s[0].n_app, 1);
  CHECK (strcmp (n->s[1].app[0], "hello") == 0);
  CHECK (strcmp (n->s[0].app[0], "world") == 0);
  CHECK_EQ (gq_dtlsauto_export (n->s[0].a, "EXPORTER-test", NULL, 0, a, 16),
            GQ_OK);
  CHECK_EQ (gq_dtlsauto_export (n->s[1].a, "EXPORTER-test", NULL, 0, b, 16),
            GQ_OK);
  CHECK (memcmp (a, b, 16) == 0);
}

static void
one (unsigned client, unsigned server, int front, int lose, unsigned want)
{
  struct net *n = net_new (client, server, front);

  n->lose_every = lose;
  CHECK_EQ (gq_dtlsauto_start (n->s[0].a, n->now), GQ_OK);
  run (n, 120000);
  if (want)
    {
      check_connected (n, want);
      if (front)
        CHECK_EQ (n->accepts, 1);
    }
  else
    {
      CHECK (!(n->s[0].connected && n->s[1].connected));
      CHECK (gq_dtlsauto_is_closed (n->s[0].a) || n->s[0].closed
             || !n->s[1].a || !gq_dtlsauto_is_connected (n->s[0].a));
    }
  net_free (n);
}

/* An attacker who downgrades: a DTLS 1.2 server that carries the sentinel
   of a server that also does 1.3 meets a client that offered both.  */
static void
sentinel (unsigned client, int expect_refused)
{
  struct net *n = net_new (client, BOTH, 0);
  gq_dtls_events ev = n->sev;

  gq_dtlsauto_free (n->s[1].a);
  n->s[1].a = NULL;
  n->sc.tls13_sentinel = 1;
  CHECK_EQ (gq_dtls12_server_new (&n->s[1].raw, &n->sc, &ev, NULL, NULL),
            GQ_OK);
  CHECK_EQ (gq_dtlsauto_start (n->s[0].a, n->now), GQ_OK);
  run (n, 60000);
  if (expect_refused)
    {
      CHECK (!n->s[0].connected);
      CHECK (n->s[0].closed);
    }
  else
    CHECK (n->s[0].connected && n->s[1].connected);
  net_free (n);
}

#define D12 GQ_DTLSAUTO_DTLS12
#define D13 GQ_DTLSAUTO_DTLS13

int
main (void)
{
  int front, lose;

  gq_crypto_init ();
  fx_setup ();
  for (front = 0; front <= 1; front++)
    for (lose = 0; lose <= 3; lose += 3)
      {
        /* Negotiation: both prefer 1.3.  */
        one (BOTH, BOTH, front, lose, 0xfefc);
        /* A server with only 1.2 (or a client with only 1.2).  */
        one (BOTH, D12, front, lose, 0xfefd);
        one (D12, BOTH, front, lose, 0xfefd);
        one (D12, D12, front, lose, 0xfefd);
        /* And only 1.3.  */
        one (BOTH, D13, front, lose, 0xfefc);
        one (D13, BOTH, front, lose, 0xfefc);
        one (D13, D13, front, lose, 0xfefc);
        /* Pinned to different versions: no association.  */
        one (D13, D12, front, lose, 0);
        one (D12, D13, front, lose, 0);
      }
  sentinel (BOTH, 1);
  sentinel (D12, 0);
  TST_DONE ();
}

#endif
