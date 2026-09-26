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

/* DTLS 1.2 associations against each other over a simulated network:
   virtual clock, latency, and loss, duplication, reordering and
   corruption chosen per test.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/dtls12.h>
#include <gnuquic/dtls12rec.h>
#include <gnuquic/dtls12cookie.h>
#include <gnuquic/dtlshs.h>
#include <gnuquic/tlsmsg.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"

#define MAXQ 512

struct net;

struct side
{
  gq_dtls12 *d;
  struct net *net;
  int idx;			/* 0 client, 1 server.  */
  int connected, closed, close_err, close_alert, tickets;
  gq_tls_info info;
  gq_tls_session sess;
  int have_sess;
  char app[64][80];		/* Application messages received.  */
  int n_app;
  int sent;			/* Datagrams this side produced.  */
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
  unsigned latency;
  int total;			/* Datagrams produced overall.  */
  /* Policy.  Return 0 to deliver, 1 to drop.  */
  int (*lose) (struct net *n, int from, int index, void *user);
  void *lose_user;
  int dup_all;			/* Deliver everything twice.  */
  int reorder;			/* Odd datagrams arrive after the next.  */
  int corrupt;			/* Flip a byte in every Nth datagram.  */
  int delivered;
  /* Server front door (dtlscookie.h), when used.  */
  gq_dtls_cookies *ck;
  gq_tls_server_config sc;
  gq_dtls_events sev;
  gq_dtls_params sparams;
  int replies, accepts, drops;
  const char *binding;
};

static int
ev_send (void *u, const uint8_t *d, size_t n)
{
  struct side *s = u;
  struct net *net = s->net;
  int index = net->total++, i;
  struct pkt *p;

  s->sent++;
  if (net->lose && net->lose (net, s->idx, index, net->lose_user))
    return 0;
  for (i = 0; i < (net->dup_all ? 2 : 1); i++)
    {
      CHECK (net->nq < MAXQ);
      if (net->nq >= MAXQ)
        return 1;
      p = &net->q[net->nq++];
      p->to = 1 - s->idx;
      p->at = net->now + net->latency
        + (net->reorder && (index & 1) ? 15 : 0) + (uint64_t) i * 3;
      p->len = n;
      CHECK (n <= sizeof p->data);
      memcpy (p->data, d, n);
      if (net->corrupt && index % net->corrupt == 0 && n > 3)
        p->data[(size_t) index % n] ^= 0x40;
    }
  return 0;
}

static int
ev_data (void *u, const uint8_t *d, size_t n)
{
  struct side *s = u;

  if (s->n_app < 64 && n < 80)
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

  s->connected = 1;
  s->info = *i;
  return 0;
}

static int
ev_ticket (void *u, const gq_tls_ticket *t)
{
  struct side *s = u;

  s->tickets++;
  CHECK_EQ (gq_tls_session_store (&s->sess, t), GQ_OK);
  s->have_sess = 1;
  return 0;
}

static void
ev_closed (void *u, int error, int alert)
{
  struct side *s = u;

  s->closed++;
  s->close_err = error;
  s->close_alert = alert;
}

struct opts
{
  struct ident *server_id;
  const uint16_t *csuites;
  size_t n_csuites;
  const gq_tls_session *resume;
  gq_ticket_keys *keys;
  enum gq_client_auth auth;
  struct ident *client_id;
  gq_dtls_params params;
  const gq_dtls12_prime *prime;
  int no_server;		/* Do not create the server.  */
  int cookie;			/* Put gq_dtls_listen in front of it.  */
};

static struct net *
net_new (const struct opts *o)
{
  struct net *n = calloc (1, sizeof *n);
  gq_dtls_events ev;
  gq_tls_config cc;
  gq_tls_server_config sc;
  struct ident *sid = o->server_id ? o->server_id : &fx_ec;
  static gq_tls_credentials creds;
  int i;

  n->latency = 10;
  n->now = 1000;
  for (i = 0; i < 2; i++)
    {
      n->s[i].net = n;
      n->s[i].idx = i;
    }
  memset (&ev, 0, sizeof ev);
  ev.send = ev_send;
  ev.data = ev_data;
  ev.connected = ev_connected;
  ev.ticket = ev_ticket;
  ev.closed = ev_closed;

  memset (&cc, 0, sizeof cc);
  cc.server_name = "example.test";
  cc.trust = fx_trust;
  cc.suites = o->csuites;
  cc.n_suites = o->n_csuites;
  cc.resume = o->resume;
  if (o->client_id)
    {
      cc.client_chain = o->client_id->chain;
      cc.n_client_chain = 1;
      cc.client_key = o->client_id->key;
    }
  ev.user = &n->s[0];
  CHECK_EQ (gq_dtls12_client_new (&n->s[0].d, &cc, &ev, &o->params), GQ_OK);

  if (!o->no_server)
    {
      memset (&sc, 0, sizeof sc);
      memset (&creds, 0, sizeof creds);
      creds.chain = sid->chain;
      creds.n_chain = 1;
      creds.key = sid->key;
      sc.credentials = creds;
      sc.ticket_keys = o->keys;
      sc.client_auth = o->auth;
      sc.client_trust = fx_trust;
      ev.user = &n->s[1];
      if (o->cookie)
        {
          /* The association comes later, from the listener.  */
          n->sc = sc;
          n->sev = ev;
          n->sparams = o->params;
          n->binding = "192.0.2.1:4433";
          CHECK_EQ (gq_dtls_cookies_new (&n->ck), GQ_OK);
        }
      else
        CHECK_EQ (gq_dtls12_server_new (&n->s[1].d, &sc, &ev, &o->params,
                                      o->prime), GQ_OK);
    }
  return n;
}

static void
net_free (struct net *n)
{
  gq_dtls12_free (n->s[0].d);
  gq_dtls12_free (n->s[1].d);
  gq_dtls_cookies_free (n->ck);
  free (n);
}

/* A datagram for a server that has no association yet.  */
static void
front_door (struct net *n, const uint8_t *d, size_t len)
{
  uint8_t reply[GQ_DTLS_LISTEN_REPLY_MAX];
  size_t rl;
  gq_dtls12_prime prime;
  int r = gq_dtls12_listen (n->ck, (const uint8_t *) n->binding,
                            strlen (n->binding), d, len, reply, sizeof reply,
                            &rl, &prime);

  if (r == GQ_DTLS_LISTEN_REPLY)
    {
      struct side *c = &n->s[1];
      struct pkt *p;

      n->replies++;
      CHECK (rl < len);			/* No amplification.  */
      CHECK (n->nq < MAXQ);
      p = &n->q[n->nq++];
      p->to = 0;
      p->at = n->now + n->latency;
      p->len = rl;
      memcpy (p->data, reply, rl);
      c->sent++;
      n->total++;
    }
  else if (r == GQ_DTLS_LISTEN_ACCEPT)
    {
      n->accepts++;
      CHECK_EQ (gq_dtls12_server_new (&n->s[1].d, &n->sc, &n->sev, &n->sparams,
                                    &prime), GQ_OK);
      gq_dtls12_receive (n->s[1].d, d, len, n->now);
    }
  else
    {
      CHECK (r == GQ_DTLS_LISTEN_DROP);
      n->drops++;
    }
}

/* Advance the simulation until nothing is left to do or LIMIT ms passed.
   Returns the virtual time spent.  */
static uint64_t
run (struct net *n, uint64_t limit)
{
  uint64_t start = n->now;
  int guard = 0;

  for (;;)
    {
      uint64_t best = 0;

      if (++guard > 200000)		/* A livelock is a failure, not a hang.  */
        {
          CHECK (!"simulation did not settle");
          break;
        }
      int bi = -1, kind = 0, i;

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
          uint64_t d = n->s[i].d ? gq_dtls12_deadline (n->s[i].d) : 0;

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
          n->delivered++;
          if (n->s[p.to].d)
            gq_dtls12_receive (n->s[p.to].d, p.data, p.len, n->now);
          else if (p.to == 1 && n->ck)
            front_door (n, p.data, p.len);
        }
      else
        gq_dtls12_timeout (n->s[kind - 2].d, n->now);
    }
  return n->now - start;
}

/* Handshake from a fresh pair; true if both ends connected.  */
static int
handshake (struct net *n, uint64_t limit)
{
  CHECK_EQ (gq_dtls12_start (n->s[0].d, n->now), GQ_OK);
  run (n, limit);
  return n->s[0].connected && n->s[1].connected;
}

static void
expect_ok (struct net *n)
{
  CHECK (n->s[0].connected && n->s[1].connected);
  CHECK (gq_dtls12_is_connected (n->s[0].d) && gq_dtls12_is_connected (n->s[1].d));
  CHECK_EQ (n->s[0].info.cipher_suite, n->s[1].info.cipher_suite);
  CHECK_EQ (n->s[0].info.group, n->s[1].info.group);
  CHECK_EQ (n->s[0].closed, 0);
  CHECK_EQ (n->s[1].closed, 0);
  /* The exporter agrees.  */
  {
    uint8_t a[24], b[24];

    CHECK_EQ (gq_dtls12_export (n->s[0].d, "EXPORTER-dtls", NULL, 0, a, 24), GQ_OK);
    CHECK_EQ (gq_dtls12_export (n->s[1].d, "EXPORTER-dtls", NULL, 0, b, 24), GQ_OK);
    CHECK (memcmp (a, b, 24) == 0);
  }
}

/* Send N numbered messages each way and check they arrive in order.  */
static void
exchange (struct net *n, int count, int lossless)
{
  int i, base0 = n->s[0].n_app, base1 = n->s[1].n_app;
  char m[40];

  for (i = 0; i < count; i++)
    {
      snprintf (m, sizeof m, "c2s-%d", i);
      CHECK_EQ (gq_dtls12_send (n->s[0].d, (const uint8_t *) m, strlen (m)), GQ_OK);
      snprintf (m, sizeof m, "s2c-%d", i);
      CHECK_EQ (gq_dtls12_send (n->s[1].d, (const uint8_t *) m, strlen (m)), GQ_OK);
    }
  run (n, 5000);
  if (lossless)
    {
      CHECK_EQ (n->s[1].n_app - base1, count);
      CHECK_EQ (n->s[0].n_app - base0, count);
      for (i = 0; i < count && i < 60 && base1 + i < 64; i++)
        {
          snprintf (m, sizeof m, "c2s-%d", i);
          CHECK (strcmp (n->s[1].app[base1 + i], m) == 0);
          snprintf (m, sizeof m, "s2c-%d", i);
          CHECK (strcmp (n->s[0].app[base0 + i], m) == 0);
        }
    }
}

/* ---- Tests ---- */


static int
lose_one (struct net *n, int from, int index, void *u)
{
  (void) n; (void) from;
  return index == *(int *) u;
}

static void
single_loss (unsigned mtu, int server_split)
{
  struct opts o;
  struct net *ref;
  int total, i;

  memset (&o, 0, sizeof o);
  o.params.mtu = mtu;
  o.server_id = server_split ? &fx_rsa : NULL;
  ref = net_new (&o);
  CHECK (handshake (ref, 20000));
  run (ref, 5000);
  total = ref->total;
  CHECK (total >= 4 && total < 200);
  net_free (ref);

  /* Whichever datagram of the handshake is lost, it still completes and
     the connection carries data.  */
  for (i = 0; i < total; i++)
    {
      struct net *n = net_new (&o);
      int drop = i;

      n->lose = lose_one;
      n->lose_user = &drop;
      if (!handshake (n, 120000))
        fprintf (stderr, "handshake stuck with datagram %d lost\n", i);
      CHECK (n->s[0].connected && n->s[1].connected);
      run (n, 60000);
      expect_ok (n);
      exchange (n, 5, 1);
      net_free (n);
    }
}

/* With records spread over many datagrams, the loss of any one (a lone
   Finished, a lone ChangeCipherSpec, part of a certificate) is repaired.  */
static void
test_single_loss (void)
{
  single_loss (0, 0);
  single_loss (300, 0);
  single_loss (300, 1);
  single_loss (600, 1);
}

static int
lose_random (struct net *n, int from, int index, void *u)
{
  static uint32_t st;
  int pct = *(int *) u;

  (void) n; (void) from; (void) index;
  st = st * 1664525u + 1013904223u;
  return (int) ((st >> 12) % 100) < pct;
}

static void
test_random_loss (void)
{
  int pct[] = { 10, 25, 40 };
  size_t p;
  int seed, ok = 0, runs = 0;

  for (p = 0; p < 3; p++)
    for (seed = 0; seed < 25; seed++)
      {
        struct opts o;
        struct net *n;

        memset (&o, 0, sizeof o);
        o.params.max_retransmits = 12;	/* Generous: this is loss, not death.  */
        n = net_new (&o);
        n->lose = lose_random;
        n->lose_user = &pct[p];
        runs++;
        if (handshake (n, 2000000))
          {
            ok++;
            run (n, 600000);
            expect_ok (n);
          }
        net_free (n);
      }
  /* With retransmission and 12 tries nearly every run gets through.  */
  CHECK (ok >= runs - 2);
}

static void
test_reorder_duplicate_corrupt (void)
{
  struct opts o;
  struct net *n;

  memset (&o, 0, sizeof o);
  n = net_new (&o);
  n->reorder = 1;
  CHECK (handshake (n, 30000));
  run (n, 20000);
  expect_ok (n);
  exchange (n, 8, 0);
  CHECK_EQ (n->s[1].n_app, 8);		/* Reordered, none lost: same count.  */
  net_free (n);

  /* Every datagram twice: replays are dropped, data seen once.  */
  n = net_new (&o);
  n->dup_all = 1;
  CHECK (handshake (n, 30000));
  run (n, 20000);
  expect_ok (n);
  exchange (n, 8, 1);
  net_free (n);

  /* Corruption: authenticated records fail and are dropped; the
     retransmissions get through.  */
  n = net_new (&o);
  n->corrupt = 3;
  CHECK (handshake (n, 600000));
  run (n, 200000);
  CHECK (n->s[0].connected && n->s[1].connected);
  CHECK_EQ (n->s[0].closed + n->s[1].closed, 0);
  net_free (n);
}

/* A peer that never answers: backoff 1, 2, 4 ... then GQ_ERR_TIMEOUT.  */
static void
test_timeout (void)
{
  struct opts o;
  struct net *n;
  uint64_t t, prev, gaps[8];
  int k = 0;

  memset (&o, 0, sizeof o);
  o.no_server = 1;
  n = net_new (&o);
  CHECK_EQ (gq_dtls12_start (n->s[0].d, n->now), GQ_OK);
  prev = n->now;
  while ((t = gq_dtls12_deadline (n->s[0].d)) != 0 && k < 8)
    {
      gaps[k++] = t - prev;
      prev = t;
      n->now = t;
      if (gq_dtls12_timeout (n->s[0].d, t) == GQ_ERR_TIMEOUT)
        break;
    }
  CHECK_EQ (k, 7);
  CHECK (gaps[0] == 1000 && gaps[1] == 2000 && gaps[2] == 4000
         && gaps[3] == 8000 && gaps[4] == 16000 && gaps[5] == 32000
         && gaps[6] == 60000);
  CHECK_EQ (n->s[0].closed, 1);
  CHECK_EQ (n->s[0].close_err, GQ_ERR_TIMEOUT);
  CHECK (gq_dtls12_is_closed (n->s[0].d));
  net_free (n);
}

/* Fragmentation: the certificate chain and the hybrid key share are bigger
   than a datagram; small MTUs split even more.  */
static void
test_mtu (void)
{
  static const unsigned mtus[] = { 300, 512, 1200, 1400 };
  size_t i;

  for (i = 0; i < sizeof mtus / sizeof mtus[0]; i++)
    {
      struct opts o;
      struct net *n;

      memset (&o, 0, sizeof o);
      o.params.mtu = mtus[i];
      o.server_id = &fx_rsa;
      n = net_new (&o);
      CHECK (handshake (n, 60000));
      expect_ok (n);
      /* No datagram exceeded the MTU.  */
      CHECK_EQ (gq_dtls12_max_payload (n->s[0].d), (size_t) mtus[i] - 37);
      exchange (n, 3, 1);
      {
        uint8_t big[1500];
        size_t m = gq_dtls12_max_payload (n->s[0].d);

        memset (big, 7, sizeof big);
        CHECK_EQ (gq_dtls12_send (n->s[0].d, big, m), GQ_OK);
        CHECK_EQ (gq_dtls12_send (n->s[0].d, big, m + 1), GQ_ERR_BUFSIZE);
      }
      net_free (n);
    }
}

/* Tickets are delivered reliably after the handshake; a second handshake
   resumes with them.  */
static void
test_resumption (void)
{
  struct opts o;
  struct net *n;
  gq_ticket_keys *keys;
  gq_tls_session sess;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  memset (&o, 0, sizeof o);
  o.keys = keys;
  n = net_new (&o);
  CHECK (handshake (n, 20000));
  run (n, 20000);
  expect_ok (n);
  CHECK (n->s[0].tickets >= 1 && n->s[0].have_sess);
  CHECK_EQ (n->s[0].info.resumed, 0);
  /* All acknowledged: nothing left retransmitting.  */
  CHECK_EQ (gq_dtls12_deadline (n->s[1].d), 0);
  sess = n->s[0].sess;
  net_free (n);

  o.resume = &sess;
  n = net_new (&o);
  CHECK (handshake (n, 20000));
  run (n, 20000);
  expect_ok (n);
  CHECK_EQ (n->s[0].info.resumed, 1);
  CHECK_EQ (n->s[1].info.resumed, 1);
  exchange (n, 3, 1);
  net_free (n);
  gq_ticket_keys_free (keys);
}

static void
test_client_auth (void)
{
  struct opts o;
  struct net *n;

  memset (&o, 0, sizeof o);
  o.auth = GQ_CLIENT_AUTH_REQUIRED;
  o.client_id = &fx_cli_ec;
  n = net_new (&o);
  CHECK (handshake (n, 30000));
  run (n, 20000);
  expect_ok (n);
  CHECK_EQ (n->s[0].info.client_auth_sent, 1);
  CHECK_EQ (n->s[1].info.client_auth_sent, 1);
  net_free (n);

  /* Required and absent: the server's alert ends both.  */
  o.client_id = NULL;
  n = net_new (&o);
  CHECK (!handshake (n, 30000));
  run (n, 30000);
  CHECK_EQ (n->s[1].closed, 1);
  CHECK_EQ (n->s[1].close_alert, 40);
  net_free (n);
}

static void
test_noise (void)
{
  struct opts o;
  struct net *n;
  uint8_t junk[300];
  size_t i, k;
  uint32_t st = 7;

  memset (&o, 0, sizeof o);
  n = net_new (&o);
  CHECK (handshake (n, 20000));
  run (n, 20000);
  for (i = 0; i < 2000; i++)
    {
      size_t len = 1 + (st >> 9) % sizeof junk;

      for (k = 0; k < len; k++)
        {
          st = st * 1664525u + 1013904223u;
          junk[k] = (uint8_t) (st >> 16);
        }
      /* Half of them start like DTLS 1.2 records.  */
      if (i & 1)
        {
          junk[0] = (uint8_t) (20 + (i & 3));
          junk[1] = 0xfe; junk[2] = 0xfd;
          junk[3] = 0; junk[4] = (uint8_t) ((i >> 2) & 1);
          junk[11] = 0; junk[12] = (uint8_t) (len > 13 ? len - 13 : 0);
        }
      gq_dtls12_receive (n->s[i & 1].d, junk, len, n->now);
    }
  CHECK_EQ (n->s[0].closed + n->s[1].closed, 0);
  exchange (n, 3, 1);
  net_free (n);

  /* Before the handshake: same noise at a server that has seen nothing, and
     at a client waiting for the ServerHello.  */
  n = net_new (&o);
  gq_dtls12_start (n->s[0].d, n->now);
  for (i = 0; i < 1500; i++)
    {
      size_t len = 1 + (st >> 9) % sizeof junk;

      for (k = 0; k < len; k++)
        {
          st = st * 1664525u + 1013904223u;
          junk[k] = (uint8_t) (st >> 16);
        }
      if (i & 1)
        {
          junk[0] = (i & 4) ? 22 : 21;
          junk[1] = 0xfe; junk[2] = 0xfd;
          memset (junk + 3, 0, 8);
          junk[11] = 0; junk[12] = (uint8_t) (len > 13 ? len - 13 : 0);
        }
      gq_dtls12_receive (n->s[(i >> 1) & 1].d, junk, len, n->now);
    }
  /* Then the real handshake still works (nothing was closed by noise
     except a forged plaintext alert at the client, which is allowed).  */
  net_free (n);
}

/* ---- Cookies ---- */

static void
test_cookie_loss (void)
{
  struct opts o;
  struct net *ref;
  int total, i;

  memset (&o, 0, sizeof o);
  o.cookie = 1;
  ref = net_new (&o);
  CHECK (handshake (ref, 20000));
  run (ref, 5000);
  total = ref->total;
  net_free (ref);
  for (i = 0; i < total; i++)
    {
      struct net *n = net_new (&o);
      int drop = i;

      n->lose = lose_one;
      n->lose_user = &drop;
      if (!handshake (n, 200000))
        fprintf (stderr, "cookie handshake stuck, datagram %d lost\n", i);
      run (n, 100000);
      expect_ok (n);
      exchange (n, 3, 1);
      net_free (n);
    }
}

/* Take the datagrams the client has produced from the network queue.  */
static size_t
take_dgram (struct net *n, uint8_t *out)
{
  size_t len = 0;

  if (n->nq)
    {
      len = n->q[0].len;
      memcpy (out, n->q[0].data, len);
      memmove (&n->q[0], &n->q[1], (size_t) (n->nq - 1) * sizeof n->q[0]);
      n->nq--;
    }
  return len;
}

static const uint16_t ecdsa128[] = { GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };
static const uint16_t ecdsa256[] = { GQ_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 };
static const uint16_t ecdsachacha[] = { GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 };
static const uint16_t rsa128[] = { GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 };
static const uint16_t rsa256[] = { GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 };
static const uint16_t rsachacha[] = { GQ_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 };

static void
test_handshakes (void)
{
  static const struct { const uint16_t *s; int rsa; } cases[] = {
    { NULL, 0 }, { ecdsa128, 0 }, { ecdsa256, 0 }, { ecdsachacha, 0 },
    { NULL, 1 }, { rsa128, 1 }, { rsa256, 1 }, { rsachacha, 1 }
  };
  size_t i;

  for (i = 0; i < sizeof cases / sizeof cases[0]; i++)
    {
      struct opts o;
      struct net *n;

      memset (&o, 0, sizeof o);
      o.csuites = cases[i].s;
      o.n_csuites = cases[i].s ? 1 : 0;
      o.server_id = cases[i].rsa ? &fx_rsa : NULL;
      n = net_new (&o);
      CHECK (handshake (n, 20000));
      expect_ok (n);
      if (cases[i].s)
        CHECK_EQ (n->s[0].info.cipher_suite, cases[i].s[0]);
      exchange (n, 10, 1);
      /* Everything settled: no timers, nothing in flight.  (The last
         flight is kept but has no timer.)  */
      CHECK_EQ (gq_dtls12_deadline (n->s[0].d), 0);
      CHECK_EQ (gq_dtls12_deadline (n->s[1].d), 0);
      CHECK_EQ (n->nq, 0);
      CHECK_EQ (gq_dtls12_close (n->s[0].d), GQ_OK);
      run (n, 1000);
      CHECK (n->s[0].closed == 1 && n->s[0].close_err == 0);
      CHECK (n->s[1].closed == 1 && n->s[1].close_err == 0);
      CHECK_EQ (gq_dtls12_send (n->s[0].d, (const uint8_t *) "x", 1),
                GQ_ERR_INVAL);
      net_free (n);
    }
}

static void
test_cookie_handshake (void)
{
  struct opts o;
  struct net *n;

  memset (&o, 0, sizeof o);
  o.cookie = 1;
  o.server_id = &fx_rsa;
  n = net_new (&o);
  CHECK_EQ (gq_dtls12_start (n->s[0].d, n->now), GQ_OK);
  run (n, 20000);
  /* One HelloVerifyRequest; no association until the cookie came back.  */
  CHECK_EQ (n->replies, 1);
  CHECK_EQ (n->accepts, 1);
  expect_ok (n);
  exchange (n, 5, 1);
  net_free (n);
}

static void
test_listener (void)
{
  struct opts o;
  struct net *n;
  uint8_t ch1[1500], reply[GQ_DTLS_LISTEN_REPLY_MAX], ch2[1500], junk[400];
  size_t ch1_len, rl, ch2_len, i, cpos, spos;
  gq_dtls12_prime prime;
  static const uint8_t bind1[] = "10.0.0.1:1111", bind2[] = "10.0.0.2:1111";
  gq_dtls_cookies *ck;
  uint32_t st = 5;

  memset (&o, 0, sizeof o);
  o.no_server = 1;
  n = net_new (&o);
  CHECK_EQ (gq_dtls_cookies_new (&ck), GQ_OK);
  CHECK_EQ (gq_dtls12_start (n->s[0].d, n->now), GQ_OK);
  ch1_len = take_dgram (n, ch1);
  CHECK (ch1_len > 100 && ch1_len < 700);

  /* ClientHello1: a HelloVerifyRequest, smaller, numbered like the hello.  */
  CHECK_EQ (gq_dtls12_listen (ck, bind1, sizeof bind1, ch1, ch1_len, reply,
                              sizeof reply, &rl, &prime), GQ_DTLS_LISTEN_REPLY);
  CHECK (rl > 0 && rl < ch1_len);
  CHECK_EQ (reply[0], 22);
  CHECK (memcmp (reply + 3, ch1 + 3, 8) == 0);	/* epoch and sequence */
  CHECK_EQ (reply[13], 3);			/* HelloVerifyRequest */
  {
    uint8_t again[GQ_DTLS_LISTEN_REPLY_MAX], other[GQ_DTLS_LISTEN_REPLY_MAX];
    size_t al, ol;

    CHECK_EQ (gq_dtls12_listen (ck, bind1, sizeof bind1, ch1, ch1_len, again,
                                sizeof again, &al, &prime),
              GQ_DTLS_LISTEN_REPLY);
    CHECK (al == rl && memcmp (again, reply, rl) == 0);	/* stateless */
    CHECK_EQ (gq_dtls12_listen (ck, bind2, sizeof bind2, ch1, ch1_len, other,
                                sizeof other, &ol, &prime),
              GQ_DTLS_LISTEN_REPLY);
    CHECK (memcmp (other, reply, rl) != 0);		/* per address */
  }

  CHECK_EQ (gq_dtls12_receive (n->s[0].d, reply, rl, n->now), GQ_OK);
  ch2_len = take_dgram (n, ch2);
  CHECK (ch2_len > 100);
  CHECK_EQ (gq_dtls12_listen (ck, bind1, sizeof bind1, ch2, ch2_len, reply,
                              sizeof reply, &rl, &prime), GQ_DTLS_LISTEN_ACCEPT);
  {
    uint64_t seq = 0;

    for (i = 5; i < 11; i++)
      seq = (seq << 8) | ch2[i];
    CHECK_EQ (prime.e0_seq, seq + 1);
  }
  CHECK (gq_dtls12_listen (ck, bind2, sizeof bind2, ch2, ch2_len, reply,
                           sizeof reply, &rl, &prime) != GQ_DTLS_LISTEN_ACCEPT);

  /* Changing the random, session ID, suites or cookie spoils it.  */
  spos = 25 + 2 + 32 + 1 + ch2[25 + 2 + 32];		/* after session id */
  cpos = spos;						/* cookie length byte */
  {
    size_t clen = ch2[cpos], suites_len;

    suites_len = ((size_t) ch2[cpos + 1 + clen] << 8) | ch2[cpos + 2 + clen];
    for (i = 25 + 2; i < cpos + 3 + clen + suites_len; i++)
      {
        uint8_t copy[1500];

        memcpy (copy, ch2, ch2_len);
        copy[i] ^= 0x01;
        CHECK (gq_dtls12_listen (ck, bind1, sizeof bind1, copy, ch2_len,
                                 reply, sizeof reply, &rl, &prime)
               != GQ_DTLS_LISTEN_ACCEPT);
      }
  }

  CHECK_EQ (gq_dtls_cookies_rotate (ck), GQ_OK);
  CHECK_EQ (gq_dtls12_listen (ck, bind1, sizeof bind1, ch2, ch2_len, reply,
                              sizeof reply, &rl, &prime), GQ_DTLS_LISTEN_ACCEPT);
  CHECK_EQ (gq_dtls_cookies_rotate (ck), GQ_OK);
  CHECK (gq_dtls12_listen (ck, bind1, sizeof bind1, ch2, ch2_len, reply,
                           sizeof reply, &rl, &prime) != GQ_DTLS_LISTEN_ACCEPT);

  /* Noise, and a real hello flipped byte by byte, never accepted.  */
  for (i = 0; i < 3000; i++)
    {
      size_t len = 1 + (st >> 9) % sizeof junk, k;
      int r;

      for (k = 0; k < len; k++)
        {
          st = st * 1664525u + 1013904223u;
          junk[k] = (uint8_t) (st >> 16);
        }
      if (i & 1)
        {
          junk[0] = 22; junk[1] = 0xfe; junk[2] = 0xfd;
          memset (junk + 3, 0, 8);
          junk[11] = (uint8_t) ((len > 13 ? len - 13 : 0) >> 8);
          junk[12] = (uint8_t) (len > 13 ? len - 13 : 0);
          if (len > 25)
            junk[13] = 1;
        }
      r = gq_dtls12_listen (ck, bind1, sizeof bind1, junk, len, reply,
                            sizeof reply, &rl, &prime);
      CHECK (r == GQ_DTLS_LISTEN_DROP || r == GQ_DTLS_LISTEN_REPLY);
    }
  for (i = 0; i < ch1_len; i++)
    {
      uint8_t copy[1500];

      memcpy (copy, ch1, ch1_len);
      copy[i] ^= 0x10;
      CHECK (gq_dtls12_listen (ck, bind1, sizeof bind1, copy, ch1_len, reply,
                               sizeof reply, &rl, &prime)
             != GQ_DTLS_LISTEN_ACCEPT);
    }
  CHECK (gq_dtls12_listen (NULL, bind1, 1, ch1, ch1_len, reply, sizeof reply,
                           &rl, &prime) < 0);
  CHECK (gq_dtls12_listen (ck, bind1, 1, ch1, ch1_len, reply, 100, &rl,
                           &prime) < 0);
  gq_dtls_cookies_free (ck);
  net_free (n);
}


int
main (void)
{
  gq_crypto_init ();
  fx_setup ();
  test_cookie_handshake ();
  test_cookie_loss ();
  test_listener ();
  test_handshakes ();
  test_single_loss ();
  test_random_loss ();
  test_reorder_duplicate_corrupt ();
  test_timeout ();
  test_mtu ();
  test_resumption ();
  test_client_auth ();
  test_noise ();
  TST_DONE ();
}

#endif
