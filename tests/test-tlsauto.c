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

/* The negotiating front (tlsauto.h): a server that serves TLS 1.2 and 1.3
   from one listener, and a client that offers both, joined back to back over
   real records.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/tlsauto.h>
#include <gnuquic/tls12conn.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"

struct bytes
{
  uint8_t *p;
  size_t n, cap;
};

static void
bytes_add (struct bytes *b, const uint8_t *d, size_t n)
{
  if (b->n + n > b->cap)
    {
      b->cap = (b->n + n) * 2 + 64;
      b->p = realloc (b->p, b->cap);
    }
  memcpy (b->p + b->n, d, n);
  b->n += n;
}

enum kind { K13, K12, KAUTO };

struct peer
{
  enum kind kind;
  gq_tlsconn *c13;
  gq_tls12conn *c12;
  gq_tlsauto *ca;
  gq_tlsconn_events ev;
  struct bytes out, app;
  int connected, closed, error;
};

static int
ev_write (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct peer *) u)->out, d, n);
  return 0;
}

static int
ev_data (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct peer *) u)->app, d, n);
  return 0;
}

static int
ev_connected (void *u, const gq_tls_info *i)
{
  (void) i;
  ((struct peer *) u)->connected = 1;
  return 0;
}

static void
ev_closed (void *u, int error, int alert)
{
  struct peer *p = u;

  (void) alert;
  p->closed = 1;
  p->error = error;
}

static void
peer_init (struct peer *p, enum kind k)
{
  memset (p, 0, sizeof *p);
  p->kind = k;
  p->ev.user = p;
  p->ev.write = ev_write;
  p->ev.data = ev_data;
  p->ev.connected = ev_connected;
  p->ev.closed = ev_closed;
}

static gq_tls_config
client_cfg (void)
{
  gq_tls_config c;

  memset (&c, 0, sizeof c);
  c.server_name = "example.test";
  c.trust = fx_trust;
  return c;
}

static gq_tls_server_config
server_cfg (void)
{
  gq_tls_server_config c;

  memset (&c, 0, sizeof c);
  c.credentials.chain = fx_ec.chain;
  c.credentials.n_chain = 1;
  c.credentials.key = fx_ec.key;
  return c;
}

static void
peer_free (struct peer *p)
{
  gq_tlsconn_free (p->c13);
  gq_tls12conn_free (p->c12);
  gq_tlsauto_free (p->ca);
  free (p->out.p);
  free (p->app.p);
}

static int
peer_recv (struct peer *p, const uint8_t *d, size_t n)
{
  switch (p->kind)
    {
    case K13: return gq_tlsconn_receive (p->c13, d, n);
    case K12: return gq_tls12conn_receive (p->c12, d, n);
    default: return gq_tlsauto_receive (p->ca, d, n);
    }
}

static int
peer_send (struct peer *p, const uint8_t *d, size_t n)
{
  switch (p->kind)
    {
    case K13: return gq_tlsconn_send (p->c13, d, n);
    case K12: return gq_tls12conn_send (p->c12, d, n);
    default: return gq_tlsauto_send (p->ca, d, n);
    }
}

/* Move everything each side wrote to the other, in CHUNK byte pieces.  */
static void
pump (struct peer *a, struct peer *b, size_t chunk)
{
  int rounds;

  for (rounds = 0; rounds < 200; rounds++)
    {
      struct peer *from[2] = { a, b }, *to[2] = { b, a };
      int i, moved = 0;

      for (i = 0; i < 2; i++)
        {
          struct bytes t = from[i]->out;
          size_t off = 0;

          from[i]->out.p = NULL;
          from[i]->out.n = from[i]->out.cap = 0;
          while (off < t.n)
            {
              size_t k = t.n - off < chunk ? t.n - off : chunk;

              if (!to[i]->closed)
                peer_recv (to[i], t.p + off, k);
              off += k;
              moved = 1;
            }
          free (t.p);
        }
      if (!moved)
        break;
    }
}

static void
make_client (struct peer *p, enum kind k, unsigned auto_versions)
{
  gq_tls_config cfg = client_cfg ();

  peer_init (p, k);
  switch (k)
    {
    case K13:
      CHECK_EQ (gq_tlsconn_client_new (&p->c13, &cfg, &p->ev), GQ_OK);
      CHECK_EQ (gq_tlsconn_start (p->c13), GQ_OK);
      break;
    case K12:
      CHECK_EQ (gq_tls12conn_client_new (&p->c12, &cfg, &p->ev), GQ_OK);
      CHECK_EQ (gq_tls12conn_start (p->c12), GQ_OK);
      break;
    default:
      CHECK_EQ (gq_tlsauto_client_new (&p->ca, &cfg, &p->ev, auto_versions),
                GQ_OK);
      CHECK_EQ (gq_tlsauto_start (p->ca), GQ_OK);
      break;
    }
}

static void
make_auto_server (struct peer *p, unsigned versions)
{
  gq_tls_server_config cfg = server_cfg ();

  peer_init (p, KAUTO);
  CHECK_EQ (gq_tlsauto_server_new (&p->ca, &cfg, &p->ev, versions), GQ_OK);
}

/* The ServerHello random, from the first record a server wrote.  */
static int
sentinel_in (const struct bytes *out)
{
  static const uint8_t s[8] = { 'D', 'O', 'W', 'N', 'G', 'R', 'D', 1 };

  /* Record header 5, handshake header 4, version 2, then the random.  */
  return out->n >= 11 + 32 && out->p[0] == 22 && out->p[5] == 2
         && memcmp (out->p + 11 + 24, s, 8) == 0;
}

static void
one_run (enum kind client, unsigned client_versions, unsigned server_versions,
         size_t chunk, unsigned want_version)
{
  struct peer c, s;
  static const uint8_t hello[] = "hello, server";
  struct bytes first_server = { NULL, 0, 0 };

  make_client (&c, client, client_versions);
  make_auto_server (&s, server_versions);
  /* Feed the first flight by hand so the ServerHello can be inspected.  */
  {
    struct bytes t = c.out;
    size_t off = 0;

    c.out.p = NULL;
    c.out.n = c.out.cap = 0;
    while (off < t.n)
      {
        size_t k = t.n - off < chunk ? t.n - off : chunk;

        peer_recv (&s, t.p + off, k);
        off += k;
      }
    free (t.p);
    if (s.out.n)
      bytes_add (&first_server, s.out.p, s.out.n);
  }
  pump (&c, &s, chunk);
  if (first_server.n && !s.out.n)
    ;
  if (want_version == 0)
    {
      CHECK (c.closed && s.closed);
      CHECK (!c.connected && !s.connected);
    }
  else
    {
      static const uint8_t reply[] = "hello, client";

      CHECK (c.connected && s.connected);
      CHECK_EQ (gq_tlsauto_version (s.ca), want_version);
      CHECK_EQ (peer_send (&c, hello, sizeof hello), GQ_OK);
      CHECK_EQ (peer_send (&s, reply, sizeof reply), GQ_OK);
      pump (&c, &s, chunk);
      CHECK (s.app.n == sizeof hello && !memcmp (s.app.p, hello, sizeof hello));
      CHECK (c.app.n == sizeof reply && !memcmp (c.app.p, reply, sizeof reply));
      /* The sentinel is there exactly when a TLS 1.2 client was served by
         an endpoint that also speaks TLS 1.3.  */
      CHECK_EQ (sentinel_in (&first_server),
                want_version == 0x0303 && (server_versions == 0
                                           || (server_versions & 2)));
    }
  free (first_server.p);
  peer_free (&c);
  peer_free (&s);
}

enum srvkind { S_AUTO, S_AUTO12, S_AUTO13, S_BARE13, S_BARE12, S_BARE12_SENTINEL };

static void
make_server (struct peer *p, enum srvkind k)
{
  gq_tls_server_config cfg = server_cfg ();

  switch (k)
    {
    case S_AUTO: make_auto_server (p, 0); break;
    case S_AUTO12: make_auto_server (p, GQ_TLSAUTO_TLS12); break;
    case S_AUTO13: make_auto_server (p, GQ_TLSAUTO_TLS13); break;
    case S_BARE13:
      peer_init (p, K13);
      CHECK_EQ (gq_tlsconn_server_new (&p->c13, &cfg, &p->ev), GQ_OK);
      break;
    default:
      peer_init (p, K12);
      cfg.tls13_sentinel = k == S_BARE12_SENTINEL;
      CHECK_EQ (gq_tls12conn_server_new (&p->c12, &cfg, &p->ev), GQ_OK);
      break;
    }
}

/* A negotiating client (offering CLIENT_VERSIONS) against each kind of
   server: WANT is the version it should end up with, 0 for a refusal.  */
static void
client_run (unsigned client_versions, enum srvkind sk, size_t chunk,
            unsigned want)
{
  struct peer c, s;
  static const uint8_t hello[] = "hello, server";

  make_client (&c, KAUTO, client_versions);
  make_server (&s, sk);
  pump (&c, &s, chunk);
  if (want == 0)
    {
      CHECK (!c.connected && !s.connected);
      CHECK (c.closed || s.closed);
    }
  else
    {
      CHECK (c.connected && s.connected);
      CHECK_EQ (gq_tlsauto_version (c.ca), want);
      CHECK_EQ (peer_send (&c, hello, sizeof hello), GQ_OK);
      pump (&c, &s, chunk);
      CHECK (s.app.n == sizeof hello && !memcmp (s.app.p, hello, sizeof hello));
    }
  peer_free (&c);
  peer_free (&s);
}

static void
test_client (void)
{
  size_t chunks[] = { 1, 5, 100, 100000 };
  size_t i;

  for (i = 0; i < sizeof chunks / sizeof chunks[0]; i++)
    {
      size_t k = chunks[i];

      /* Both offered: whatever the server speaks.  */
      client_run (0, S_AUTO, k, 0x0304);
      client_run (0, S_AUTO13, k, 0x0304);
      client_run (0, S_BARE13, k, 0x0304);
      client_run (0, S_AUTO12, k, 0x0303);
      client_run (0, S_BARE12, k, 0x0303);
      /* Pinned clients get their version or nothing.  */
      client_run (GQ_TLSAUTO_TLS13, S_AUTO, k, 0x0304);
      client_run (GQ_TLSAUTO_TLS12, S_AUTO, k, 0x0303);
      client_run (GQ_TLSAUTO_TLS13, S_BARE12, k, 0);
      client_run (GQ_TLSAUTO_TLS12, S_BARE13, k, 0);
      /* A server that could speak TLS 1.3 but answers in 1.2 to a client that
         offered 1.3 has been pushed down: the client walks away.  */
      client_run (0, S_BARE12_SENTINEL, k, 0);
      /* ...but a client that never offered TLS 1.3 does not look.  */
      client_run (GQ_TLSAUTO_TLS12, S_BARE12_SENTINEL, k, 0x0303);
    }
}

static void
test_versions (void)
{
  size_t chunks[] = { 1, 3, 7, 100, 100000 };
  size_t i;

  for (i = 0; i < sizeof chunks / sizeof chunks[0]; i++)
    {
      /* Both served from one listener.  */
      one_run (K13, 0, 0, chunks[i], 0x0304);
      one_run (K12, 0, 0, chunks[i], 0x0303);
      /* Restricted listeners serve their own and refuse the other.  */
      one_run (K13, 0, GQ_TLSAUTO_TLS13, chunks[i], 0x0304);
      one_run (K12, 0, GQ_TLSAUTO_TLS12, chunks[i], 0x0303);
      one_run (K12, 0, GQ_TLSAUTO_TLS13, chunks[i], 0);
      one_run (K13, 0, GQ_TLSAUTO_TLS12, chunks[i], 0);
    }
}

/* A ClientHello cut into several records, at every point.  */
static void
test_fragmented_hello (void)
{
  struct peer c;
  size_t cut;

  make_client (&c, K13, 0);
  {
    /* The first record: 5 byte header and the handshake message.  */
    size_t len = (size_t) (c.out.p[3] << 8 | c.out.p[4]);
    uint8_t *hs = malloc (len);

    memcpy (hs, c.out.p + 5, len);
    for (cut = 1; cut < len; cut += 97)
      {
        struct peer s;
        uint8_t rec[2][70000];
        size_t l0 = cut, l1 = len - cut;

        rec[0][0] = 22; rec[0][1] = 3; rec[0][2] = 1;
        rec[0][3] = (uint8_t) (l0 >> 8); rec[0][4] = (uint8_t) l0;
        memcpy (rec[0] + 5, hs, l0);
        rec[1][0] = 22; rec[1][1] = 3; rec[1][2] = 3;
        rec[1][3] = (uint8_t) (l1 >> 8); rec[1][4] = (uint8_t) l1;
        memcpy (rec[1] + 5, hs + l0, l1);
        make_auto_server (&s, 0);
        peer_recv (&s, rec[0], 5 + l0);
        CHECK (s.out.n == 0);			/* Waiting for the rest.  */
        peer_recv (&s, rec[1], 5 + l1);
        CHECK (s.out.n > 0);			/* Answered.  */
        CHECK_EQ (gq_tlsauto_version (s.ca), 0x0304);
        peer_free (&s);
      }
    free (hs);
  }
  peer_free (&c);
}

/* Junk of every kind is refused without harm, and a first flight that never
   completes is bounded.  */
static void
test_garbage (void)
{
  struct peer s;
  uint8_t junk[80000];
  size_t i, n;

  for (n = 0; n < 40; n++)
    {
      make_auto_server (&s, 0);
      for (i = 0; i < sizeof junk; i++)
        junk[i] = (uint8_t) (i * 31 + n);
      junk[0] = n & 1 ? 22 : (uint8_t) n;
      junk[1] = 3;
      if (n % 4 == 0)
        {
          junk[3] = 0x10;			/* A long record, never done.  */
          junk[4] = 0;
        }
      peer_recv (&s, junk, n < 20 ? 200 + n : sizeof junk);
      peer_recv (&s, junk, 5);
      peer_free (&s);
    }
  /* A record of type 22 that starts a huge handshake message.  */
  make_auto_server (&s, 0);
  {
    static const uint8_t big[] = { 22, 3, 3, 0, 8, 1, 0xff, 0xff, 0xff, 0, 0, 0,
                                   0 };

    peer_recv (&s, big, sizeof big);
    CHECK (gq_tlsauto_version (s.ca) != 0);
  }
  peer_free (&s);
}

int
main (void)
{
  gq_crypto_init ();
  fx_setup ();
  test_versions ();
  test_client ();
  test_fragmented_hello ();
  test_garbage ();
  TST_DONE ();
}

#endif
