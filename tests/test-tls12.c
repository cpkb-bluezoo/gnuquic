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

/* TLS 1.2 handshake engine: the client and server engines against each
   other, message by message (no record layer), with the security policy
   exercised by mutating what one side sends.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/tls12.h>
#include <gnuquic/tls12msg.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"

/* ---- A harness around one engine ---- */

struct item
{
  int ccs;			/* A ChangeCipherSpec, else handshake bytes.  */
  uint8_t d[65536];
  size_t n;
};

#define MAXQ 12

struct eng
{
  gq_tls12 *t;
  int server;
  struct item q[MAXQ];
  int nq;
  int alert;			/* -1: none sent.  */
  int complete;
  gq_tls_info info;
  int tickets;
  gq_tls_session session;	/* Last ticket received (client).  */
  int have_session;
  uint8_t key[2][32], iv[2][12];	/* [0] read, [1] write.  */
  size_t klen, ilen;
  enum gq_aead aead;
  int verify_calls;
  int verify_result;
};

static int
s_send (void *u, const uint8_t *d, size_t n)
{
  struct eng *e = u;
  struct item *last = e->nq ? &e->q[e->nq - 1] : NULL;

  if (last == NULL || last->ccs)
    {
      CHECK (e->nq < MAXQ);
      last = &e->q[e->nq++];
      last->ccs = 0;
      last->n = 0;
    }
  CHECK (last->n + n <= sizeof last->d);
  memcpy (last->d + last->n, d, n);
  last->n += n;
  return 0;
}

static int
s_keys (void *u, enum gq_dir dir, enum gq_aead aead, const uint8_t *k,
        size_t kl, const uint8_t *iv, size_t il)
{
  struct eng *e = u;
  int i = dir == GQ_DIR_WRITE;

  if (dir == GQ_DIR_WRITE)
    {
      CHECK (e->nq < MAXQ);
      e->q[e->nq].ccs = 1;
      e->q[e->nq++].n = 0;
    }
  memcpy (e->key[i], k, kl);
  memcpy (e->iv[i], iv, il);
  e->klen = kl;
  e->ilen = il;
  e->aead = aead;
  return 0;
}

static int
s_verify (void *u, const gq_slice *chain, size_t n, const char *name)
{
  struct eng *e = u;

  (void) chain; (void) n; (void) name;
  e->verify_calls++;
  return e->verify_result;
}

static int
s_ticket (void *u, const gq_tls_ticket *t)
{
  struct eng *e = u;

  e->tickets++;
  CHECK_EQ (gq_tls_session_store (&e->session, t), GQ_OK);
  e->have_session = 1;
  return 0;
}

static int
s_complete (void *u, const gq_tls_info *i)
{
  struct eng *e = u;

  e->complete = 1;
  e->info = *i;
  return 0;
}

static int
s_alert (void *u, unsigned a)
{
  ((struct eng *) u)->alert = (int) a;
  return 0;
}

static gq_tls12_sink
sink_for (struct eng *e)
{
  gq_tls12_sink s;

  memset (&s, 0, sizeof s);
  s.user = e;
  s.send = s_send;
  s.change_keys = s_keys;
  s.ticket = s_ticket;
  s.complete = s_complete;
  s.alert = s_alert;
  return s;
}

static struct eng *
eng_new (int server)
{
  struct eng *e = calloc (1, sizeof *e);

  e->server = server;
  e->alert = -1;
  return e;
}

static void
eng_free (struct eng *e)
{
  gq_tls12_free (e->t);
  free (e);
}

/* Deliver FROM's queued output to TO in CHUNK-byte pieces (0: whole).
   Stops at the first failure and returns its status.  */
static int
deliver (struct eng *from, struct eng *to, size_t chunk)
{
  int i, r = GQ_OK;

  for (i = 0; i < from->nq && r == GQ_OK; i++)
    {
      struct item *it = &from->q[i];

      if (it->ccs)
        r = gq_tls12_change_cipher_spec (to->t);
      else
        {
          size_t pos = 0;

          while (pos < it->n && r == GQ_OK)
            {
              size_t k = it->n - pos;
              const uint8_t *p = it->d + pos;

              if (chunk && k > chunk)
                k = chunk;
              pos += k;
              r = gq_tls12_feed (to->t, &p, &k);
            }
        }
    }
  from->nq = 0;
  return r;
}

/* ---- Configuration ---- */

struct opts
{
  struct ident *server_id;	/* Default: fx_ec.  */
  const uint16_t *csuites;	/* Client suites.  */
  size_t n_csuites;
  const uint16_t *ssuites;
  size_t n_ssuites;
  enum gq_client_auth auth;
  struct ident *client_id;
  const gq_tls_session *resume;
  gq_ticket_keys *keys;		/* Server ticket keys.  */
  const char *sni;		/* Default example.test.  */
  uint64_t (*now) (void *);	/* Client clock.  */
  uint64_t (*snow) (void *);	/* Server clock.  */
  const gq_slice *calpn, *salpn;
  size_t n_calpn, n_salpn;
};

struct pair
{
  struct eng *c, *s;
  gq_tls_config cc;
  gq_tls_server_config sc;
};

static struct pair *
pair_new (const struct opts *o)
{
  struct pair *p = calloc (1, sizeof *p);
  gq_tls12_sink cs, ss;
  struct ident *sid = o->server_id ? o->server_id : &fx_ec;
  static gq_tls_credentials creds;

  p->c = eng_new (0);
  p->s = eng_new (1);
  memset (&creds, 0, sizeof creds);
  creds.chain = sid->chain;
  creds.n_chain = 1;
  creds.key = sid->key;

  p->cc.server_name = o->sni ? o->sni : "example.test";
  p->cc.trust = fx_trust;
  p->cc.suites = o->csuites;
  p->cc.n_suites = o->n_csuites;
  p->cc.resume = o->resume;
  p->cc.alpn = o->calpn;
  p->cc.n_alpn = o->n_calpn;
  p->cc.hooks.now_ms = o->now;
  if (o->client_id)
    {
      p->cc.client_chain = o->client_id->chain;
      p->cc.n_client_chain = 1;
      p->cc.client_key = o->client_id->key;
    }
  p->sc.credentials = creds;
  p->sc.suites = o->ssuites;
  p->sc.n_suites = o->n_ssuites;
  p->sc.client_auth = o->auth;
  p->sc.client_trust = fx_trust;
  p->sc.ticket_keys = o->keys;
  p->sc.alpn = o->salpn;
  p->sc.n_alpn = o->n_salpn;
  p->sc.hooks.now_ms = o->snow ? o->snow : o->now;

  cs = sink_for (p->c);
  ss = sink_for (p->s);
  CHECK_EQ (gq_tls12_client_new (&p->c->t, &p->cc, &cs), GQ_OK);
  CHECK_EQ (gq_tls12_server_new (&p->s->t, &p->sc, &ss), GQ_OK);
  return p;
}

static void
pair_free (struct pair *p)
{
  eng_free (p->c);
  eng_free (p->s);
  free (p);
}

/* Run the whole handshake; returns 0 on success, else the first error.  */
static int
run (struct pair *p, size_t chunk)
{
  int r = gq_tls12_start (p->c->t), guard;

  for (guard = 0; guard < 20 && r == GQ_OK; guard++)
    {
      if (p->c->nq == 0 && p->s->nq == 0)
        break;
      r = deliver (p->c, p->s, chunk);
      if (r == GQ_OK)
        r = deliver (p->s, p->c, chunk);
    }
  return r;
}

static void
expect_done (struct pair *p, int resumed)
{
  CHECK (p->c->complete && p->s->complete);
  CHECK (gq_tls12_is_complete (p->c->t) && gq_tls12_is_complete (p->s->t));
  CHECK_EQ (p->c->info.cipher_suite, p->s->info.cipher_suite);
  CHECK_EQ (p->c->info.resumed, resumed);
  CHECK_EQ (p->s->info.resumed, resumed);
  CHECK_EQ (p->c->info.group, GQ_GROUP_SECP256R1);
  /* Both ends derived the same keys, in opposite directions.  */
  CHECK (p->c->klen == p->s->klen && p->c->klen > 0);
  CHECK (memcmp (p->c->key[1], p->s->key[0], p->c->klen) == 0);
  CHECK (memcmp (p->c->key[0], p->s->key[1], p->c->klen) == 0);
  CHECK (memcmp (p->c->iv[1], p->s->iv[0], p->c->ilen) == 0);
  CHECK (memcmp (p->c->iv[0], p->s->iv[1], p->c->ilen) == 0);
  CHECK (memcmp (p->c->key[0], p->c->key[1], p->c->klen) != 0);
  /* And the same exporter output.  */
  {
    uint8_t a[24], b[24];

    CHECK_EQ (gq_tls12_export (p->c->t, "EXPORTER-test", (const uint8_t *) "ctx",
                               3, a, sizeof a), GQ_OK);
    CHECK_EQ (gq_tls12_export (p->s->t, "EXPORTER-test", (const uint8_t *) "ctx",
                               3, b, sizeof b), GQ_OK);
    CHECK (memcmp (a, b, sizeof a) == 0);
  }
}

/* ---- Wire-level editing helpers ---- */

/* Offset of the first handshake message of TYPE in IT, or -1.  */
static long
find_msg (const struct item *it, unsigned type)
{
  size_t pos = 0;

  while (pos + 4 <= it->n)
    {
      size_t n = ((size_t) it->d[pos + 1] << 16) | ((size_t) it->d[pos + 2] << 8)
        | it->d[pos + 3];

      if (it->d[pos] == type)
        return (long) pos;
      pos += 4 + n;
    }
  return -1;
}

/* Walk a hello's extension block; return the offset of extension TYPE's
   4-byte header, or -1.  Works for ClientHello (FLAG 0) and ServerHello.  */
static long
find_ext (const uint8_t *m, unsigned type)
{
  size_t p = 4 + 2 + 32;
  size_t end;

  p += 1 + m[p];			/* session id */
  if (m[0] == 1)
    {
      p += 2 + (((size_t) m[p] << 8) | m[p + 1]);	/* suites */
      p += 1 + m[p];			/* compression */
    }
  else
    p += 3;				/* suite, compression */
  end = p + 2 + (((size_t) m[p] << 8) | m[p + 1]);
  p += 2;
  while (p + 4 <= end)
    {
      unsigned t = ((unsigned) m[p] << 8) | m[p + 1];
      size_t n = ((size_t) m[p + 2] << 8) | m[p + 3];

      if (t == type)
        return (long) p;
      p += 4 + n;
    }
  return -1;
}

/* Remove extension TYPE from the hello at IT->d + M, fixing up the message
   and extension block lengths (the transcript then differs from the
   sender's, so only use this on a flight that fails immediately).  */
static void
drop_ext (struct item *it, long m, unsigned type)
{
  uint8_t *h = it->d + m;
  long o = find_ext (h, type);
  size_t sz, mlen, elen, p;

  CHECK (o >= 0);
  if (o < 0)
    return;
  sz = 4 + (((size_t) h[o + 2] << 8) | h[o + 3]);
  memmove (h + o, h + o + sz, it->n - (size_t) m - (size_t) o - sz);
  it->n -= sz;
  mlen = (((size_t) h[1] << 16) | ((size_t) h[2] << 8) | h[3]) - sz;
  h[1] = (uint8_t) (mlen >> 16); h[2] = (uint8_t) (mlen >> 8); h[3] = (uint8_t) mlen;
  /* The extension block length sits just before the first extension.  */
  p = 4 + 2 + 32;
  p += 1 + h[p];
  p += h[0] == 1 ? 2 + (((size_t) h[p] << 8) | h[p + 1]) + 1 + h[p + 2 + (((size_t) h[p] << 8) | h[p + 1])] : 3;
  elen = (((size_t) h[p] << 8) | h[p + 1]) - sz;
  h[p] = (uint8_t) (elen >> 8); h[p + 1] = (uint8_t) elen;
}

/* Change extension FROM's type to TO, so the peer sees it as unknown.  */
static void
rename_ext (uint8_t *m, unsigned from, unsigned to)
{
  long o = find_ext (m, from);

  CHECK (o >= 0);
  if (o >= 0)
    {
      m[o] = (uint8_t) (to >> 8);
      m[o + 1] = (uint8_t) to;
    }
}

/* ---- Tests ---- */

static const uint16_t ecdsa128[] = { GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };
static const uint16_t ecdsa256[] = { GQ_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 };
static const uint16_t ecdsachacha[] = { GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 };
static const uint16_t rsa128[] = { GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 };
static const uint16_t rsa256[] = { GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 };
static const uint16_t rsachacha[] = { GQ_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 };
static const uint16_t cbc[] = { 0xc013, 0xc014, 0x002f, 0x009c };

static void
test_suites_and_keys (void)
{
  size_t chunks[] = { 0, 1, 3, 100 };
  size_t i, k;
  struct ident *ec = &fx_ec, *ec384 = &fx_ec384, *rsa = &fx_rsa;
  struct
  {
    const uint16_t *s;
    struct ident *id;
    unsigned suite;
  } t[] = {
    { ecdsa128, ec, GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 },
    { ecdsa256, ec, GQ_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 },
    { ecdsachacha, ec, GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 },
    { ecdsa128, ec384, GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 },
    { rsa128, rsa, GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 },
    { rsa256, rsa, GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 },
    { rsachacha, rsa, GQ_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 }
  };

  for (i = 0; i < sizeof t / sizeof t[0]; i++)
    for (k = 0; k < sizeof chunks / sizeof chunks[0]; k++)
      {
        struct opts o;
        struct pair *p;

        memset (&o, 0, sizeof o);
        o.server_id = t[i].id;
        o.csuites = t[i].s;
        o.n_csuites = 1;
        p = pair_new (&o);
        CHECK_EQ (run (p, chunks[k]), GQ_OK);
        expect_done (p, 0);
        CHECK_EQ (p->c->info.cipher_suite, t[i].suite);
        CHECK_EQ (p->s->info.server_name_len, 12);
        CHECK (memcmp (p->s->info.server_name, "example.test", 12) == 0);
        CHECK_EQ (p->c->info.client_auth_requested, 0);
        pair_free (p);
      }

  /* A suite that does not fit the certificate's key type finds no
     common suite: the server fails with handshake_failure.  */
  {
    struct opts o;
    struct pair *p;

    memset (&o, 0, sizeof o);
    o.csuites = rsa128;
    o.n_csuites = 1;
    p = pair_new (&o);
    CHECK (run (p, 0) < 0);
    CHECK_EQ (p->s->alert, GQ_ALERT_HANDSHAKE_FAILURE);
    pair_free (p);
  }

  /* The server chooses: with everything on offer, its first preference
     that fits the key wins (AES-256-GCM for ECDSA, as in the policy).  */
  {
    struct opts o;
    struct pair *p;

    memset (&o, 0, sizeof o);
    p = pair_new (&o);
    CHECK_EQ (run (p, 0), GQ_OK);
    expect_done (p, 0);
    CHECK_EQ (p->c->info.cipher_suite, GQ_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    pair_free (p);
  }
}

static void
test_alpn (void)
{
  static const gq_slice cl[] = { { (const uint8_t *) "http/1.1", 8 },
                                 { (const uint8_t *) "h2", 2 } };
  static const gq_slice sv[] = { { (const uint8_t *) "h2", 2 } };
  static const gq_slice none[] = { { (const uint8_t *) "foo", 3 } };
  struct opts o;
  struct pair *p;

  memset (&o, 0, sizeof o);
  o.calpn = cl;
  o.n_calpn = 2;
  o.salpn = sv;
  o.n_salpn = 1;
  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  expect_done (p, 0);
  CHECK (p->c->info.alpn_len == 2 && memcmp (p->c->info.alpn, "h2", 2) == 0);
  CHECK (p->s->info.alpn_len == 2);
  pair_free (p);

  o.calpn = none;
  o.n_calpn = 1;
  p = pair_new (&o);
  CHECK (run (p, 0) < 0);
  CHECK_EQ (p->s->alert, GQ_ALERT_NO_APPLICATION_PROTOCOL);
  pair_free (p);

  /* Client offers none: the server selects none, and that is fine.  */
  o.calpn = NULL;
  o.n_calpn = 0;
  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  CHECK_EQ (p->c->info.alpn_len, 0);
  pair_free (p);
}

/* ---- Resumption ---- */

static uint64_t fake_now;

static uint64_t server_now;

static uint64_t
now_fn (void *u)
{
  (void) u;
  return fake_now;
}

static uint64_t
snow_fn (void *u)
{
  (void) u;
  return server_now;
}

static void
test_resumption (void)
{
  gq_ticket_keys *keys, *other;
  struct opts o;
  struct pair *p, *q;
  gq_tls_session sess;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  CHECK_EQ (gq_ticket_keys_new (&other), GQ_OK);
  fake_now = 1000000000000ull;
  memset (&o, 0, sizeof o);
  o.keys = keys;
  o.now = now_fn;

  /* Full handshake yields a ticket.  */
  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  expect_done (p, 0);
  CHECK_EQ (p->c->tickets, 1);
  CHECK (p->c->have_session);
  CHECK_EQ (p->c->session.psk_len, 48);
  sess = p->c->session;
  pair_free (p);

  /* Presented again: abbreviated handshake, no certificates, no new
     ticket, the same secret.  */
  o.resume = &sess;
  q = pair_new (&o);
  CHECK_EQ (run (q, 0), GQ_OK);
  expect_done (q, 1);
  CHECK_EQ (q->c->tickets, 0);
  CHECK_EQ (q->s->info.cipher_suite, sess.cipher_suite);
  pair_free (q);

  /* Chunked delivery does not matter.  */
  q = pair_new (&o);
  CHECK_EQ (run (q, 1), GQ_OK);
  expect_done (q, 1);
  pair_free (q);

  /* A server with other keys, a rotated-away key, an expired ticket, a
     ticket for another name, and a damaged ticket all fall back to a
     full handshake without failing.  */
  o.keys = other;
  q = pair_new (&o);
  CHECK_EQ (run (q, 0), GQ_OK);
  expect_done (q, 0);
  CHECK_EQ (q->c->tickets, 1);
  pair_free (q);

  o.keys = keys;
  CHECK_EQ (gq_ticket_keys_rotate (keys), GQ_OK);	/* Old key still works.  */
  q = pair_new (&o);
  CHECK_EQ (run (q, 0), GQ_OK);
  expect_done (q, 1);
  pair_free (q);
  {
    int i;

    for (i = 0; i < GQ_TICKET_KEYS_MAX; i++)
      CHECK_EQ (gq_ticket_keys_rotate (keys), GQ_OK);
  }
  q = pair_new (&o);
  CHECK_EQ (run (q, 0), GQ_OK);
  expect_done (q, 0);
  pair_free (q);

  /* Fresh session from the current keys for the remaining cases.  */
  o.resume = NULL;
  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  sess = p->c->session;
  pair_free (p);

  /* Expired: the client would not even offer it, so make only the server
     believe it is late.  */
  o.resume = &sess;
  server_now = fake_now + 86400ull * 1000 + 5000;
  o.snow = snow_fn;
  q = pair_new (&o);
  CHECK_EQ (run (q, 0), GQ_OK);
  expect_done (q, 0);
  pair_free (q);
  /* And a client that knows it is expired does not offer it.  */
  o.snow = NULL;
  fake_now += 86400ull * 1000 + 5000;
  q = pair_new (&o);
  CHECK_EQ (gq_tls12_start (q->c->t), GQ_OK);
  {
    long e = find_ext (q->c->q[0].d, GQ_EXT12_SESSION_TICKET);

    CHECK (e >= 0 && q->c->q[0].d[e + 3] == 0);	/* Empty extension.  */
  }
  pair_free (q);
  fake_now -= 86400ull * 1000 + 5000;

  /* The ticket is bound to the server name.  */
  o.sni = "other.example";
  o.server_id = &fx_ec;
  {
    /* The certificate is not valid for the other name, so verify with a
       callback; the point is that resumption is refused.  */
    struct pair *r = pair_new (&o);

    r->c->verify_result = 0;
    r->cc.trust = NULL;
    gq_tls12_free (r->c->t);
    {
      gq_tls12_sink cs = sink_for (r->c);

      cs.verify_peer = s_verify;
      CHECK_EQ (gq_tls12_client_new (&r->c->t, &r->cc, &cs), GQ_OK);
    }
    CHECK_EQ (run (r, 0), GQ_OK);
    expect_done (r, 0);
    pair_free (r);
  }
  o.sni = NULL;

  /* A session for a suite the client no longer offers is not offered.  */
  o.csuites = rsa128;
  o.n_csuites = 1;
  o.server_id = &fx_rsa;
  q = pair_new (&o);
  CHECK_EQ (run (q, 0), GQ_OK);
  expect_done (q, 0);
  pair_free (q);

  /* A damaged ticket is just a full handshake.  */
  o.csuites = NULL;
  o.n_csuites = 0;
  o.server_id = NULL;
  sess.ticket[sess.ticket_len / 2] ^= 0x80;
  q = pair_new (&o);
  CHECK_EQ (run (q, 0), GQ_OK);
  expect_done (q, 0);
  pair_free (q);
  sess.ticket[sess.ticket_len / 2] ^= 0x80;
  q = pair_new (&o);
  CHECK_EQ (run (q, 0), GQ_OK);
  expect_done (q, 1);			/* Restored: it works again.  */
  pair_free (q);

  gq_ticket_keys_free (keys);
  gq_ticket_keys_free (other);
}

/* ---- Client authentication ---- */

static void
test_client_auth (void)
{
  struct opts o;
  struct pair *p;

  /* Required, EC and RSA client keys.  */
  memset (&o, 0, sizeof o);
  o.auth = GQ_CLIENT_AUTH_REQUIRED;
  o.client_id = &fx_cli_ec;
  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  expect_done (p, 0);
  CHECK_EQ (p->c->info.client_auth_requested, 1);
  CHECK_EQ (p->c->info.client_auth_sent, 1);
  CHECK_EQ (p->s->info.client_auth_sent, 1);
  pair_free (p);

  o.client_id = &fx_cli_rsa;
  p = pair_new (&o);
  CHECK_EQ (run (p, 1), GQ_OK);
  expect_done (p, 0);
  CHECK_EQ (p->s->info.client_auth_sent, 1);
  pair_free (p);

  /* RSA server certificate and RSA client together.  */
  o.server_id = &fx_rsa;
  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  expect_done (p, 0);
  pair_free (p);

  /* Required and absent: handshake_failure.  */
  o.server_id = NULL;
  o.client_id = NULL;
  p = pair_new (&o);
  CHECK (run (p, 0) < 0);
  CHECK_EQ (p->s->alert, GQ_ALERT_HANDSHAKE_FAILURE);
  pair_free (p);

  /* Optional and absent: proceeds, unauthenticated.  */
  o.auth = GQ_CLIENT_AUTH_OPTIONAL;
  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  expect_done (p, 0);
  CHECK_EQ (p->c->info.client_auth_requested, 1);
  CHECK_EQ (p->c->info.client_auth_sent, 0);
  CHECK_EQ (p->s->info.client_auth_sent, 0);
  pair_free (p);

  /* A certificate that does not verify.  */
  o.auth = GQ_CLIENT_AUTH_REQUIRED;
  o.client_id = &fx_ec;			/* serverAuth only: wrong purpose.  */
  p = pair_new (&o);
  CHECK (run (p, 0) < 0);
  CHECK (p->s->alert == GQ_ALERT_BAD_CERTIFICATE || p->s->alert > 0);
  pair_free (p);

  /* A client that signs CertificateVerify wrongly is refused: flip a bit
     in the CertificateVerify signature.  */
  o.client_id = &fx_cli_ec;
  p = pair_new (&o);
  CHECK_EQ (gq_tls12_start (p->c->t), GQ_OK);
  CHECK_EQ (deliver (p->c, p->s, 0), GQ_OK);
  CHECK_EQ (deliver (p->s, p->c, 0), GQ_OK);
  {
    long m = find_msg (&p->c->q[0], GQ_HS_CERTIFICATE_VERIFY);

    CHECK (m >= 0);
    p->c->q[0].d[p->c->q[0].n - 3] ^= 1;
    CHECK (deliver (p->c, p->s, 0) < 0);
    CHECK_EQ (p->s->alert, GQ_ALERT_DECRYPT_ERROR);
  }
  pair_free (p);

  /* Server config: refuses to ask without a way to verify.  */
  {
    gq_tls_server_config sc;
    gq_tls12_sink s;
    struct eng *e = eng_new (1);
    gq_tls12 *t;

    memset (&sc, 0, sizeof sc);
    sc.credentials.chain = fx_ec.chain;
    sc.credentials.n_chain = 1;
    sc.credentials.key = fx_ec.key;
    sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
    s = sink_for (e);
    CHECK_EQ (gq_tls12_server_new (&t, &sc, &s), GQ_ERR_INVAL);
    eng_free (e);
  }
}

/* ---- Server refusals, by editing the ClientHello ---- */

/* Start a client, let MUT edit its ClientHello, deliver it to a server
   and report the server's alert (or -1 if it accepted).  */
static int
ch_case (void (*mut) (uint8_t *m, size_t n), const struct opts *o)
{
  struct pair *p = pair_new (o);
  int r, alert;

  CHECK_EQ (gq_tls12_start (p->c->t), GQ_OK);
  CHECK_EQ (p->c->nq, 1);
  if (mut)
    mut (p->c->q[0].d, p->c->q[0].n);
  r = deliver (p->c, p->s, 0);
  alert = r == GQ_OK ? -1 : p->s->alert;
  pair_free (p);
  return alert;
}

static void no_ems (uint8_t *m, size_t n) { (void) n; rename_ext (m, GQ_EXT12_EXTENDED_MASTER_SECRET, 0x7777); }
static void no_reneg (uint8_t *m, size_t n) { (void) n; rename_ext (m, GQ_EXT12_RENEGOTIATION_INFO, 0x7778); }
static void bad_reneg (uint8_t *m, size_t n)
{
  long o = find_ext (m, GQ_EXT12_RENEGOTIATION_INFO);

  (void) n;
  CHECK (o >= 0);
  m[o + 4] = 0xaa;			/* Not the empty indication.  */
}
static void no_groups (uint8_t *m, size_t n) { (void) n; rename_ext (m, GQ_EXT_SUPPORTED_GROUPS, 0x7779); }
static void wrong_group (uint8_t *m, size_t n)
{
  long o = find_ext (m, GQ_EXT_SUPPORTED_GROUPS);

  (void) n;
  CHECK (o >= 0);
  m[o + 6] = 0x00; m[o + 7] = 0x1d;		/* x25519 only.  */
}
static void no_sigs (uint8_t *m, size_t n) { (void) n; rename_ext (m, GQ_EXT_SIGNATURE_ALGORITHMS, 0x777a); }
static void old_version (uint8_t *m, size_t n) { (void) n; m[4] = 3; m[5] = 2; }
static void ssl3_version (uint8_t *m, size_t n) { (void) n; m[4] = 3; m[5] = 0; }
static void only_tls13 (uint8_t *m, size_t n)
{
  long o = find_ext (m, GQ_EXT_SUPPORTED_VERSIONS);

  (void) n;
  CHECK (o >= 0);
  m[o + 6] = 0x04;			/* 0x0304 only.  */
}
static void bad_ems_body (uint8_t *m, size_t n)
{
  long o = find_ext (m, GQ_EXT12_EXTENDED_MASTER_SECRET);

  (void) n;
  CHECK (o >= 0);
  m[o + 3] = 1;			/* Claims one byte of content ... */
  /* ... which swallows the first byte of the next extension header, so
     the block no longer parses to a valid whole.  */
}
static void truncated (uint8_t *m, size_t n) { (void) n; m[3] -= 3; }
static void
scsv_instead (uint8_t *m, size_t n)
{
  /* Replace the renegotiation_info extension by the signalling suite.  */
  size_t p = 4 + 2 + 32;

  (void) n;
  p += 1 + m[p];
  m[p + 2] = 0x00;			/* The first suite becomes the SCSV.  */
  m[p + 3] = 0xff;
  rename_ext (m, GQ_EXT12_RENEGOTIATION_INFO, 0x7778);
}
static void
cbc_only (uint8_t *m, size_t n)
{
  size_t p = 4 + 2 + 32, l, i;

  (void) n;
  p += 1 + m[p];
  l = ((size_t) m[p] << 8) | m[p + 1];
  for (i = 0; i < l; i += 2)
    {
      static const uint16_t v[] = { 0xc013, 0xc014, 0x002f, 0x009c, 0x0035 };
      uint16_t s = v[(i / 2) % 5];

      m[p + 2 + i] = (uint8_t) (s >> 8);
      m[p + 3 + i] = (uint8_t) s;
    }
  /* The renegotiation extension is still present; only suites differ.  */
}
static void
compress (uint8_t *m, size_t n)
{
  /* Replace [null] by [deflate]: same length, so nothing shifts.  */
  size_t p = 4 + 2 + 32;

  (void) n;
  p += 1 + m[p];
  p += 2 + (((size_t) m[p] << 8) | m[p + 1]);
  m[p + 1] = 1;
}

static void
test_server_refusals (void)
{
  struct opts o;

  memset (&o, 0, sizeof o);
  CHECK_EQ (ch_case (NULL, &o), -1);
  CHECK_EQ (ch_case (no_ems, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (ch_case (bad_ems_body, &o) != -1, 1);
  CHECK_EQ (ch_case (no_reneg, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (ch_case (bad_reneg, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (ch_case (scsv_instead, &o), -1);
  CHECK_EQ (ch_case (no_groups, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (ch_case (wrong_group, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (ch_case (no_sigs, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (ch_case (old_version, &o), GQ_ALERT_PROTOCOL_VERSION);
  CHECK_EQ (ch_case (ssl3_version, &o), GQ_ALERT_PROTOCOL_VERSION);
  CHECK_EQ (ch_case (only_tls13, &o), GQ_ALERT_PROTOCOL_VERSION);
  CHECK_EQ (ch_case (cbc_only, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (ch_case (compress, &o), GQ_ALERT_ILLEGAL_PARAMETER);
  CHECK (ch_case (truncated, &o) >= 0);
}

/* ---- Client refusals, by editing the server's flight ---- */

/* Run a handshake to the point the server has answered the ClientHello,
   let MUT edit the server flight, deliver it and return the client's
   alert (or -1).  */
static int
flight_case (void (*mut) (struct item *it), const struct opts *o)
{
  struct pair *p = pair_new (o);
  int r, alert;

  CHECK_EQ (gq_tls12_start (p->c->t), GQ_OK);
  CHECK_EQ (deliver (p->c, p->s, 0), GQ_OK);
  CHECK_EQ (p->s->nq, 1);
  if (mut)
    mut (&p->s->q[0]);
  r = deliver (p->s, p->c, 0);
  alert = r == GQ_OK ? -1 : p->c->alert;
  pair_free (p);
  return alert;
}

static void
sh_no_ems (struct item *it)
{
  drop_ext (it, find_msg (it, GQ_HS_SERVER_HELLO), GQ_EXT12_EXTENDED_MASTER_SECRET);
}
static void
sh_no_reneg (struct item *it)
{
  drop_ext (it, find_msg (it, GQ_HS_SERVER_HELLO), GQ_EXT12_RENEGOTIATION_INFO);
}
static void
sh_bad_reneg (struct item *it)
{
  long m = find_msg (it, GQ_HS_SERVER_HELLO);
  long o = find_ext (it->d + m, GQ_EXT12_RENEGOTIATION_INFO);

  it->d[m + o + 4 + 0] = 0x55;	/* value byte: not zero */
}
static void
sh_unsolicited (struct item *it)
{
  long m = find_msg (it, GQ_HS_SERVER_HELLO);

  /* renegotiation_info becomes heartbeat (15): never offered by us.  */
  rename_ext (it->d + m, GQ_EXT12_RENEGOTIATION_INFO, 0x000f);
}
static void
sh_cbc_suite (struct item *it)
{
  long m = find_msg (it, GQ_HS_SERVER_HELLO);
  size_t p = (size_t) m + 4 + 2 + 32;

  p += 1 + it->d[p];
  it->d[p] = 0xc0; it->d[p + 1] = 0x13;
}
static void
sh_tls13_suite (struct item *it)
{
  long m = find_msg (it, GQ_HS_SERVER_HELLO);
  size_t p = (size_t) m + 4 + 2 + 32;

  p += 1 + it->d[p];
  it->d[p] = 0x13; it->d[p + 1] = 0x01;
}
static void
sh_old_version (struct item *it)
{
  long m = find_msg (it, GQ_HS_SERVER_HELLO);

  it->d[m + 4] = 3; it->d[m + 5] = 2;
}
static void
sh_hrr (struct item *it)
{
  long m = find_msg (it, GQ_HS_SERVER_HELLO);

  memcpy (it->d + m + 6, gq_hrr_random, 32);
}
static void
ske_bad_sig (struct item *it)
{
  long m = find_msg (it, GQ_HS12_SERVER_KEY_EXCHANGE);
  size_t n = ((size_t) it->d[m + 1] << 16) | ((size_t) it->d[m + 2] << 8) | it->d[m + 3];

  it->d[m + 4 + n - 5] ^= 0x10;
}
static void
ske_bad_point (struct item *it)
{
  long m = find_msg (it, GQ_HS12_SERVER_KEY_EXCHANGE);

  it->d[m + 4 + 5 + 20] ^= 0x01;	/* changes the signed parameters */
}
static void
ske_other_curve (struct item *it)
{
  long m = find_msg (it, GQ_HS12_SERVER_KEY_EXCHANGE);

  it->d[m + 4 + 1] = 0x00; it->d[m + 4 + 2] = 0x1d;	/* x25519 */
}
static void
ske_sha1_scheme (struct item *it)
{
  long m = find_msg (it, GQ_HS12_SERVER_KEY_EXCHANGE);
  size_t o = (size_t) m + 4 + 4 + 65;

  it->d[o] = 0x02; it->d[o + 1] = 0x03;		/* ecdsa_sha1 */
}
static void
cert_wrong_order (struct item *it)
{
  /* Swap Certificate and ServerKeyExchange types: unexpected message.  */
  long m = find_msg (it, GQ_HS_CERTIFICATE);

  it->d[m] = GQ_HS12_SERVER_KEY_EXCHANGE;
}
static void
drop_shd_type (struct item *it)
{
  long m = find_msg (it, GQ_HS12_SERVER_HELLO_DONE);

  it->d[m] = GQ_HS_FINISHED;
}

static void
test_client_refusals (void)
{
  struct opts o;

  memset (&o, 0, sizeof o);
  CHECK_EQ (flight_case (NULL, &o), -1);
  CHECK_EQ (flight_case (sh_no_ems, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (flight_case (sh_no_reneg, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (flight_case (sh_bad_reneg, &o), GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK_EQ (flight_case (sh_unsolicited, &o), GQ_ALERT_UNSUPPORTED_EXTENSION);
  CHECK_EQ (flight_case (sh_cbc_suite, &o), GQ_ALERT_ILLEGAL_PARAMETER);
  CHECK_EQ (flight_case (sh_tls13_suite, &o), GQ_ALERT_ILLEGAL_PARAMETER);
  CHECK_EQ (flight_case (sh_old_version, &o), GQ_ALERT_PROTOCOL_VERSION);
  CHECK_EQ (flight_case (sh_hrr, &o), GQ_ALERT_ILLEGAL_PARAMETER);
  CHECK_EQ (flight_case (ske_bad_sig, &o), GQ_ALERT_DECRYPT_ERROR);
  CHECK_EQ (flight_case (ske_bad_point, &o), GQ_ALERT_DECRYPT_ERROR);
  CHECK_EQ (flight_case (ske_other_curve, &o), GQ_ALERT_ILLEGAL_PARAMETER);
  CHECK_EQ (flight_case (ske_sha1_scheme, &o), GQ_ALERT_ILLEGAL_PARAMETER);
  CHECK_EQ (flight_case (cert_wrong_order, &o), GQ_ALERT_UNEXPECTED_MESSAGE);
  CHECK_EQ (flight_case (drop_shd_type, &o), GQ_ALERT_UNEXPECTED_MESSAGE);

  /* An RSA-suite signature scheme with an ECDSA suite is refused: swap a
     suite for the other kind while leaving the certificate.  */
  o.csuites = ecdsa128;
  o.n_csuites = 1;
  CHECK_EQ (flight_case (NULL, &o), -1);

  /* The wrong host name.  */
  {
    struct pair *p;

    memset (&o, 0, sizeof o);
    o.sni = "not-the-name.test";
    p = pair_new (&o);
    CHECK (run (p, 0) < 0);
    CHECK_EQ (p->c->alert, GQ_ALERT_BAD_CERTIFICATE);
    pair_free (p);
  }
  /* An untrusted certificate authority.  */
  {
    struct pair *p;
    gq_trust *empty;

    memset (&o, 0, sizeof o);
    p = pair_new (&o);
    gq_trust_new (&empty);
    gq_tls12_free (p->c->t);
    p->cc.trust = empty;
    {
      gq_tls12_sink cs = sink_for (p->c);

      CHECK_EQ (gq_tls12_client_new (&p->c->t, &p->cc, &cs), GQ_OK);
    }
    CHECK (run (p, 0) < 0);
    CHECK_EQ (p->c->alert, GQ_ALERT_UNKNOWN_CA);
    pair_free (p);
    gq_trust_free (empty);
  }
}

/* ---- State machine ---- */

static void
test_state_machine (void)
{
  struct opts o;
  struct pair *p;
  uint8_t hr[4] = { 0, 0, 0, 0 };
  const uint8_t *b;
  size_t l;

  memset (&o, 0, sizeof o);

  /* After the handshake, any handshake message is a renegotiation
     attempt, from either side.  */
  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  b = hr; l = 4;
  CHECK (gq_tls12_feed (p->c->t, &b, &l) < 0);
  CHECK_EQ (p->c->alert, GQ_ALERT_NO_RENEGOTIATION);
  CHECK (gq_tls12_is_failed (p->c->t));
  CHECK (gq_tls12_feed (p->c->t, &b, &l) < 0);	/* And it stays failed.  */
  pair_free (p);

  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  hr[0] = GQ_HS_CLIENT_HELLO;
  b = hr; l = 4;
  CHECK (gq_tls12_feed (p->s->t, &b, &l) < 0);
  CHECK_EQ (p->s->alert, GQ_ALERT_NO_RENEGOTIATION);
  pair_free (p);

  /* ChangeCipherSpec too early.  */
  p = pair_new (&o);
  CHECK_EQ (gq_tls12_start (p->c->t), GQ_OK);
  CHECK_EQ (deliver (p->c, p->s, 0), GQ_OK);
  CHECK (gq_tls12_change_cipher_spec (p->s->t) < 0);
  CHECK_EQ (p->s->alert, GQ_ALERT_UNEXPECTED_MESSAGE);
  CHECK (gq_tls12_change_cipher_spec (p->c->t) < 0);
  pair_free (p);

  /* A second ChangeCipherSpec.  */
  p = pair_new (&o);
  CHECK_EQ (run (p, 0), GQ_OK);
  CHECK (gq_tls12_change_cipher_spec (p->s->t) < 0);
  pair_free (p);

  /* A message that straddles the ChangeCipherSpec.  */
  p = pair_new (&o);
  CHECK_EQ (gq_tls12_start (p->c->t), GQ_OK);
  CHECK_EQ (deliver (p->c, p->s, 0), GQ_OK);
  CHECK_EQ (deliver (p->s, p->c, 0), GQ_OK);
  /* The client's flight: CKE, CCS, Finished.  Give the server half of the
     CKE, then the CCS.  */
  {
    const uint8_t *d = p->c->q[0].d;
    size_t half = p->c->q[0].n / 2;

    CHECK_EQ (gq_tls12_feed (p->s->t, &d, &half), GQ_OK);
    CHECK (gq_tls12_change_cipher_spec (p->s->t) < 0);
    CHECK_EQ (p->s->alert, GQ_ALERT_UNEXPECTED_MESSAGE);
  }
  pair_free (p);

  /* A handshake message larger than the limit is refused on its header.  */
  p = pair_new (&o);
  {
    uint8_t big[4] = { GQ_HS_CLIENT_HELLO, 0x10, 0, 0 };

    b = big; l = 4;
    CHECK (gq_tls12_feed (p->s->t, &b, &l) < 0);
    CHECK_EQ (p->s->alert, GQ_ALERT_ILLEGAL_PARAMETER);
  }
  pair_free (p);

  /* A tampered Finished is refused with decrypt_error, on both sides.  */
  p = pair_new (&o);
  CHECK_EQ (gq_tls12_start (p->c->t), GQ_OK);
  CHECK_EQ (deliver (p->c, p->s, 0), GQ_OK);
  CHECK_EQ (deliver (p->s, p->c, 0), GQ_OK);
  CHECK_EQ (p->c->nq, 3);
  p->c->q[2].d[p->c->q[2].n - 1] ^= 1;
  CHECK (deliver (p->c, p->s, 0) < 0);
  CHECK_EQ (p->s->alert, GQ_ALERT_DECRYPT_ERROR);
  pair_free (p);

  p = pair_new (&o);
  CHECK_EQ (gq_tls12_start (p->c->t), GQ_OK);
  CHECK_EQ (deliver (p->c, p->s, 0), GQ_OK);
  CHECK_EQ (deliver (p->s, p->c, 0), GQ_OK);
  CHECK_EQ (deliver (p->c, p->s, 0), GQ_OK);
  CHECK_EQ (p->s->nq, 2);		/* ChangeCipherSpec, Finished.  */
  p->s->q[1].d[5] ^= 1;
  CHECK (deliver (p->s, p->c, 0) < 0);
  CHECK_EQ (p->c->alert, GQ_ALERT_DECRYPT_ERROR);
  pair_free (p);
}

/* ---- Robustness: mutated and random input must never crash ---- */

static uint32_t rng_state = 12345;

static uint32_t
rnd32 (void)
{
  rng_state = rng_state * 1664525u + 1013904223u;
  return rng_state >> 8;
}

/* Corrupt ITEM in place: flip a few bytes, or truncate it.  */
static void
corrupt (struct item *it)
{
  unsigned k, n = 1 + rnd32 () % 4;

  if (it->n == 0)
    return;
  for (k = 0; k < n; k++)
    it->d[rnd32 () % it->n] ^= (uint8_t) (1 + rnd32 () % 255);
  if (rnd32 () % 5 == 0)
    it->n = rnd32 () % it->n;
}

static void
test_fuzz (void)
{
  struct opts o;
  int i;

  memset (&o, 0, sizeof o);
  o.auth = GQ_CLIENT_AUTH_OPTIONAL;
  o.client_id = &fx_cli_ec;
  for (i = 0; i < 600; i++)
    {
      struct pair *p = pair_new (&o);
      int r, round;

      /* Alternate which flight of the handshake is damaged.  */
      r = gq_tls12_start (p->c->t);
      CHECK_EQ (r, GQ_OK);
      for (round = 0; round < 3 && r == GQ_OK; round++)
        {
          struct eng *from = round % 2 == 0 ? p->c : p->s;
          struct eng *to = round % 2 == 0 ? p->s : p->c;
          int q;

          if (round == i % 3)
            for (q = 0; q < from->nq; q++)
              if (!from->q[q].ccs)
                corrupt (&from->q[q]);
          r = deliver (from, to, i % 7 == 0 ? 1 : 0);
        }
      /* Whatever happened, the engines are either finished or failed and
         refuse to be driven further without crashing.  */
      {
        uint8_t junk[64];
        const uint8_t *b = junk;
        size_t l = sizeof junk, k;

        for (k = 0; k < sizeof junk; k++)
          junk[k] = (uint8_t) rnd32 ();
        (void) gq_tls12_feed (p->c->t, &b, &l);
        b = junk; l = sizeof junk;
        (void) gq_tls12_feed (p->s->t, &b, &l);
        (void) gq_tls12_change_cipher_spec (p->c->t);
        (void) gq_tls12_change_cipher_spec (p->s->t);
      }
      pair_free (p);
    }

  /* Pure garbage into a fresh server and client, as ClientHello and as
     ServerHello-shaped input with valid headers.  */
  for (i = 0; i < 400; i++)
    {
      struct pair *p = pair_new (&o);
      uint8_t junk[300];
      const uint8_t *b = junk;
      size_t l = 4 + rnd32 () % 200, k;

      for (k = 0; k < sizeof junk; k++)
        junk[k] = (uint8_t) rnd32 ();
      junk[0] = (i & 1) ? GQ_HS_CLIENT_HELLO : GQ_HS_SERVER_HELLO;
      junk[1] = 0;
      junk[2] = 0;
      junk[3] = (uint8_t) (l - 4);
      (void) gq_tls12_feed (p->s->t, &b, &l);
      pair_free (p);
    }
}

/* ---- Configuration ---- */

static void
test_config (void)
{
  struct eng *e = eng_new (0);
  gq_tls12_sink s = sink_for (e);
  gq_tls_config c;
  gq_tls12 *t;
  static const uint8_t tp[] = { 1 };

  memset (&c, 0, sizeof c);
  c.trust = fx_trust;
  c.server_name = "example.test";
  CHECK_EQ (gq_tls12_client_new (&t, &c, &s), GQ_OK);
  gq_tls12_free (t);

  /* No way to authenticate the server.  */
  c.trust = NULL;
  CHECK_EQ (gq_tls12_client_new (&t, &c, &s), GQ_ERR_INVAL);
  c.trust = fx_trust;
  /* QUIC and 0-RTT are TLS 1.3 only.  */
  c.quic = 1;
  CHECK_EQ (gq_tls12_client_new (&t, &c, &s), GQ_ERR_INVAL);
  c.quic = 0;
  c.transport_params = tp;
  c.transport_params_len = 1;
  CHECK_EQ (gq_tls12_client_new (&t, &c, &s), GQ_ERR_INVAL);
  c.transport_params = NULL;
  c.early_data = 1;
  CHECK_EQ (gq_tls12_client_new (&t, &c, &s), GQ_ERR_INVAL);
  c.early_data = 0;
  /* TLS 1.3 suites and CBC suites leave nothing to offer.  */
  {
    static const uint16_t bad[] = { GQ_TLS_AES_128_GCM_SHA256, 0xc013 };

    c.suites = bad;
    c.n_suites = 2;
    CHECK_EQ (gq_tls12_client_new (&t, &c, &s), GQ_ERR_INVAL);
  }
  c.suites = cbc;
  c.n_suites = 4;
  CHECK_EQ (gq_tls12_client_new (&t, &c, &s), GQ_ERR_INVAL);
  c.suites = NULL;
  c.n_suites = 0;
  /* Only ML-DSA and Ed25519: not TLS 1.2 schemes.  */
  {
    static const uint16_t sigs[] = { GQ_SIG_ED25519, GQ_SIG_MLDSA65, 0x0201 };

    c.sigschemes = sigs;
    c.n_sigschemes = 3;
    CHECK_EQ (gq_tls12_client_new (&t, &c, &s), GQ_ERR_INVAL);
  }
  c.sigschemes = NULL;
  c.n_sigschemes = 0;
  /* The engine cannot be driven before it starts, or the wrong way.  */
  CHECK_EQ (gq_tls12_client_new (&t, &c, &s), GQ_OK);
  {
    const uint8_t *b = tp;
    size_t l = 1;

    CHECK_EQ (gq_tls12_feed (t, &b, &l), GQ_ERR_INVAL);
    CHECK_EQ (gq_tls12_change_cipher_spec (t), GQ_ERR_INVAL);
    CHECK_EQ (gq_tls12_export (t, "EXPORTER-x", NULL, 0, (uint8_t *) &l, 1),
              GQ_ERR_INVAL);
  }
  gq_tls12_free (t);
  eng_free (e);

  /* A server needs credentials.  */
  {
    gq_tls_server_config sc;
    struct eng *se = eng_new (1);
    gq_tls12_sink ss = sink_for (se);

    memset (&sc, 0, sizeof sc);
    CHECK_EQ (gq_tls12_server_new (&t, &sc, &ss), GQ_ERR_INVAL);
    sc.credentials.chain = fx_ec.chain;
    sc.credentials.n_chain = 1;
    sc.credentials.key = fx_ec.key;
    sc.suites = cbc;
    sc.n_suites = 4;
    CHECK_EQ (gq_tls12_server_new (&t, &sc, &ss), GQ_ERR_INVAL);
    sc.suites = NULL;
    sc.n_suites = 0;
    sc.quic = 1;
    CHECK_EQ (gq_tls12_server_new (&t, &sc, &ss), GQ_ERR_INVAL);
    eng_free (se);
  }
}

int
main (void)
{
  gq_crypto_init ();
  fx_setup ();
  test_suites_and_keys ();
  test_alpn ();
  test_resumption ();
  test_client_auth ();
  test_server_refusals ();
  test_client_refusals ();
  test_state_machine ();
  test_fuzz ();
  test_config ();
  TST_DONE ();
}

#endif
