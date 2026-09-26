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

#include <stdlib.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/tlsmsg.h>
#include <gnuquic/tls12msg.h>
#include <gnuquic/dtlsrec.h>
#include <gnuquic/dtlshs.h>
#include <gnuquic/dtls12cookie.h>
#include <gnuquic/dtlsauto.h>

#define V13 0xfefc
#define V12 0xfefd

struct gq_dtlsauto
{
  int server;
  unsigned versions;
  gq_tls_server_config scfg;	/* Kept: the engines point into what we hold.  */
  gq_tls_config ccfg, cfg12;
  gq_dtls_events ev, wev;
  gq_dtls_params params;
  int have_params;
  gq_dtls *d13;
  gq_dtls12 *d12;
  /* Client: the hello the DTLS 1.3 engine sent, for the hand-over.  */
  uint8_t ch[4096];
  size_t ch_len;
  uint64_t ch_next_seq;
  int have_ch, undecided;
};

static unsigned
norm (unsigned v)
{
  v &= GQ_DTLSAUTO_DTLS12 | GQ_DTLSAUTO_DTLS13;
  return v ? v : (GQ_DTLSAUTO_DTLS12 | GQ_DTLSAUTO_DTLS13);
}

/* ------------------------------------------------------------------ */
/* Reading the first datagram                                         */
/* ------------------------------------------------------------------ */

struct first
{
  int seen;
  gq_drec rec;
  gq_dtls_hs_frag f;
  int ok;
};

static int
on_frag (void *u, const gq_dtls_hs_frag *f)
{
  struct first *x = u;

  if (!x->ok)
    {
      x->f = *f;
      x->ok = f->frag_off == 0;
    }
  return 1;
}

static int
on_rec (void *u, const gq_drec *r)
{
  struct first *x = u;

  if (!x->seen && r->kind == GQ_DREC_PLAINTEXT && r->epoch == 0
      && r->type == GQ_DTLS_CT_HANDSHAKE)
    {
      x->seen = 1;
      x->rec = *r;
      gq_dtls_hs_parse (r->body, 65536, on_frag, x);
    }
  return 1;
}

/* The first plaintext handshake fragment of DGRAM, at offset 0.  */
static int
first_frag (const uint8_t *d, size_t n, struct first *x)
{
  memset (x, 0, sizeof *x);
  gq_dtls_records (d, n, on_rec, x);
  return x->seen && x->ok;
}

static int
take (const uint8_t **p, size_t *n, size_t k, gq_slice *out)
{
  if (k > *n)
    return 0;
  out->data = *p;
  out->len = k;
  *p += k;
  *n -= k;
  return 1;
}

/* Walk the whole extensions present in the N bytes at P; report the body
   of the first of TYPE (found = 1).  */
static void
find_ext (const uint8_t *p, size_t n, unsigned type, int *found, gq_slice *body)
{
  *found = 0;
  while (n >= 4)
    {
      unsigned t = ((unsigned) p[0] << 8) | p[1];
      size_t l = ((size_t) p[2] << 8) | p[3];

      if (l > n - 4)
        return;
      if (t == type)
        {
          *found = 1;
          *body = (gq_slice) { p + 4, l };
          return;
        }
      p += 4 + l;
      n -= 4 + l;
    }
}

/* Does the supported_versions list (client form: length byte, then
   versions) hold V?  */
static int
list_has (gq_slice s, unsigned v)
{
  size_t i;

  if (s.len < 1 || s.data[0] != s.len - 1)
    return 0;
  for (i = 1; i + 1 < s.len; i += 2)
    if ((((unsigned) s.data[i] << 8) | s.data[i + 1]) == v)
      return 1;
  return 0;
}

/* Which DTLS version is this first datagram of a client for?  Returns V13
   or V12, or 0 for a datagram to drop.  See dtlsauto.h.  */
static unsigned
classify (const uint8_t *d, size_t n, unsigned versions)
{
  struct first x;
  const uint8_t *p;
  size_t len, l;
  gq_slice s, cookie;
  int found;
  gq_slice body;

  if (versions == GQ_DTLSAUTO_DTLS13)
    return V13;
  if (versions == GQ_DTLSAUTO_DTLS12)
    return V12;
  if (!first_frag (d, n, &x) || x.f.type != GQ_HS_CLIENT_HELLO)
    return 0;
  p = x.f.data.data;
  len = x.f.data.len;
  if (!take (&p, &len, 2 + 32, &s) || !take (&p, &len, 1, &s)
      || !take (&p, &len, s.data[0], &s))
    return 0;
  if (!take (&p, &len, 1, &s) || !take (&p, &len, s.data[0], &cookie))
    return 0;
  if (cookie.len)		/* A HelloVerifyRequest cookie answers 1.2.  */
    return V12;
  if (!take (&p, &len, 2, &s))
    return 0;
  l = ((size_t) s.data[0] << 8) | s.data[1];
  if (!take (&p, &len, l, &s) || !take (&p, &len, 1, &s)
      || !take (&p, &len, s.data[0], &s) || !take (&p, &len, 2, &s))
    return V12;
  find_ext (p, len, GQ_EXT_COOKIE, &found, &body);
  if (found)			/* A HelloRetryRequest cookie: 1.3.  */
    return V13;
  find_ext (p, len, GQ_EXT_SUPPORTED_VERSIONS, &found, &body);
  if (!found)
    return V12;
  if (list_has (body, V13))
    return V13;
  return list_has (body, V12) ? V12 : 0;
}

/* ------------------------------------------------------------------ */
/* Server                                                             */
/* ------------------------------------------------------------------ */

int
gq_dtlsauto_listen (gq_dtls_cookies *ck, const gq_tls_server_config *config,
                    unsigned versions, const uint8_t *binding,
                    size_t binding_len, const uint8_t *dgram, size_t len,
                    uint8_t *reply, size_t reply_cap, size_t *reply_len,
                    gq_dtlsauto_prime *prime)
{
  unsigned v;
  int r;

  if (ck == NULL || config == NULL || dgram == NULL || prime == NULL)
    return GQ_ERR_INVAL;
  versions = norm (versions);
  memset (prime, 0, sizeof *prime);
  v = classify (dgram, len, versions);
  if (v == V13)
    r = gq_dtls_listen (ck, config, binding, binding_len, dgram, len, reply,
                        reply_cap, reply_len, &prime->p13);
  else if (v == V12)
    r = gq_dtls12_listen (ck, binding, binding_len, dgram, len, reply,
                          reply_cap, reply_len, &prime->p12);
  else
    {
      if (reply_len)
        *reply_len = 0;
      return GQ_DTLS_LISTEN_DROP;
    }
  if (r == GQ_DTLS_LISTEN_ACCEPT)
    prime->version = v;
  return r;
}

static int
make_server_engine (gq_dtlsauto *c, unsigned version,
                    const gq_dtlsauto_prime *prime)
{
  gq_tls_server_config cfg = c->scfg;

  if (version == V13)
    return gq_dtls_server_new (&c->d13, &cfg, &c->ev,
                               c->have_params ? &c->params : NULL,
                               prime ? &prime->p13 : NULL);
  return gq_dtls12_server_new (&c->d12, &cfg, &c->ev,
                               c->have_params ? &c->params : NULL,
                               prime ? &prime->p12 : NULL);
}

int
gq_dtlsauto_server_new (gq_dtlsauto **out, const gq_tls_server_config *config,
                        const gq_dtls_events *events,
                        const gq_dtls_params *params, unsigned versions,
                        const gq_dtlsauto_prime *prime)
{
  gq_dtlsauto *c;
  unsigned only = 0;
  int r;

  if (out == NULL || config == NULL || events == NULL)
    return GQ_ERR_INVAL;
  *out = NULL;
  versions = norm (versions);
  if (prime != NULL)
    {
      if ((prime->version == V13 && !(versions & GQ_DTLSAUTO_DTLS13))
          || (prime->version == V12 && !(versions & GQ_DTLSAUTO_DTLS12))
          || (prime->version != V13 && prime->version != V12))
        return GQ_ERR_INVAL;
      only = prime->version;
    }
  else if (versions == GQ_DTLSAUTO_DTLS13)
    only = V13;
  else if (versions == GQ_DTLSAUTO_DTLS12)
    only = V12;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  c->server = 1;
  c->versions = versions;
  c->scfg = *config;
  c->scfg.tls13_sentinel = (versions & GQ_DTLSAUTO_DTLS13) != 0;
  c->ev = *events;
  if (params)
    {
      c->params = *params;
      c->have_params = 1;
    }
  if (only)
    {
      r = make_server_engine (c, only, prime);
      if (r != GQ_OK)
        {
          free (c);
          return r;
        }
    }
  *out = c;
  return GQ_OK;
}

void
gq_dtlsauto_free (gq_dtlsauto *c)
{
  if (c == NULL)
    return;
  gq_dtls_free (c->d13);
  gq_dtls12_free (c->d12);
  free (c);
}

/* ------------------------------------------------------------------ */
/* Client                                                             */
/* ------------------------------------------------------------------ */

/* While undecided, remember the hello the DTLS 1.3 engine sent (the last
   copy: retransmissions carry higher record numbers).  */
static int
w_send (void *u, const uint8_t *d, size_t n)
{
  gq_dtlsauto *c = u;
  struct first x;

  if (c->undecided && first_frag (d, n, &x) && x.f.type == GQ_HS_CLIENT_HELLO
      && x.f.frag_len == x.f.length && x.f.length + 4 <= sizeof c->ch)
    {
      c->ch[0] = GQ_HS_CLIENT_HELLO;
      c->ch[1] = (uint8_t) (x.f.length >> 16);
      c->ch[2] = (uint8_t) (x.f.length >> 8);
      c->ch[3] = (uint8_t) x.f.length;
      memcpy (c->ch + 4, x.f.data.data, x.f.length);
      c->ch_len = x.f.length + 4;
      c->ch_next_seq = x.rec.seq + 1;
      c->have_ch = 1;
    }
  return c->ev.send (c->ev.user, d, n);
}

static int
w_data (void *u, const uint8_t *d, size_t n)
{
  gq_dtlsauto *c = u;

  return c->ev.data (c->ev.user, d, n);
}

static int
w_connected (void *u, const gq_tls_info *i)
{
  gq_dtlsauto *c = u;

  return c->ev.connected (c->ev.user, i);
}

static int
w_ticket (void *u, const gq_tls_ticket *t)
{
  gq_dtlsauto *c = u;

  return c->ev.ticket (c->ev.user, t);
}

static int
w_verify (void *u, const gq_slice *chain, size_t n, const char *name)
{
  gq_dtlsauto *c = u;

  return c->ev.verify_peer (c->ev.user, chain, n, name);
}

static void
w_closed (void *u, int error, int alert)
{
  gq_dtlsauto *c = u;

  if (c->ev.closed)
    c->ev.closed (c->ev.user, error, alert);
}

int
gq_dtlsauto_client_new (gq_dtlsauto **out, const gq_tls_config *config,
                        const gq_dtls_events *events,
                        const gq_dtls_params *params, unsigned versions)
{
  gq_dtlsauto *c;
  int r;

  if (out == NULL || config == NULL || events == NULL || config->quic
      || config->transport_params)
    return GQ_ERR_INVAL;
  *out = NULL;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  c->versions = norm (versions);
  c->ccfg = *config;
  c->cfg12 = *config;
  c->cfg12.early_data = 0;
  c->cfg12.also_tls12 = 0;
  c->ev = *events;
  if (params)
    {
      c->params = *params;
      c->have_params = 1;
    }
  if (c->versions == GQ_DTLSAUTO_DTLS13)
    r = gq_dtls_client_new (&c->d13, &c->ccfg, &c->ev,
                            c->have_params ? &c->params : NULL);
  else if (c->versions == GQ_DTLSAUTO_DTLS12)
    r = gq_dtls12_client_new (&c->d12, &c->cfg12, &c->ev,
                              c->have_params ? &c->params : NULL);
  else
    {
      c->ccfg.also_tls12 = 1;
      c->wev = *events;
      c->wev.user = c;
      c->wev.send = w_send;
      c->wev.data = w_data;
      c->wev.connected = events->connected ? w_connected : NULL;
      c->wev.ticket = events->ticket ? w_ticket : NULL;
      c->wev.verify_peer = events->verify_peer ? w_verify : NULL;
      c->wev.closed = w_closed;
      c->undecided = 1;
      r = gq_dtls_client_new (&c->d13, &c->ccfg, &c->wev,
                              c->have_params ? &c->params : NULL);
    }
  if (r != GQ_OK)
    {
      free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

/* Client: which engine does the server's first datagram belong to?  */
static unsigned
client_classify (const uint8_t *d, size_t n)
{
  struct first x;
  gq_slice s, body;
  const uint8_t *p;
  size_t len, l;
  int found;

  if (!first_frag (d, n, &x))
    return V13;			/* Not ours to judge: the engine refuses.  */
  if (x.f.type == GQ_HS12_HELLO_VERIFY_REQUEST)
    return V12;
  if (x.f.type != GQ_HS_SERVER_HELLO)
    return V13;
  p = x.f.data.data;
  len = x.f.data.len;
  if (!take (&p, &len, 2 + 32, &s) || !take (&p, &len, 1, &s)
      || !take (&p, &len, s.data[0], &s) || !take (&p, &len, 3, &s)
      || !take (&p, &len, 2, &s))
    return V13;
  l = ((size_t) s.data[0] << 8) | s.data[1];
  if (l > len)
    return V13;
  find_ext (p, l, GQ_EXT_SUPPORTED_VERSIONS, &found, &body);
  return found ? V13 : V12;
}

/* The server chose DTLS 1.2: continue from the hello already sent.  */
static int
hand_over (gq_dtlsauto *c, uint64_t now)
{
  int r;

  if (!c->have_ch)
    return GQ_ERR_PROTOCOL;
  r = gq_dtls12_client_new (&c->d12, &c->cfg12, &c->ev,
                            c->have_params ? &c->params : NULL);
  if (r != GQ_OK)
    return r;
  r = gq_dtls12_client_adopt (c->d12, c->ch, c->ch_len, c->ch_next_seq, now);
  if (r != GQ_OK)
    return r;
  gq_dtls_free (c->d13);
  c->d13 = NULL;
  c->undecided = 0;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Association                                                        */
/* ------------------------------------------------------------------ */

int
gq_dtlsauto_start (gq_dtlsauto *c, uint64_t now)
{
  if (c == NULL || c->server)
    return GQ_ERR_INVAL;
  if (c->d13)
    return gq_dtls_start (c->d13, now);
  return gq_dtls12_start (c->d12, now);
}

int
gq_dtlsauto_receive (gq_dtlsauto *c, const uint8_t *dgram, size_t len,
                     uint64_t now)
{
  int r;

  if (c == NULL || dgram == NULL)
    return GQ_ERR_INVAL;
  if (c->server && !c->d13 && !c->d12)
    {
      unsigned v = classify (dgram, len, c->versions);

      if (v == 0)
        return GQ_OK;		/* Not a hello we can serve: dropped.  */
      r = make_server_engine (c, v, NULL);
      if (r != GQ_OK)
        return r;
    }
  else if (!c->server && c->undecided)
    {
      if (client_classify (dgram, len) == V12)
        {
          r = hand_over (c, now);
          if (r != GQ_OK)
            {
              c->undecided = 0;
              w_closed (c, r, -1);
              return r;
            }
        }
      else
        c->undecided = 0;
    }
  if (c->d13)
    return gq_dtls_receive (c->d13, dgram, len, now);
  return gq_dtls12_receive (c->d12, dgram, len, now);
}

int
gq_dtlsauto_send (gq_dtlsauto *c, const uint8_t *data, size_t len)
{
  if (c == NULL)
    return GQ_ERR_INVAL;
  if (c->d13)
    return gq_dtls_send (c->d13, data, len);
  if (c->d12)
    return gq_dtls12_send (c->d12, data, len);
  return GQ_ERR_INVAL;
}

size_t
gq_dtlsauto_max_payload (const gq_dtlsauto *c)
{
  if (c == NULL)
    return 0;
  if (c->d13)
    return gq_dtls_max_payload (c->d13);
  return c->d12 ? gq_dtls12_max_payload (c->d12) : 0;
}

int
gq_dtlsauto_key_update (gq_dtlsauto *c, int request_peer)
{
  if (c == NULL)
    return GQ_ERR_INVAL;
  if (c->d13)
    return gq_dtls_key_update (c->d13, request_peer);
  return GQ_ERR_UNSUPPORTED;
}

int
gq_dtlsauto_close (gq_dtlsauto *c)
{
  if (c == NULL)
    return GQ_ERR_INVAL;
  if (c->d13)
    return gq_dtls_close (c->d13);
  if (c->d12)
    return gq_dtls12_close (c->d12);
  return GQ_OK;
}

uint64_t
gq_dtlsauto_deadline (const gq_dtlsauto *c)
{
  if (c == NULL)
    return 0;
  if (c->d13)
    return gq_dtls_deadline (c->d13);
  return c->d12 ? gq_dtls12_deadline (c->d12) : 0;
}

int
gq_dtlsauto_timeout (gq_dtlsauto *c, uint64_t now)
{
  if (c == NULL)
    return GQ_ERR_INVAL;
  if (c->d13)
    return gq_dtls_timeout (c->d13, now);
  return c->d12 ? gq_dtls12_timeout (c->d12, now) : GQ_OK;
}

int
gq_dtlsauto_is_connected (const gq_dtlsauto *c)
{
  if (c == NULL)
    return 0;
  if (c->d13)
    return gq_dtls_is_connected (c->d13);
  return c->d12 ? gq_dtls12_is_connected (c->d12) : 0;
}

int
gq_dtlsauto_is_closed (const gq_dtlsauto *c)
{
  if (c == NULL)
    return 1;
  if (c->d13)
    return gq_dtls_is_closed (c->d13);
  return c->d12 ? gq_dtls12_is_closed (c->d12) : 0;
}

int
gq_dtlsauto_export (const gq_dtlsauto *c, const char *label,
                    const uint8_t *context, size_t context_len, uint8_t *out,
                    size_t out_len)
{
  if (c == NULL)
    return GQ_ERR_INVAL;
  if (c->d13)
    return gq_dtls_export (c->d13, label, context, context_len, out, out_len);
  if (c->d12)
    return gq_dtls12_export (c->d12, label, context, context_len, out,
                             out_len);
  return GQ_ERR_INVAL;
}

unsigned
gq_dtlsauto_version (const gq_dtlsauto *c)
{
  if (c == NULL || c->undecided)
    return 0;
  if (c->d13)
    return V13;
  return c->d12 ? V12 : 0;
}
