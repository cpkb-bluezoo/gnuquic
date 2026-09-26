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
#include <gnuquic/policy.h>
#include <gnuquic/crypto.h>
#include <gnuquic/dtlsrec.h>
#include <gnuquic/dtlshs.h>
#include <gnuquic/transcript.h>
#include <gnuquic/dtlscookie.h>

#include "tls_int.h"		/* gqi_suite_params */

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

#define TAG_LEN 16
#define CHECK_LEN 16
#define COOKIE_VERSION 1

struct gq_dtls_cookies
{
  uint8_t cur[32], prev[32];
  int have_prev;
};

int
gq_dtls_cookies_new (gq_dtls_cookies **out)
{
  gq_dtls_cookies *ck;

  if (out == NULL)
    return GQ_ERR_INVAL;
  TRY (gq_crypto_init ());
  ck = calloc (1, sizeof *ck);
  if (ck == NULL)
    return GQ_ERR_NOMEM;
  if (gq_random (ck->cur, sizeof ck->cur) != GQ_OK)
    {
      free (ck);
      return GQ_ERR_CRYPTO;
    }
  *out = ck;
  return GQ_OK;
}

void
gq_dtls_cookies_free (gq_dtls_cookies *ck)
{
  if (ck)
    {
      gq_wipe (ck, sizeof *ck);
      free (ck);
    }
}

int
gq_dtls_cookies_rotate (gq_dtls_cookies *ck)
{
  uint8_t fresh[32];

  if (ck == NULL)
    return GQ_ERR_INVAL;
  TRY (gq_random (fresh, sizeof fresh));
  memcpy (ck->prev, ck->cur, sizeof ck->prev);
  memcpy (ck->cur, fresh, sizeof ck->cur);
  ck->have_prev = 1;
  gq_wipe (fresh, sizeof fresh);
  return GQ_OK;
}

int
gq_dtls_cookies_set (gq_dtls_cookies *ck, const uint8_t cur[32],
                     const uint8_t prev[32])
{
  if (ck == NULL || cur == NULL)
    return GQ_ERR_INVAL;
  memcpy (ck->cur, cur, 32);
  ck->have_prev = prev != NULL;
  if (prev)
    memcpy (ck->prev, prev, 32);
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Cookie                                                             */
/* ------------------------------------------------------------------ */

/* version | suite | group | hash length | ClientHello1 hash | check | tag  */
#define BODY_FIXED (1 + 2 + 2 + 1)

static int
tag_of (const uint8_t key[32], const uint8_t *binding, size_t bl,
        const uint8_t *body, size_t n, uint8_t tag[TAG_LEN])
{
  uint8_t buf[256 + 128], mac[32];

  if (bl > 256 || n > 128)
    return GQ_ERR_RANGE;
  memcpy (buf, binding, bl);
  memcpy (buf + bl, body, n);
  TRY (gq_hmac (GQ_HASH_SHA256, key, 32, buf, bl + n, mac, sizeof mac));
  memcpy (tag, mac, TAG_LEN);
  return GQ_OK;
}

/* What a ClientHello promises: its random and offered suites, hashed, so
   ClientHello2 can be held to them.  */
static int
check_of (const uint8_t *random, gq_slice suites, uint8_t out[CHECK_LEN])
{
  uint8_t buf[32 + 512], h[32];

  if (suites.len > 512)
    return GQ_ERR_RANGE;
  memcpy (buf, random, 32);
  memcpy (buf + 32, suites.data, suites.len);
  TRY (gq_hash_compute (GQ_HASH_SHA256, buf, 32 + suites.len, h, 32));
  memcpy (out, h, CHECK_LEN);
  return GQ_OK;
}

/* Parsed cookie contents.  */
struct cookie
{
  uint16_t suite, group;
  uint8_t hash[GQ_MAX_HASH_LEN];
  size_t hlen;
  uint8_t check[CHECK_LEN];
};

static int
make_cookie (const gq_dtls_cookies *ck, const uint8_t *binding, size_t bl,
             const struct cookie *c, uint8_t *out, size_t *out_len)
{
  size_t n = 0;

  out[n++] = COOKIE_VERSION;
  out[n++] = (uint8_t) (c->suite >> 8);
  out[n++] = (uint8_t) c->suite;
  out[n++] = (uint8_t) (c->group >> 8);
  out[n++] = (uint8_t) c->group;
  out[n++] = (uint8_t) c->hlen;
  memcpy (out + n, c->hash, c->hlen);
  n += c->hlen;
  memcpy (out + n, c->check, CHECK_LEN);
  n += CHECK_LEN;
  TRY (tag_of (ck->cur, binding, bl, out, n, out + n));
  *out_len = n + TAG_LEN;
  return GQ_OK;
}

/* Authenticate and parse a cookie.  1 if valid.  */
static int
open_cookie (const gq_dtls_cookies *ck, const uint8_t *binding, size_t bl,
             gq_slice s, struct cookie *c)
{
  uint8_t tag[TAG_LEN];
  size_t n, hl;
  int ok = 0;

  if (s.len < BODY_FIXED + CHECK_LEN + TAG_LEN || s.data[0] != COOKIE_VERSION)
    return 0;
  hl = s.data[5];
  if (hl != 32 && hl != 48)
    return 0;
  n = BODY_FIXED + hl + CHECK_LEN;
  if (s.len != n + TAG_LEN)
    return 0;
  if (tag_of (ck->cur, binding, bl, s.data, n, tag) == GQ_OK
      && gq_ct_equal (tag, s.data + n, TAG_LEN))
    ok = 1;
  else if (ck->have_prev
           && tag_of (ck->prev, binding, bl, s.data, n, tag) == GQ_OK
           && gq_ct_equal (tag, s.data + n, TAG_LEN))
    ok = 1;
  if (!ok)
    return 0;
  c->suite = (uint16_t) (((unsigned) s.data[1] << 8) | s.data[2]);
  c->group = (uint16_t) (((unsigned) s.data[3] << 8) | s.data[4]);
  c->hlen = hl;
  memcpy (c->hash, s.data + BODY_FIXED, hl);
  memcpy (c->check, s.data + BODY_FIXED + hl, CHECK_LEN);
  return 1;
}

/* ------------------------------------------------------------------ */
/* Reading the first fragment of a ClientHello                        */
/* ------------------------------------------------------------------ */

/* What we can see of a ClientHello in the bytes at hand.  */
struct hello
{
  int have_prefix;		/* Up to and including cipher_suites.  */
  const uint8_t *random;
  gq_slice suites;
  int have_cookie;
  gq_slice cookie;
  int have_versions, have_groups, have_shares;
  gq_slice versions, groups, shares;
};

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

/* Scan the body of a DTLS ClientHello of which N bytes are available:
   the fixed part, then as many whole extensions as are there.  */
static int
scan_hello (const uint8_t *p, size_t n, struct hello *h)
{
  gq_slice s, ext;
  unsigned type;
  size_t l;

  memset (h, 0, sizeof *h);
  if (!take (&p, &n, 2, &s) || ((s.data[0] << 8) | s.data[1]) != 0xfefd)
    return 0;
  if (!take (&p, &n, 32, &s))
    return 0;
  h->random = s.data;
  if (!take (&p, &n, 1, &s) || !take (&p, &n, s.data[0], &s))	/* session */
    return 0;
  if (!take (&p, &n, 1, &s))					/* cookie */
    return 0;
  if (s.data[0] != 0)		/* Must be empty in DTLS 1.3 (5.3).  */
    return 0;
  if (!take (&p, &n, 2, &s))
    return 0;
  l = ((size_t) s.data[0] << 8) | s.data[1];
  if (l < 2 || l % 2 || !take (&p, &n, l, &h->suites))
    return 0;
  h->have_prefix = 1;
  if (!take (&p, &n, 1, &s) || !take (&p, &n, s.data[0], &s))	/* compression */
    return 1;
  if (!take (&p, &n, 2, &s))
    return 1;
  /* Extensions: walk while whole ones are present.  */
  while (n >= 4)
    {
      const uint8_t *q = p;

      type = ((unsigned) q[0] << 8) | q[1];
      l = ((size_t) q[2] << 8) | q[3];
      if (l > n - 4)
        break;
      ext.data = q + 4;
      ext.len = l;
      p += 4 + l;
      n -= 4 + l;
      switch (type)
        {
        case GQ_EXT_COOKIE:
          h->have_cookie = 1;
          h->cookie = ext;
          break;
        case GQ_EXT_SUPPORTED_VERSIONS:
          h->have_versions = 1;
          h->versions = ext;
          break;
        case GQ_EXT_SUPPORTED_GROUPS:
          h->have_groups = 1;
          h->groups = ext;
          break;
        case GQ_EXT_KEY_SHARE:
          h->have_shares = 1;
          h->shares = ext;
          break;
        default:
          break;
        }
    }
  return 1;
}

/* ------------------------------------------------------------------ */
/* Listening                                                          */
/* ------------------------------------------------------------------ */

struct first
{
  int seen, ok;
  gq_dtls_hs_frag f;
};

static int
on_first_frag (void *u, const gq_dtls_hs_frag *f)
{
  struct first *x = u;

  if (!x->seen)
    {
      x->seen = 1;
      x->f = *f;
      x->ok = f->type == GQ_HS_CLIENT_HELLO && f->frag_off == 0;
    }
  return 1;			/* Only the first fragment matters.  */
}

static int
on_first_rec (void *u, const gq_drec *r)
{
  struct first *x = u;

  if (r->kind == GQ_DREC_PLAINTEXT && r->epoch == 0
      && r->type == GQ_DTLS_CT_HANDSHAKE)
    gq_dtls_hs_parse (r->body, 65536, on_first_frag, x);
  return 1;			/* Only the first record.  */
}

static int
in_list16 (gq_slice list, unsigned v)
{
  size_t i;

  for (i = 0; i + 1 < list.len; i += 2)
    if ((((unsigned) list.data[i] << 8) | list.data[i + 1]) == v)
      return 1;
  return 0;
}

/* Build the HelloRetryRequest message for COOKIE, in TLS form.  */
static int
build_hrr (const struct cookie *c, const uint8_t *cookie, size_t cookie_len,
           uint8_t *out, size_t cap, size_t *len)
{
  gq_sh_params sp;
  gq_wbuf w;

  memset (&sp, 0, sizeof sp);
  sp.hello_retry_request = 1;
  sp.dtls = 1;
  sp.cipher_suite = c->suite;
  sp.group = c->group;
  sp.cookie = (gq_slice) { cookie, cookie_len };
  gq_wbuf_init (&w, out, cap);
  gq_build_server_hello (&w, &sp);
  TRY (gq_wbuf_status (&w));
  *len = w.len;
  return GQ_OK;
}

int
gq_dtls_listen (gq_dtls_cookies *ck, const gq_tls_server_config *config,
                const uint8_t *binding, size_t bl, const uint8_t *dgram,
                size_t len, uint8_t *reply, size_t reply_cap,
                size_t *reply_len, gq_tls_dtls_prime *prime)
{
  struct first x;
  struct hello h;
  struct cookie c;
  const uint16_t *suites, *groups;
  size_t ns, ng, i, n;
  int complete;
  uint8_t cookie[BODY_FIXED + GQ_MAX_HASH_LEN + CHECK_LEN + TAG_LEN];
  size_t cookie_len;
  uint8_t hrr[GQ_DTLS_HRR_MAX];
  size_t hrr_len;
  enum gq_aead aead;
  enum gq_hash hash;
  gq_wbuf w;

  if (ck == NULL || config == NULL || binding == NULL || dgram == NULL
      || reply == NULL || reply_len == NULL || prime == NULL
      || reply_cap < GQ_DTLS_LISTEN_REPLY_MAX)
    return GQ_ERR_INVAL;
  *reply_len = 0;

  memset (&x, 0, sizeof x);
  gq_dtls_records (dgram, len, on_first_rec, &x);
  if (!x.seen || !x.ok)
    return GQ_DTLS_LISTEN_DROP;
  complete = x.f.frag_len == x.f.length;
  if (!scan_hello (x.f.data.data, x.f.data.len, &h) || !h.have_prefix)
    return GQ_DTLS_LISTEN_DROP;
  /* DTLS 1.3 must be offered (an older DTLS client is not ours to serve).  */
  if (complete)
    {
      if (!h.have_versions || h.versions.len < 1
          || h.versions.data[0] != h.versions.len - 1
          || !in_list16 ((gq_slice) { h.versions.data + 1,
                                      h.versions.len - 1 }, 0xfefc))
        return GQ_DTLS_LISTEN_DROP;
    }

  /* The server's choices, as the association would make them.  */
  suites = config->suites ? config->suites
                          : gq_policy_default_suites (GQ_DTLS_1_3, &ns);
  ns = config->suites ? config->n_suites : ns;
  groups = config->groups ? config->groups : gq_policy_default_groups (&ng);
  ng = config->groups ? config->n_groups : ng;

  /* A cookie in hand: ClientHello2.  */
  if (h.have_cookie)
    {
      gq_slice cv = { NULL, 0 };
      uint8_t chk[CHECK_LEN];

      /* extension body: 2-byte length then the cookie.  */
      if (h.cookie.len >= 2
          && (((size_t) h.cookie.data[0] << 8) | h.cookie.data[1])
             == h.cookie.len - 2)
        cv = (gq_slice) { h.cookie.data + 2, h.cookie.len - 2 };
      if (cv.len && open_cookie (ck, binding, bl, cv, &c)
          && check_of (h.random, h.suites, chk) == GQ_OK
          && gq_ct_equal (chk, c.check, CHECK_LEN)
          && in_list16 (h.suites, c.suite)
          && gq_policy_allows_suite (GQ_DTLS_1_3, c.suite))
        {
          memset (prime, 0, sizeof *prime);
          prime->suite = c.suite;
          prime->group = c.group;
          memcpy (prime->ch1_hash, c.hash, c.hlen);
          if (build_hrr (&c, cv.data, cv.len, prime->hrr, sizeof prime->hrr,
                         &prime->hrr_len) != GQ_OK)
            return GQ_DTLS_LISTEN_DROP;
          return GQ_DTLS_LISTEN_ACCEPT;
        }
      /* Stale or forged: fall through and treat a whole hello as new.  */
    }

  /* ClientHello1: needs the whole message, in this datagram.  */
  if (!complete || !h.have_versions || !h.have_groups || !h.have_shares)
    return GQ_DTLS_LISTEN_DROP;

  memset (&c, 0, sizeof c);
  for (i = 0; i < ns && c.suite == 0; i++)
    if (in_list16 (h.suites, suites[i])
        && gq_policy_allows_suite (GQ_DTLS_1_3, suites[i]))
      c.suite = suites[i];
  if (c.suite == 0)
    return GQ_DTLS_LISTEN_DROP;
  {
    /* The retry asks for our most preferred group the client supports,
       unless the client already sent a share for exactly that one; then
       it carries only the cookie.  (The retry round trip is needed for the
       cookie anyway, so this is how a hybrid post-quantum group is
       reached although the first hello is kept small.)  */
    gq_slice gl, sh;
    unsigned want = 0;
    size_t o = 0;

    if (h.groups.len < 2 || h.shares.len < 2)
      return GQ_DTLS_LISTEN_DROP;
    gl = (gq_slice) { h.groups.data + 2, h.groups.len - 2 };
    sh = (gq_slice) { h.shares.data + 2, h.shares.len - 2 };
    for (i = 0; i < ng && want == 0; i++)
      if (in_list16 (gl, groups[i]))
        want = groups[i];
    if (want == 0)
      return GQ_DTLS_LISTEN_DROP;
    c.group = (uint16_t) want;
    while (o + 4 <= sh.len)
      {
        unsigned g = ((unsigned) sh.data[o] << 8) | sh.data[o + 1];
        size_t kl = ((size_t) sh.data[o + 2] << 8) | sh.data[o + 3];

        if (kl > sh.len - o - 4)
          break;
        if (g == want)
          c.group = 0;
        o += 4 + kl;
      }
  }
  /* Bind the cookie to this hello: its hash (the transcript will start
     from it), and what it promised.  */
  {
    gq_transcript *tr;
    uint8_t hdr[4];

    if (!gqi_suite_params (c.suite, &aead, &hash))
      return GQ_DTLS_LISTEN_DROP;
    c.hlen = gq_hash_size (hash);
    hdr[0] = GQ_HS_CLIENT_HELLO;
    hdr[1] = (uint8_t) (x.f.length >> 16);
    hdr[2] = (uint8_t) (x.f.length >> 8);
    hdr[3] = (uint8_t) x.f.length;
    if (gq_transcript_new (&tr, hash) != GQ_OK)
      return GQ_ERR_NOMEM;
    n = (gq_transcript_update (tr, hdr, 4) == GQ_OK
         && gq_transcript_update (tr, x.f.data.data, x.f.data.len) == GQ_OK
         && gq_transcript_hash (tr, c.hash, c.hlen) == GQ_OK);
    gq_transcript_free (tr);
    if (!n)
      return GQ_ERR_CRYPTO;
  }
  TRY (check_of (h.random, h.suites, c.check));
  TRY (make_cookie (ck, binding, bl, &c, cookie, &cookie_len));
  TRY (build_hrr (&c, cookie, cookie_len, hrr, sizeof hrr, &hrr_len));

  /* The reply: one plaintext record (epoch 0, record 0) carrying message
     0 of the server's side, unfragmented.  */
  {
    uint8_t frag[GQ_DTLS_HRR_MAX + GQ_DTLS_HS_HEADER];
    gq_wbuf f;

    gq_wbuf_init (&f, frag, sizeof frag);
    gq_dtls_put_hs_frag (&f, GQ_HS_SERVER_HELLO, (uint32_t) (hrr_len - 4), 0,
                         0, hrr + 4, hrr_len - 4);
    TRY (gq_wbuf_status (&f));
    gq_wbuf_init (&w, reply, reply_cap);
    gq_dtls_put_plain (&w, GQ_DTLS_CT_HANDSHAKE, 0, frag, f.len);
    TRY (gq_wbuf_status (&w));
  }
  /* Never answer with more than we were sent.  */
  if (w.len >= len)
    return GQ_DTLS_LISTEN_DROP;
  *reply_len = w.len;
  return GQ_DTLS_LISTEN_REPLY;
}
