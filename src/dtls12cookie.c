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
#include <gnuquic/crypto.h>
#include <gnuquic/dtls12rec.h>
#include <gnuquic/dtlshs.h>
#include <gnuquic/tls12msg.h>
#include <gnuquic/dtls12cookie.h>

#include "dtls_int.h"

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

#define COOKIE_LEN 32


struct first
{
  int seen;
  gq_d12rec rec;
  gq_dtls_hs_frag f;
  int ok;
};

static int
on_first_frag (void *u, const gq_dtls_hs_frag *f)
{
  struct first *x = u;

  if (!x->ok)
    {
      x->f = *f;
      x->ok = f->type == GQ_HS_CLIENT_HELLO && f->frag_off == 0;
    }
  return 1;
}

static int
on_first_rec (void *u, const gq_d12rec *r)
{
  struct first *x = u;

  if (!x->seen && r->epoch == 0 && r->type == GQ_D12_CT_HANDSHAKE)
    {
      x->seen = 1;
      x->rec = *r;
      gq_dtls_hs_parse (r->body, 65536, on_first_frag, x);
    }
  return 1;
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

/* The HMAC over binding and the hello's constant parts.  */
static int
tag_of (const uint8_t key[32], const uint8_t *binding, size_t bl,
        const uint8_t *random, gq_slice sid, gq_slice suites,
        uint8_t out[COOKIE_LEN])
{
  uint8_t buf[256 + 32 + 1 + 32 + 2 + 512];
  size_t n = 0;

  if (bl > 256 || sid.len > 32 || suites.len > 512)
    return GQ_ERR_RANGE;
  memcpy (buf + n, binding, bl);
  n += bl;
  memcpy (buf + n, random, 32);
  n += 32;
  buf[n++] = (uint8_t) sid.len;
  memcpy (buf + n, sid.data, sid.len);
  n += sid.len;
  buf[n++] = (uint8_t) (suites.len >> 8);
  buf[n++] = (uint8_t) suites.len;
  memcpy (buf + n, suites.data, suites.len);
  n += suites.len;
  return gq_hmac (GQ_HASH_SHA256, key, 32, buf, n, out, COOKIE_LEN);
}

int
gq_dtls12_listen (gq_dtls_cookies *ck, const uint8_t *binding, size_t bl,
                  const uint8_t *dgram, size_t len, uint8_t *reply,
                  size_t reply_cap, size_t *reply_len,
                  gq_dtls12_prime *prime)
{
  struct first x;
  const uint8_t *p;
  size_t n, l;
  gq_slice s, random, sid, cookie, suites;
  uint8_t want[COOKIE_LEN], hvr[64], frag[96];
  gq_wbuf w, f;
  gq_dtls12_epoch e0;

  if (ck == NULL || binding == NULL || dgram == NULL || reply == NULL
      || reply_len == NULL || prime == NULL
      || reply_cap < GQ_DTLS_LISTEN_REPLY_MAX)
    return GQ_ERR_INVAL;
  *reply_len = 0;

  memset (&x, 0, sizeof x);
  gq_dtls12_records (dgram, len, on_first_rec, &x);
  if (!x.seen || !x.ok)
    return GQ_DTLS_LISTEN_DROP;

  /* client_version, random, session_id, cookie, cipher_suites.  */
  p = x.f.data.data;
  n = x.f.data.len;
  if (!take (&p, &n, 2, &s) || ((s.data[0] << 8) | s.data[1]) != 0xfefd)
    return GQ_DTLS_LISTEN_DROP;
  if (!take (&p, &n, 32, &random))
    return GQ_DTLS_LISTEN_DROP;
  if (!take (&p, &n, 1, &s) || s.data[0] > 32
      || !take (&p, &n, s.data[0], &sid))
    return GQ_DTLS_LISTEN_DROP;
  if (!take (&p, &n, 1, &s) || !take (&p, &n, s.data[0], &cookie))
    return GQ_DTLS_LISTEN_DROP;
  if (!take (&p, &n, 2, &s))
    return GQ_DTLS_LISTEN_DROP;
  l = ((size_t) s.data[0] << 8) | s.data[1];
  if (l < 2 || l % 2 || !take (&p, &n, l, &suites))
    return GQ_DTLS_LISTEN_DROP;

  /* A valid cookie (from this or the previous secret): accept.  */
  if (cookie.len == COOKIE_LEN)
    {
      if (tag_of (ck->cur, binding, bl, random.data, sid, suites, want)
          == GQ_OK && gq_ct_equal (want, cookie.data, COOKIE_LEN))
        {
          prime->e0_seq = x.rec.seq + 1;
          return GQ_DTLS_LISTEN_ACCEPT;
        }
      if (ck->have_prev
          && tag_of (ck->prev, binding, bl, random.data, sid, suites, want)
             == GQ_OK && gq_ct_equal (want, cookie.data, COOKIE_LEN))
        {
          prime->e0_seq = x.rec.seq + 1;
          return GQ_DTLS_LISTEN_ACCEPT;
        }
    }

  /* Otherwise a HelloVerifyRequest with the cookie for this hello, in a
     record numbered like the ClientHello's.  */
  TRY (tag_of (ck->cur, binding, bl, random.data, sid, suites, want));
  gq_wbuf_init (&w, hvr, sizeof hvr);
  gq_tls12_build_hvr (&w, (gq_slice) { want, COOKIE_LEN });
  TRY (gq_wbuf_status (&w));
  gq_wbuf_init (&f, frag, sizeof frag);
  gq_dtls_put_hs_frag (&f, GQ_HS12_HELLO_VERIFY_REQUEST,
                       (uint32_t) (w.len - 4), 0, 0, hvr + 4, w.len - 4);
  TRY (gq_wbuf_status (&f));
  gq_dtls12_epoch_plain (&e0);
  e0.send_seq = x.rec.seq;
  gq_wbuf_init (&w, reply, reply_cap);
  gq_dtls12_put_plain (&w, &e0, GQ_D12_CT_HANDSHAKE, frag, f.len);
  TRY (gq_wbuf_status (&w));
  if (w.len >= len)
    return GQ_DTLS_LISTEN_DROP;		/* Never more than we were sent.  */
  *reply_len = w.len;
  return GQ_DTLS_LISTEN_REPLY;
}
