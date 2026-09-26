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

#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/tls12msg.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* ------------------------------------------------------------------ */
/* Reading                                                            */
/* ------------------------------------------------------------------ */

struct rd
{
  const uint8_t *p;
  size_t n;
};

static int
rd_bytes (struct rd *r, size_t len, gq_slice *out)
{
  if (len > r->n)
    return GQ_ERR_ENCODING;
  out->data = r->p;
  out->len = len;
  r->p += len;
  r->n -= len;
  return GQ_OK;
}

static int
rd_uint (struct rd *r, unsigned width, unsigned long *v)
{
  gq_slice s;
  unsigned i;

  TRY (rd_bytes (r, width, &s));
  *v = 0;
  for (i = 0; i < width; i++)
    *v = (*v << 8) | s.data[i];
  return GQ_OK;
}

static int
rd_vec (struct rd *r, unsigned width, gq_slice *out)
{
  unsigned long n;

  TRY (rd_uint (r, width, &n));
  return rd_bytes (r, n, out);
}

static int
rd_end (const struct rd *r)
{
  return r->n == 0 ? GQ_OK : GQ_ERR_ENCODING;
}

int
gq_tls12_certificate_parse (gq_slice body, gq_slice *chain, size_t max,
                            size_t *n)
{
  struct rd r = { body.data, body.len }, l;
  gq_slice list;

  *n = 0;
  TRY (rd_vec (&r, 3, &list));
  TRY (rd_end (&r));
  l.p = list.data;
  l.n = list.len;
  while (l.n > 0)
    {
      gq_slice der;

      TRY (rd_vec (&l, 3, &der));
      if (der.len == 0)
        return GQ_ERR_ENCODING;
      if (*n == max)
        return GQ_ERR_PROTOCOL;
      chain[(*n)++] = der;
    }
  return GQ_OK;
}

/* ECPoint: one length byte then the point.  */
static int
rd_point (struct rd *r, gq_slice *point)
{
  TRY (rd_vec (r, 1, point));
  if (point->len == 0)
    return GQ_ERR_ENCODING;
  return GQ_OK;
}

static int
parse_ske (gq_slice body, gq_tls12_ske *ske, int wide)
{
  struct rd r = { body.data, body.len };
  const uint8_t *start = body.data;
  unsigned long v;
  size_t want;

  memset (ske, 0, sizeof *ske);
  TRY (rd_uint (&r, 1, &v));
  if (v != GQ_TLS12_CURVE_NAMED)
    return GQ_ERR_PROTOCOL;
  TRY (rd_uint (&r, 2, &v));
  ske->group = (uint16_t) v;
  if (v == GQ_GROUP_SECP256R1)
    want = GQ_TLS12_POINT_LEN;
  else if (wide && v == GQ_GROUP_SECP384R1)
    want = 97;
  else if (wide && v == GQ_GROUP_X25519)
    want = 32;
  else
    return GQ_ERR_PROTOCOL;
  TRY (rd_point (&r, &ske->point));
  ske->params.data = start;
  ske->params.len = (size_t) (r.p - start);
  if (ske->point.len != want)
    return GQ_ERR_PROTOCOL;
  TRY (rd_uint (&r, 2, &v));
  ske->scheme = (uint16_t) v;
  TRY (rd_vec (&r, 2, &ske->signature));
  return rd_end (&r);
}

int
gq_tls12_ske_parse (gq_slice body, gq_tls12_ske *ske)
{
  return parse_ske (body, ske, 0);
}

int
gq_tls12_ske_parse_wide (gq_slice body, gq_tls12_ske *ske)
{
  return parse_ske (body, ske, 1);
}

int
gq_tls12_certreq_parse (gq_slice body, gq_slice *sigalgs)
{
  struct rd r = { body.data, body.len };
  gq_slice types, cas, names;

  TRY (rd_vec (&r, 1, &types));
  if (types.len == 0)
    return GQ_ERR_ENCODING;
  TRY (rd_vec (&r, 2, sigalgs));
  if (sigalgs->len < 2 || sigalgs->len % 2)
    return GQ_ERR_ENCODING;
  TRY (rd_vec (&r, 2, &cas));
  TRY (rd_end (&r));
  /* Each authority is a 2-byte-length distinguished name.  */
  {
    struct rd c = { cas.data, cas.len };

    while (c.n > 0)
      TRY (rd_vec (&c, 2, &names));
  }
  return GQ_OK;
}

int
gq_tls12_cke_parse (gq_slice body, gq_slice *point)
{
  struct rd r = { body.data, body.len };

  TRY (rd_point (&r, point));
  TRY (rd_end (&r));
  return point->len == GQ_TLS12_POINT_LEN ? GQ_OK : GQ_ERR_PROTOCOL;
}

int
gq_tls12_nst_parse (gq_slice body, uint32_t *lifetime, gq_slice *ticket)
{
  struct rd r = { body.data, body.len };
  unsigned long v;

  TRY (rd_uint (&r, 4, &v));
  *lifetime = (uint32_t) v;
  TRY (rd_vec (&r, 2, ticket));
  TRY (rd_end (&r));
  if (ticket->len == 0)
    return GQ_ERR_ENCODING;
  if (*lifetime > 604800)
    return GQ_ERR_PROTOCOL;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Writing                                                            */
/* ------------------------------------------------------------------ */

static void
put_u16_list (gq_wbuf *w, const uint16_t *l, size_t n)
{
  size_t i;

  gq_wbuf_open (w, 2);
  for (i = 0; i < n; i++)
    gq_wbuf_u16 (w, l[i]);
  gq_wbuf_close (w);
}

/* extended_master_secret and an empty renegotiation_info, both sides.  */
static void
put_hardening (gq_wbuf *w)
{
  gq_wbuf_ext_open (w, GQ_EXT12_EXTENDED_MASTER_SECRET);
  gq_wbuf_close (w);
  gq_wbuf_ext_open (w, GQ_EXT12_RENEGOTIATION_INFO);
  gq_wbuf_u8 (w, 0);
  gq_wbuf_close (w);
}

void
gq_tls12_build_client_hello (gq_wbuf *w, const gq_tls12_ch_params *p)
{
  size_t i;

  gq_wbuf_hs_open (w, GQ_HS_CLIENT_HELLO);
  gq_wbuf_u16 (w, p->dtls ? 0xfefd : 0x0303);
  gq_wbuf_bytes (w, p->random, 32);
  gq_wbuf_open (w, 1);
  gq_wbuf_slice (w, p->session_id);
  gq_wbuf_close (w);
  if (p->dtls)
    {
      gq_wbuf_open (w, 1);		/* cookie */
      gq_wbuf_slice (w, p->cookie);
      gq_wbuf_close (w);
    }
  put_u16_list (w, p->suites, p->n_suites);
  gq_wbuf_u8 (w, 1);			/* compression_methods: */
  gq_wbuf_u8 (w, 0);			/* null only.  */

  gq_wbuf_open (w, 2);
  if (p->server_name)
    {
      gq_wbuf_ext_open (w, GQ_EXT_SERVER_NAME);
      gq_wbuf_open (w, 2);
      gq_wbuf_u8 (w, 0);
      gq_wbuf_open (w, 2);
      gq_wbuf_bytes (w, p->server_name, strlen (p->server_name));
      gq_wbuf_close (w);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
    }
  gq_wbuf_ext_open (w, GQ_EXT_SUPPORTED_VERSIONS);
  gq_wbuf_open (w, 1);
  gq_wbuf_u16 (w, p->dtls ? 0xfefd : 0x0303);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
  gq_wbuf_ext_open (w, GQ_EXT_SUPPORTED_GROUPS);
  gq_wbuf_open (w, 2);
  gq_wbuf_u16 (w, GQ_GROUP_SECP256R1);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
  gq_wbuf_ext_open (w, GQ_EXT12_EC_POINT_FORMATS);
  gq_wbuf_open (w, 1);
  gq_wbuf_u8 (w, 0);			/* uncompressed */
  gq_wbuf_close (w);
  gq_wbuf_close (w);
  gq_wbuf_ext_open (w, GQ_EXT_SIGNATURE_ALGORITHMS);
  put_u16_list (w, p->sigalgs, p->n_sigalgs);
  gq_wbuf_close (w);
  if (p->n_cert_sigalgs)
    {
      gq_wbuf_ext_open (w, GQ_EXT12_SIGNATURE_ALGORITHMS_CERT);
      put_u16_list (w, p->cert_sigalgs, p->n_cert_sigalgs);
      gq_wbuf_close (w);
    }
  if (p->n_alpn)
    {
      gq_wbuf_ext_open (w, GQ_EXT_ALPN);
      gq_wbuf_open (w, 2);
      for (i = 0; i < p->n_alpn; i++)
        {
          gq_wbuf_open (w, 1);
          gq_wbuf_slice (w, p->alpn[i]);
          gq_wbuf_close (w);
        }
      gq_wbuf_close (w);
      gq_wbuf_close (w);
    }
  put_hardening (w);
  if (p->have_ticket)
    {
      gq_wbuf_ext_open (w, GQ_EXT12_SESSION_TICKET);
      gq_wbuf_slice (w, p->ticket);
      gq_wbuf_close (w);
    }
  gq_wbuf_close (w);			/* extensions */
  gq_wbuf_close (w);			/* message */
}

void
gq_tls12_build_server_hello (gq_wbuf *w, const gq_tls12_sh_params *p)
{
  gq_wbuf_hs_open (w, GQ_HS_SERVER_HELLO);
  gq_wbuf_u16 (w, p->dtls ? 0xfefd : 0x0303);
  gq_wbuf_bytes (w, p->random, 32);
  gq_wbuf_open (w, 1);
  gq_wbuf_slice (w, p->session_id);
  gq_wbuf_close (w);
  gq_wbuf_u16 (w, p->cipher_suite);
  gq_wbuf_u8 (w, 0);
  gq_wbuf_open (w, 2);
  put_hardening (w);
  if (p->issue_ticket)
    {
      gq_wbuf_ext_open (w, GQ_EXT12_SESSION_TICKET);
      gq_wbuf_close (w);
    }
  if (p->alpn.len)
    {
      gq_wbuf_ext_open (w, GQ_EXT_ALPN);
      gq_wbuf_open (w, 2);
      gq_wbuf_open (w, 1);
      gq_wbuf_slice (w, p->alpn);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
    }
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}

void
gq_tls12_build_certificate (gq_wbuf *w, const gq_slice *chain, size_t n)
{
  size_t i;

  gq_wbuf_hs_open (w, GQ_HS_CERTIFICATE);
  gq_wbuf_open (w, 3);
  for (i = 0; i < n; i++)
    {
      gq_wbuf_open (w, 3);
      gq_wbuf_slice (w, chain[i]);
      gq_wbuf_close (w);
    }
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}

void
gq_tls12_put_ecdh_params (gq_wbuf *w, gq_slice point)
{
  gq_wbuf_u8 (w, GQ_TLS12_CURVE_NAMED);
  gq_wbuf_u16 (w, GQ_GROUP_SECP256R1);
  gq_wbuf_open (w, 1);
  gq_wbuf_slice (w, point);
  gq_wbuf_close (w);
}

void
gq_tls12_build_ske (gq_wbuf *w, gq_slice params, uint16_t scheme,
                    gq_slice signature)
{
  gq_wbuf_hs_open (w, GQ_HS12_SERVER_KEY_EXCHANGE);
  gq_wbuf_slice (w, params);
  gq_wbuf_u16 (w, scheme);
  gq_wbuf_open (w, 2);
  gq_wbuf_slice (w, signature);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}

void
gq_tls12_build_certreq (gq_wbuf *w, const uint16_t *sigalgs, size_t n)
{
  gq_wbuf_hs_open (w, GQ_HS_CERTIFICATE_REQUEST);
  gq_wbuf_u8 (w, 2);			/* certificate_types: */
  gq_wbuf_u8 (w, 1);			/* rsa_sign */
  gq_wbuf_u8 (w, 64);			/* ecdsa_sign */
  put_u16_list (w, sigalgs, n);
  gq_wbuf_u16 (w, 0);			/* no certificate authorities */
  gq_wbuf_close (w);
}

void
gq_tls12_build_server_hello_done (gq_wbuf *w)
{
  gq_wbuf_hs_open (w, GQ_HS12_SERVER_HELLO_DONE);
  gq_wbuf_close (w);
}

void
gq_tls12_build_cke (gq_wbuf *w, gq_slice point)
{
  gq_wbuf_hs_open (w, GQ_HS12_CLIENT_KEY_EXCHANGE);
  gq_wbuf_open (w, 1);
  gq_wbuf_slice (w, point);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}

void
gq_tls12_build_nst (gq_wbuf *w, uint32_t lifetime, gq_slice ticket)
{
  gq_wbuf_hs_open (w, GQ_HS_NEW_SESSION_TICKET);
  gq_wbuf_u32 (w, lifetime);
  gq_wbuf_open (w, 2);
  gq_wbuf_slice (w, ticket);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}

int
gq_tls12_hvr_parse (gq_slice body, uint16_t *version, gq_slice *cookie)
{
  struct rd r = { body.data, body.len };
  unsigned long v;

  TRY (rd_uint (&r, 2, &v));
  *version = (uint16_t) v;
  TRY (rd_vec (&r, 1, cookie));
  TRY (rd_end (&r));
  return cookie->len ? GQ_OK : GQ_ERR_ENCODING;
}

void
gq_tls12_build_hvr (gq_wbuf *w, gq_slice cookie)
{
  gq_wbuf_hs_open (w, GQ_HS12_HELLO_VERIFY_REQUEST);
  gq_wbuf_u16 (w, 0xfefd);
  gq_wbuf_open (w, 1);
  gq_wbuf_slice (w, cookie);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}
