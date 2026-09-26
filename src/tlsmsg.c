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
#include <gnuquic/tlsmsg.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* SHA-256 of "HelloRetryRequest" (RFC 8446 section 4.1.3).  */
const uint8_t gq_hrr_random[32] = {
  0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
  0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
  0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

/* ------------------------------------------------------------------ */
/* Reading                                                            */
/* ------------------------------------------------------------------ */

struct rd
{
  const uint8_t *p;
  size_t n;
};

static struct rd
rd_of (gq_slice s)
{
  struct rd r;

  r.p = s.data;
  r.n = s.len;
  return r;
}

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
rd_u8 (struct rd *r, unsigned *v)
{
  unsigned long x;

  TRY (rd_uint (r, 1, &x));
  *v = (unsigned) x;
  return GQ_OK;
}

static int
rd_u16 (struct rd *r, unsigned *v)
{
  unsigned long x;

  TRY (rd_uint (r, 2, &x));
  *v = (unsigned) x;
  return GQ_OK;
}

/* Length-prefixed vector with a WIDTH-byte prefix.  */
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

/* ------------------------------------------------------------------ */
/* Framing                                                            */
/* ------------------------------------------------------------------ */

int
gq_hs_parse (const uint8_t **buf, size_t *len, size_t max_body,
             gq_hs_cb cb, void *user)
{
  while (*len > 0)
    {
      const uint8_t *p = *buf;
      size_t n;
      gq_slice msg, body;

      if (*len < 4)
        return GQ_NEED_MORE;
      n = ((size_t) p[1] << 16) | ((size_t) p[2] << 8) | p[3];
      if (n > max_body)
        return GQ_ERR_PROTOCOL;
      if (*len - 4 < n)
        return GQ_NEED_MORE;
      msg.data = p;
      msg.len = 4 + n;
      body.data = p + 4;
      body.len = n;
      *buf = p + 4 + n;
      *len -= 4 + n;
      if (cb && cb (user, p[0], msg, body))
        return GQ_ERR_HANDLER;
    }
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Extensions                                                         */
/* ------------------------------------------------------------------ */

int
gq_ext_next (gq_slice *rest, unsigned *type, gq_slice *value)
{
  struct rd r = rd_of (*rest);

  if (r.n == 0)
    return 0;
  TRY (rd_u16 (&r, type));
  TRY (rd_vec (&r, 2, value));
  rest->data = r.p;
  rest->len = r.n;
  return 1;
}

int
gq_ext_validate (gq_slice exts)
{
  uint16_t seen[128];
  size_t n = 0, i;
  unsigned type;
  gq_slice value, rest = exts;
  int r;

  while ((r = gq_ext_next (&rest, &type, &value)) == 1)
    {
      if (n == 128)
        return GQ_ERR_PROTOCOL;
      for (i = 0; i < n; i++)
        if (seen[i] == type)
          return GQ_ERR_PROTOCOL;
      seen[n++] = (uint16_t) type;
    }
  return r;
}

int
gq_ext_find (gq_slice exts, unsigned type, gq_slice *value)
{
  unsigned t;
  gq_slice v, rest = exts;

  while (gq_ext_next (&rest, &t, &v) == 1)
    if (t == type)
      {
        *value = v;
        return 1;
      }
  return 0;
}

int
gq_list_u16 (gq_slice value, unsigned prefix, gq_slice *list)
{
  struct rd r = rd_of (value);

  TRY (rd_vec (&r, prefix, list));
  TRY (rd_end (&r));
  if (list->len < 2 || list->len % 2)
    return GQ_ERR_ENCODING;
  return GQ_OK;
}

size_t
gq_u16_count (gq_slice list)
{
  return list.len / 2;
}

unsigned
gq_u16_at (gq_slice list, size_t i)
{
  return ((unsigned) list.data[2 * i] << 8) | list.data[2 * i + 1];
}

int
gq_u16_contains (gq_slice list, unsigned v)
{
  size_t i;

  for (i = 0; i < gq_u16_count (list); i++)
    if (gq_u16_at (list, i) == v)
      return 1;
  return 0;
}

int
gq_ext_u16 (gq_slice value, uint16_t *v)
{
  struct rd r = rd_of (value);
  unsigned x;

  TRY (rd_u16 (&r, &x));
  TRY (rd_end (&r));
  *v = (uint16_t) x;
  return GQ_OK;
}

int
gq_ext_psk_modes (gq_slice value, gq_slice *modes)
{
  struct rd r = rd_of (value);

  TRY (rd_vec (&r, 1, modes));
  TRY (rd_end (&r));
  return modes->len ? GQ_OK : GQ_ERR_ENCODING;
}

int
gq_ext_server_name (gq_slice value, gq_slice *host)
{
  struct rd r = rd_of (value), list;
  gq_slice l;

  TRY (rd_vec (&r, 2, &l));
  TRY (rd_end (&r));
  list = rd_of (l);
  while (list.n > 0)
    {
      unsigned type;
      gq_slice name;
      size_t i;

      TRY (rd_u8 (&list, &type));
      TRY (rd_vec (&list, 2, &name));
      if (type != 0)
        continue;
      /* host_name: 1 to 255 printable ASCII bytes, no NUL.  */
      if (name.len < 1 || name.len > 255)
        return GQ_ERR_PROTOCOL;
      for (i = 0; i < name.len; i++)
        if (name.data[i] < 0x21 || name.data[i] > 0x7e)
          return GQ_ERR_PROTOCOL;
      *host = name;
      return GQ_OK;
    }
  return GQ_ERR_PROTOCOL;
}

int
gq_ext_alpn (gq_slice value, gq_slice *protocols)
{
  struct rd r = rd_of (value);

  TRY (rd_vec (&r, 2, protocols));
  TRY (rd_end (&r));
  return protocols->len ? GQ_OK : GQ_ERR_ENCODING;
}

int
gq_alpn_next (gq_slice *protocols, gq_slice *name)
{
  struct rd r = rd_of (*protocols);

  if (r.n == 0)
    return 0;
  TRY (rd_vec (&r, 1, name));
  if (name->len == 0)
    return GQ_ERR_ENCODING;
  protocols->data = r.p;
  protocols->len = r.n;
  return 1;
}

int
gq_ext_key_share_client (gq_slice value, gq_slice *entries)
{
  struct rd r = rd_of (value);

  TRY (rd_vec (&r, 2, entries));
  return rd_end (&r);
}

int
gq_key_share_next (gq_slice *entries, uint16_t *group, gq_slice *kx)
{
  struct rd r = rd_of (*entries);
  unsigned g;

  if (r.n == 0)
    return 0;
  TRY (rd_u16 (&r, &g));
  TRY (rd_vec (&r, 2, kx));
  if (kx->len == 0)
    return GQ_ERR_ENCODING;
  *group = (uint16_t) g;
  entries->data = r.p;
  entries->len = r.n;
  return 1;
}

int
gq_ext_key_share_server (gq_slice value, uint16_t *group, gq_slice *kx)
{
  gq_slice rest = value;
  int r = gq_key_share_next (&rest, group, kx);

  if (r < 0)
    return r;
  return (r == 1 && rest.len == 0) ? GQ_OK : GQ_ERR_ENCODING;
}

int
gq_ext_psk_client (gq_slice value, gq_slice *identities, gq_slice *binders,
                   const uint8_t **binders_start)
{
  struct rd r = rd_of (value);

  TRY (rd_vec (&r, 2, identities));
  *binders_start = r.p;
  TRY (rd_vec (&r, 2, binders));
  TRY (rd_end (&r));
  return (identities->len && binders->len) ? GQ_OK : GQ_ERR_ENCODING;
}

int
gq_psk_identity_next (gq_slice *ids, gq_slice *identity, uint32_t *age)
{
  struct rd r = rd_of (*ids);
  unsigned long a;

  if (r.n == 0)
    return 0;
  TRY (rd_vec (&r, 2, identity));
  TRY (rd_uint (&r, 4, &a));
  if (identity->len == 0)
    return GQ_ERR_ENCODING;
  *age = (uint32_t) a;
  ids->data = r.p;
  ids->len = r.n;
  return 1;
}

int
gq_psk_binder_next (gq_slice *binders, gq_slice *binder)
{
  struct rd r = rd_of (*binders);

  if (r.n == 0)
    return 0;
  TRY (rd_vec (&r, 1, binder));
  if (binder->len < 32)
    return GQ_ERR_ENCODING;
  binders->data = r.p;
  binders->len = r.n;
  return 1;
}

int
gq_ext_cookie (gq_slice value, gq_slice *cookie)
{
  struct rd r = rd_of (value);

  TRY (rd_vec (&r, 2, cookie));
  TRY (rd_end (&r));
  return cookie->len ? GQ_OK : GQ_ERR_ENCODING;
}

int
gq_ext_early_data_nst (gq_slice value, uint32_t *max)
{
  struct rd r = rd_of (value);
  unsigned long v;

  TRY (rd_uint (&r, 4, &v));
  TRY (rd_end (&r));
  *max = (uint32_t) v;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Message bodies                                                     */
/* ------------------------------------------------------------------ */

/* Read the optional trailing extension block of a hello.  */
static int
rd_extensions (struct rd *r, int required, gq_slice *exts)
{
  exts->data = r->p;
  exts->len = 0;
  if (r->n == 0)
    return required ? GQ_ERR_ENCODING : GQ_OK;
  TRY (rd_vec (r, 2, exts));
  TRY (rd_end (r));
  return gq_ext_validate (*exts);
}

int
gq_client_hello_parse (gq_slice body, gq_client_hello *ch)
{
  struct rd r = rd_of (body);
  unsigned v;
  gq_slice random, comp;

  memset (ch, 0, sizeof *ch);
  TRY (rd_u16 (&r, &v));
  ch->legacy_version = (uint16_t) v;
  TRY (rd_bytes (&r, 32, &random));
  ch->random = random.data;
  TRY (rd_vec (&r, 1, &ch->session_id));
  if (ch->session_id.len > 32)
    return GQ_ERR_ENCODING;
  ch->legacy_cookie.data = r.p;
  ch->legacy_cookie.len = 0;
  if (ch->legacy_version == 0xfefd || ch->legacy_version == 0xfeff)
    TRY (rd_vec (&r, 1, &ch->legacy_cookie));
  TRY (rd_vec (&r, 2, &ch->cipher_suites));
  if (ch->cipher_suites.len < 2 || ch->cipher_suites.len % 2)
    return GQ_ERR_ENCODING;
  TRY (rd_vec (&r, 1, &comp));
  if (comp.len != 1 || comp.data[0] != 0)
    return GQ_ERR_PROTOCOL;
  return rd_extensions (&r, 0, &ch->extensions);
}

int
gq_server_hello_parse (gq_slice body, gq_server_hello *sh)
{
  struct rd r = rd_of (body);
  unsigned v, comp;
  gq_slice random;

  memset (sh, 0, sizeof *sh);
  TRY (rd_u16 (&r, &v));
  sh->legacy_version = (uint16_t) v;
  TRY (rd_bytes (&r, 32, &random));
  sh->random = random.data;
  TRY (rd_vec (&r, 1, &sh->session_id_echo));
  if (sh->session_id_echo.len > 32)
    return GQ_ERR_ENCODING;
  TRY (rd_u16 (&r, &v));
  sh->cipher_suite = (uint16_t) v;
  TRY (rd_u8 (&r, &comp));
  if (comp != 0)
    return GQ_ERR_PROTOCOL;
  sh->is_hello_retry_request = memcmp (sh->random, gq_hrr_random, 32) == 0;
  return rd_extensions (&r, 1, &sh->extensions);
}

int
gq_encrypted_extensions_parse (gq_slice body, gq_slice *exts)
{
  struct rd r = rd_of (body);

  TRY (rd_vec (&r, 2, exts));
  TRY (rd_end (&r));
  return gq_ext_validate (*exts);
}

int
gq_certificate_parse (gq_slice body, gq_slice *context, gq_slice *entries)
{
  struct rd r = rd_of (body);

  TRY (rd_vec (&r, 1, context));
  TRY (rd_vec (&r, 3, entries));
  return rd_end (&r);
}

int
gq_cert_entry_next (gq_slice *entries, gq_slice *cert, gq_slice *exts)
{
  struct rd r = rd_of (*entries);

  if (r.n == 0)
    return 0;
  TRY (rd_vec (&r, 3, cert));
  TRY (rd_vec (&r, 2, exts));
  if (cert->len == 0)
    return GQ_ERR_ENCODING;
  TRY (gq_ext_validate (*exts));
  entries->data = r.p;
  entries->len = r.n;
  return 1;
}

int
gq_certificate_request_parse (gq_slice body, gq_slice *context,
                              gq_slice *exts)
{
  struct rd r = rd_of (body);

  TRY (rd_vec (&r, 1, context));
  TRY (rd_vec (&r, 2, exts));
  TRY (rd_end (&r));
  return gq_ext_validate (*exts);
}

int
gq_certificate_verify_parse (gq_slice body, uint16_t *scheme, gq_slice *sig)
{
  struct rd r = rd_of (body);
  unsigned s;

  TRY (rd_u16 (&r, &s));
  TRY (rd_vec (&r, 2, sig));
  TRY (rd_end (&r));
  *scheme = (uint16_t) s;
  return GQ_OK;
}

int
gq_finished_parse (gq_slice body, size_t hash_len, gq_slice *verify)
{
  if (body.len != hash_len)
    return GQ_ERR_ENCODING;
  *verify = body;
  return GQ_OK;
}

int
gq_new_session_ticket_parse (gq_slice body, gq_new_session_ticket *n)
{
  struct rd r = rd_of (body);
  unsigned long v;

  memset (n, 0, sizeof *n);
  TRY (rd_uint (&r, 4, &v));
  n->lifetime = (uint32_t) v;
  TRY (rd_uint (&r, 4, &v));
  n->age_add = (uint32_t) v;
  TRY (rd_vec (&r, 1, &n->nonce));
  TRY (rd_vec (&r, 2, &n->ticket));
  TRY (rd_vec (&r, 2, &n->extensions));
  TRY (rd_end (&r));
  if (n->ticket.len == 0)
    return GQ_ERR_ENCODING;
  if (n->lifetime > 604800)	/* Seven days (RFC 8446 section 4.6.1).  */
    return GQ_ERR_PROTOCOL;
  return gq_ext_validate (n->extensions);
}

int
gq_key_update_parse (gq_slice body, int *request)
{
  struct rd r = rd_of (body);
  unsigned v;

  TRY (rd_u8 (&r, &v));
  TRY (rd_end (&r));
  if (v > 1)
    return GQ_ERR_PROTOCOL;
  *request = (int) v;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Writing                                                            */
/* ------------------------------------------------------------------ */

static void
wfail (gq_wbuf *w, int err)
{
  if (w->err == GQ_OK)
    w->err = err;
}

void
gq_wbuf_init (gq_wbuf *w, uint8_t *buf, size_t cap)
{
  memset (w, 0, sizeof *w);
  w->p = buf;
  w->cap = cap;
}

void
gq_wbuf_bytes (gq_wbuf *w, const void *src, size_t n)
{
  if (w->err)
    return;
  if (w->cap - w->len < n)
    {
      wfail (w, GQ_ERR_BUFSIZE);
      return;
    }
  if (n)
    memcpy (w->p + w->len, src, n);
  w->len += n;
}

static void
wuint (gq_wbuf *w, unsigned width, unsigned long v)
{
  uint8_t b[4];
  unsigned i;

  for (i = 0; i < width; i++)
    b[i] = (uint8_t) (v >> (8 * (width - 1 - i)));
  gq_wbuf_bytes (w, b, width);
}

void gq_wbuf_u8 (gq_wbuf *w, unsigned v) { wuint (w, 1, v); }
void gq_wbuf_u16 (gq_wbuf *w, unsigned v) { wuint (w, 2, v); }
void gq_wbuf_u24 (gq_wbuf *w, unsigned long v) { wuint (w, 3, v); }
void gq_wbuf_u32 (gq_wbuf *w, uint32_t v) { wuint (w, 4, v); }

void
gq_wbuf_slice (gq_wbuf *w, gq_slice s)
{
  gq_wbuf_bytes (w, s.data, s.len);
}

void
gq_wbuf_open (gq_wbuf *w, unsigned width)
{
  if (w->err)
    return;
  if (width < 1 || width > 3 || w->depth >= GQ_WBUF_DEPTH)
    {
      wfail (w, GQ_ERR_INVAL);
      return;
    }
  w->mark[w->depth] = w->len;
  w->width[w->depth] = (unsigned char) width;
  w->depth++;
  wuint (w, width, 0);
}

void
gq_wbuf_close (gq_wbuf *w)
{
  size_t start, n, max;
  unsigned width, i;

  if (w->err)
    return;
  if (w->depth == 0)
    {
      wfail (w, GQ_ERR_INVAL);
      return;
    }
  w->depth--;
  width = w->width[w->depth];
  start = w->mark[w->depth];
  n = w->len - start - width;
  max = ((size_t) 1 << (8 * width)) - 1;
  if (n > max)
    {
      wfail (w, GQ_ERR_RANGE);
      return;
    }
  for (i = 0; i < width; i++)
    w->p[start + i] = (uint8_t) (n >> (8 * (width - 1 - i)));
}

void
gq_wbuf_ext_open (gq_wbuf *w, unsigned type)
{
  gq_wbuf_u16 (w, type);
  gq_wbuf_open (w, 2);
}

void
gq_wbuf_hs_open (gq_wbuf *w, unsigned type)
{
  gq_wbuf_u8 (w, type);
  gq_wbuf_open (w, 3);
}

int
gq_wbuf_status (const gq_wbuf *w)
{
  if (w->err)
    return w->err;
  return w->depth == 0 ? GQ_OK : GQ_ERR_INVAL;
}

static void
put_exts (gq_wbuf *w, const gq_ext *exts, size_t n)
{
  size_t i;

  gq_wbuf_open (w, 2);
  for (i = 0; i < n; i++)
    {
      gq_wbuf_ext_open (w, exts[i].type);
      gq_wbuf_slice (w, exts[i].value);
      gq_wbuf_close (w);
    }
  gq_wbuf_close (w);
}

void
gq_build_server_hello (gq_wbuf *w, const gq_sh_params *p)
{
  if (!p->hello_retry_request && p->random == NULL)
    {
      wfail (w, GQ_ERR_INVAL);
      return;
    }
  gq_wbuf_hs_open (w, GQ_HS_SERVER_HELLO);
  gq_wbuf_u16 (w, p->dtls ? 0xfefd : 0x0303);	/* legacy_version */
  gq_wbuf_bytes (w, p->hello_retry_request ? gq_hrr_random : p->random, 32);
  gq_wbuf_open (w, 1);
  gq_wbuf_slice (w, p->session_id_echo);
  gq_wbuf_close (w);
  gq_wbuf_u16 (w, p->cipher_suite);
  gq_wbuf_u8 (w, 0);				/* compression */
  gq_wbuf_open (w, 2);
  if (p->group)
    {
      gq_wbuf_ext_open (w, GQ_EXT_KEY_SHARE);
      gq_wbuf_u16 (w, p->group);
      if (!p->hello_retry_request)
        {
          gq_wbuf_open (w, 2);
          gq_wbuf_slice (w, p->key_exchange);
          gq_wbuf_close (w);
        }
      gq_wbuf_close (w);
    }
  gq_wbuf_ext_open (w, GQ_EXT_SUPPORTED_VERSIONS);
  gq_wbuf_u16 (w, p->dtls ? 0xfefc : 0x0304);
  gq_wbuf_close (w);
  if (p->hello_retry_request && p->cookie.len)
    {
      gq_wbuf_ext_open (w, GQ_EXT_COOKIE);
      gq_wbuf_open (w, 2);
      gq_wbuf_slice (w, p->cookie);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
    }
  if (!p->hello_retry_request && p->psk_selected)
    {
      gq_wbuf_ext_open (w, GQ_EXT_PRE_SHARED_KEY);
      gq_wbuf_u16 (w, p->psk_identity);
      gq_wbuf_close (w);
    }
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}

void
gq_build_encrypted_extensions (gq_wbuf *w, const gq_ext *exts, size_t n)
{
  gq_wbuf_hs_open (w, GQ_HS_ENCRYPTED_EXTENSIONS);
  put_exts (w, exts, n);
  gq_wbuf_close (w);
}

void
gq_build_certificate (gq_wbuf *w, gq_slice context, const gq_slice *certs,
                      size_t n)
{
  size_t i;

  gq_wbuf_hs_open (w, GQ_HS_CERTIFICATE);
  gq_wbuf_open (w, 1);
  gq_wbuf_slice (w, context);
  gq_wbuf_close (w);
  gq_wbuf_open (w, 3);
  for (i = 0; i < n; i++)
    {
      gq_wbuf_open (w, 3);
      gq_wbuf_slice (w, certs[i]);
      gq_wbuf_close (w);
      gq_wbuf_open (w, 2);		/* No per-certificate extensions.  */
      gq_wbuf_close (w);
    }
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}

void
gq_build_certificate_verify (gq_wbuf *w, uint16_t scheme, gq_slice sig)
{
  gq_wbuf_hs_open (w, GQ_HS_CERTIFICATE_VERIFY);
  gq_wbuf_u16 (w, scheme);
  gq_wbuf_open (w, 2);
  gq_wbuf_slice (w, sig);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}

void
gq_build_finished (gq_wbuf *w, gq_slice verify)
{
  gq_wbuf_hs_open (w, GQ_HS_FINISHED);
  gq_wbuf_slice (w, verify);
  gq_wbuf_close (w);
}

void
gq_build_new_session_ticket (gq_wbuf *w, uint32_t lifetime, uint32_t age_add,
                             gq_slice nonce, gq_slice ticket,
                             const gq_ext *exts, size_t n)
{
  gq_wbuf_hs_open (w, GQ_HS_NEW_SESSION_TICKET);
  gq_wbuf_u32 (w, lifetime);
  gq_wbuf_u32 (w, age_add);
  gq_wbuf_open (w, 1);
  gq_wbuf_slice (w, nonce);
  gq_wbuf_close (w);
  gq_wbuf_open (w, 2);
  gq_wbuf_slice (w, ticket);
  gq_wbuf_close (w);
  put_exts (w, exts, n);
  gq_wbuf_close (w);
}

void
gq_build_key_update (gq_wbuf *w, int request_update)
{
  gq_wbuf_hs_open (w, GQ_HS_KEY_UPDATE);
  gq_wbuf_u8 (w, request_update ? 1 : 0);
  gq_wbuf_close (w);
}
