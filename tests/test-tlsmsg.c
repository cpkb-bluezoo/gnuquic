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

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/tlsmsg.h>

#include "tst-util.h"
#include "vectors-tls.h"

#define S(x) ((gq_slice) { (x), sizeof (x) })

static gq_slice
sl (const uint8_t *p, size_t n)
{
  gq_slice s;

  s.data = p;
  s.len = n;
  return s;
}

/* ---- Framing over a whole server flight, in every chunking ---- */

struct flight
{
  unsigned types[16];
  size_t lens[16];
  size_t n;
};

static int
on_msg (void *u, unsigned type, gq_slice msg, gq_slice body)
{
  struct flight *f = u;

  CHECK_EQ (body.len + 4, msg.len);
  CHECK (body.data == msg.data + 4);
  if (f->n < 16)
    {
      f->types[f->n] = type;
      f->lens[f->n] = msg.len;
      f->n++;
    }
  return 0;
}

static size_t
build_flight (uint8_t *out, size_t cap)
{
  const char *msgs[] = { T8448_SERVER_HELLO, T8448_ENCRYPTED_EXTENSIONS,
                         T8448_CERTIFICATE, T8448_CERTIFICATE_VERIFY,
                         T8448_SERVER_FINISHED };
  size_t i, off = 0;

  for (i = 0; i < 5; i++)
    off += tst_unhex (msgs[i], out + off, cap - off);
  return off;
}

static void
test_framing (void)
{
  uint8_t flight[1024], pend[1024];
  size_t n = build_flight (flight, sizeof flight), chunk;
  struct flight whole, split;
  const uint8_t *p = flight;
  size_t l = n;

  memset (&whole, 0, sizeof whole);
  CHECK_EQ (gq_hs_parse (&p, &l, 1 << 16, on_msg, &whole), GQ_OK);
  CHECK_EQ (whole.n, 5);
  CHECK_EQ (whole.types[0], GQ_HS_SERVER_HELLO);
  CHECK_EQ (whole.types[1], GQ_HS_ENCRYPTED_EXTENSIONS);
  CHECK_EQ (whole.types[2], GQ_HS_CERTIFICATE);
  CHECK_EQ (whole.types[3], GQ_HS_CERTIFICATE_VERIFY);
  CHECK_EQ (whole.types[4], GQ_HS_FINISHED);
  CHECK_EQ (whole.lens[0], 90);
  CHECK_EQ (whole.lens[2], 445);

  for (chunk = 1; chunk <= 100; chunk++)
    {
      size_t plen = 0, pos = 0;

      memset (&split, 0, sizeof split);
      while (pos < n)
        {
          size_t take = n - pos < chunk ? n - pos : chunk, used;
          int r;

          memcpy (pend + plen, flight + pos, take);
          plen += take;
          pos += take;
          p = pend;
          l = plen;
          r = gq_hs_parse (&p, &l, 1 << 16, on_msg, &split);
          CHECK (r == GQ_OK || r == GQ_NEED_MORE);
          used = plen - l;
          memmove (pend, pend + used, l);
          plen = l;
        }
      CHECK_EQ (plen, 0);
      CHECK (split.n == whole.n
             && memcmp (split.types, whole.types, sizeof whole.types) == 0
             && memcmp (split.lens, whole.lens, sizeof whole.lens) == 0);
    }

  /* Declared length above the limit is refused from the header alone.  */
  p = flight;
  l = 4;
  CHECK_EQ (gq_hs_parse (&p, &l, 50, on_msg, &split), GQ_ERR_PROTOCOL);
  /* Partial header and partial body are NEED_MORE, consuming nothing.  */
  p = flight;
  l = 3;
  CHECK_EQ (gq_hs_parse (&p, &l, 1 << 16, on_msg, &split), GQ_NEED_MORE);
  CHECK_EQ (l, 3);
}

static void
test_client_hello (void)
{
  uint8_t buf[256];
  size_t n = tst_unhex (T8448_CLIENT_HELLO, buf, sizeof buf), i;
  gq_slice body = sl (buf + 4, n - 4), v, host, groups, list, kx, modes;
  gq_client_hello ch;
  uint16_t group;
  uint8_t pub[32];

  CHECK_EQ (n, 196);
  CHECK_EQ (gq_client_hello_parse (body, &ch), GQ_OK);
  CHECK_EQ (ch.legacy_version, 0x0303);
  CHECK_EQ (ch.session_id.len, 0);
  CHECK_EQ (gq_u16_count (ch.cipher_suites), 3);
  CHECK_EQ (gq_u16_at (ch.cipher_suites, 0), GQ_TLS_AES_128_GCM_SHA256);
  CHECK_EQ (gq_u16_at (ch.cipher_suites, 1), GQ_TLS_CHACHA20_POLY1305_SHA256);
  CHECK_EQ (gq_u16_at (ch.cipher_suites, 2), GQ_TLS_AES_256_GCM_SHA384);
  CHECK (ch.random == buf + 4 + 2);

  CHECK (gq_ext_find (ch.extensions, GQ_EXT_SERVER_NAME, &v));
  CHECK_EQ (gq_ext_server_name (v, &host), GQ_OK);
  CHECK (host.len == 6 && memcmp (host.data, "server", 6) == 0);

  CHECK (gq_ext_find (ch.extensions, GQ_EXT_SUPPORTED_VERSIONS, &v));
  CHECK_EQ (gq_list_u16 (v, 1, &list), GQ_OK);
  CHECK (gq_u16_contains (list, 0x0304));
  CHECK (!gq_u16_contains (list, 0x0303));

  CHECK (gq_ext_find (ch.extensions, GQ_EXT_SUPPORTED_GROUPS, &v));
  CHECK_EQ (gq_list_u16 (v, 2, &groups), GQ_OK);
  CHECK (gq_u16_contains (groups, GQ_GROUP_X25519));
  CHECK (gq_u16_contains (groups, GQ_GROUP_SECP256R1));

  CHECK (gq_ext_find (ch.extensions, GQ_EXT_SIGNATURE_ALGORITHMS, &v));
  CHECK_EQ (gq_list_u16 (v, 2, &list), GQ_OK);
  CHECK_EQ (gq_u16_count (list), 15);
  CHECK_EQ (gq_u16_at (list, 0), 0x0403);

  CHECK (gq_ext_find (ch.extensions, GQ_EXT_KEY_SHARE, &v));
  CHECK_EQ (gq_ext_key_share_client (v, &list), GQ_OK);
  CHECK_EQ (gq_key_share_next (&list, &group, &kx), 1);
  CHECK_EQ (group, GQ_GROUP_X25519);
  tst_unhex (T8448_CLIENT_X25519_PUB, pub, 32);
  CHECK (kx.len == 32 && memcmp (kx.data, pub, 32) == 0);
  CHECK_EQ (gq_key_share_next (&list, &group, &kx), 0);

  CHECK (gq_ext_find (ch.extensions, GQ_EXT_PSK_KEY_EXCHANGE_MODES, &v));
  CHECK_EQ (gq_ext_psk_modes (v, &modes), GQ_OK);
  CHECK (modes.len == 1 && modes.data[0] == GQ_PSK_DHE_KE);

  CHECK (!gq_ext_find (ch.extensions, GQ_EXT_ALPN, &v));
  CHECK (!gq_ext_find (ch.extensions, GQ_EXT_PRE_SHARED_KEY, &v));
  /* Unknown extensions (renegotiation_info 0xff01) are simply skipped.  */
  CHECK (gq_ext_find (ch.extensions, 0xff01, &v));

  /* Truncating the body anywhere inside the extension block is an error,
     and nothing reads out of bounds.  */
  for (i = 4 + 2 + 32 + 1 + 2 + 6 + 2 + 2; i < n - 4; i++)
    CHECK (gq_client_hello_parse (sl (buf + 4, i), &ch) < 0);
  for (i = 0; i < 4 + 2 + 32; i++)
    CHECK (gq_client_hello_parse (sl (buf + 4, i), &ch) < 0);
}

static void
test_hello_errors (void)
{
  uint8_t buf[256], dup[256];
  size_t n = tst_unhex (T8448_CLIENT_HELLO, buf, sizeof buf);
  gq_client_hello ch;
  uint8_t *comp;

  /* Compression method other than null.  */
  memcpy (dup, buf, n);
  comp = dup + 4 + 2 + 32 + 1 + 2 + 6 + 1;	/* After the suites.  */
  CHECK_EQ (comp[-1], 1);			/* compression length */
  comp[0] = 1;
  CHECK_EQ (gq_client_hello_parse (sl (dup + 4, n - 4), &ch), GQ_ERR_PROTOCOL);

  /* Duplicate extension: build a block with the same type twice.  */
  {
    static const uint8_t dupext[] = { 0x00, 0x08, 0x00, 0x2b, 0x00, 0x00,
                                      0x00, 0x2b, 0x00, 0x00 };

    CHECK_EQ (gq_ext_validate (sl (dupext + 2, 8)), GQ_ERR_PROTOCOL);
    CHECK_EQ (gq_ext_validate (sl (dupext + 2, 4)), GQ_OK);
    CHECK_EQ (gq_ext_validate (sl (dupext + 2, 3)), GQ_ERR_ENCODING);
  }

  /* Odd-length cipher suite list.  */
  {
    static const uint8_t bad[] = {
      3, 3,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 3, 0x13, 0x01, 0x00, 1, 0
    };

    CHECK_EQ (gq_client_hello_parse (S (bad), &ch), GQ_ERR_ENCODING);
  }
}

static void
test_server_side_messages (void)
{
  uint8_t sh[128], out[1024], tmp[1024];
  size_t n = tst_unhex (T8448_SERVER_HELLO, sh, sizeof sh), on;
  gq_server_hello s;
  gq_wbuf w;
  gq_sh_params p;
  gq_slice v;
  uint16_t group;
  gq_slice kx;
  uint8_t spub[32];

  CHECK_EQ (n, 90);
  CHECK_EQ (gq_server_hello_parse (sl (sh + 4, n - 4), &s), GQ_OK);
  CHECK_EQ (s.cipher_suite, GQ_TLS_AES_128_GCM_SHA256);
  CHECK_EQ (s.legacy_version, 0x0303);
  CHECK (!s.is_hello_retry_request);
  CHECK_EQ (s.session_id_echo.len, 0);
  CHECK (gq_ext_find (s.extensions, GQ_EXT_SUPPORTED_VERSIONS, &v));
  CHECK_EQ (gq_ext_u16 (v, &group), GQ_OK);
  CHECK_EQ (group, 0x0304);
  CHECK (gq_ext_find (s.extensions, GQ_EXT_KEY_SHARE, &v));
  CHECK_EQ (gq_ext_key_share_server (v, &group, &kx), GQ_OK);
  CHECK_EQ (group, GQ_GROUP_X25519);
  tst_unhex (T8448_SERVER_X25519_PUB, spub, 32);
  CHECK (kx.len == 32 && memcmp (kx.data, spub, 32) == 0);

  /* Rebuilding it gives the RFC's bytes.  */
  memset (&p, 0, sizeof p);
  p.random = s.random;
  p.cipher_suite = s.cipher_suite;
  p.group = GQ_GROUP_X25519;
  p.key_exchange = kx;
  gq_wbuf_init (&w, out, sizeof out);
  gq_build_server_hello (&w, &p);
  CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
  CHECK (w.len == n && memcmp (out, sh, n) == 0);

  /* EncryptedExtensions: parse, rebuild, compare.  */
  {
    uint8_t ee[64];
    size_t en = tst_unhex (T8448_ENCRYPTED_EXTENSIONS, ee, sizeof ee), i = 0;
    gq_slice exts, rest;
    gq_ext list[8];
    unsigned type;

    CHECK_EQ (gq_encrypted_extensions_parse (sl (ee + 4, en - 4), &exts),
              GQ_OK);
    rest = exts;
    while (gq_ext_next (&rest, &type, &list[i].value) == 1)
      list[i++].type = (uint16_t) type;
    CHECK (i >= 2);
    gq_wbuf_init (&w, out, sizeof out);
    gq_build_encrypted_extensions (&w, list, i);
    CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
    CHECK (w.len == en && memcmp (out, ee, en) == 0);
  }

  /* Certificate.  */
  {
    uint8_t c[512];
    size_t cn = tst_unhex (T8448_CERTIFICATE, c, sizeof c);
    gq_slice ctx, entries, der, ex;
    gq_slice certs[1];

    CHECK_EQ (gq_certificate_parse (sl (c + 4, cn - 4), &ctx, &entries), GQ_OK);
    CHECK_EQ (ctx.len, 0);
    CHECK_EQ (gq_cert_entry_next (&entries, &der, &ex), 1);
    CHECK_EQ (der.len, 0x1b0);		/* 4-byte DER header + 0x1ac */
    CHECK (der.data[0] == 0x30 && der.data[1] == 0x82);
    CHECK_EQ (ex.len, 0);
    CHECK_EQ (gq_cert_entry_next (&entries, &der, &ex), 0);
    certs[0] = sl (c + 4 + 4 + 3, 0x1b0);
    CHECK (certs[0].data[0] == 0x30);
    gq_wbuf_init (&w, out, sizeof out);
    gq_build_certificate (&w, ctx, certs, 1);
    CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
    CHECK (w.len == cn && memcmp (out, c, cn) == 0);
  }

  /* CertificateVerify.  */
  {
    uint8_t cv[256];
    size_t cn = tst_unhex (T8448_CERTIFICATE_VERIFY, cv, sizeof cv);
    uint16_t scheme;
    gq_slice sig;

    CHECK_EQ (gq_certificate_verify_parse (sl (cv + 4, cn - 4), &scheme, &sig),
              GQ_OK);
    CHECK_EQ (scheme, GQ_SIG_RSA_PSS_RSAE_SHA256);
    CHECK_EQ (sig.len, 128);
    gq_wbuf_init (&w, out, sizeof out);
    gq_build_certificate_verify (&w, scheme, sig);
    CHECK (w.len == cn && memcmp (out, cv, cn) == 0);
  }

  /* Finished, and the length check.  */
  {
    uint8_t f[64];
    size_t fn = tst_unhex (T8448_SERVER_FINISHED, f, sizeof f);
    gq_slice vd;

    CHECK_EQ (gq_finished_parse (sl (f + 4, fn - 4), 32, &vd), GQ_OK);
    CHECK_EQ (gq_finished_parse (sl (f + 4, fn - 4), 48, &vd), GQ_ERR_ENCODING);
    gq_wbuf_init (&w, out, sizeof out);
    gq_build_finished (&w, vd);
    CHECK (w.len == fn && memcmp (out, f, fn) == 0);
  }

  /* NewSessionTicket.  */
  {
    uint8_t t[256];
    size_t tn = tst_unhex (T8448_NEW_SESSION_TICKET, t, sizeof t), i = 0;
    gq_new_session_ticket nst;
    gq_slice rest;
    gq_ext list[4];
    unsigned type;
    uint32_t max;

    CHECK_EQ (gq_new_session_ticket_parse (sl (t + 4, tn - 4), &nst), GQ_OK);
    CHECK_EQ (nst.lifetime, 0x1e);
    CHECK_EQ (nst.age_add, 0xfad6aac5U);
    CHECK_EQ (nst.nonce.len, 2);
    CHECK (nst.ticket.len > 100);
    rest = nst.extensions;
    while (gq_ext_next (&rest, &type, &list[i].value) == 1)
      list[i++].type = (uint16_t) type;
    CHECK_EQ (i, 1);
    CHECK_EQ (list[0].type, GQ_EXT_EARLY_DATA);
    CHECK_EQ (gq_ext_early_data_nst (list[0].value, &max), GQ_OK);
    CHECK_EQ (max, 0x400U);
    gq_wbuf_init (&w, tmp, sizeof tmp);
    gq_build_new_session_ticket (&w, nst.lifetime, nst.age_add, nst.nonce,
                                 nst.ticket, list, i);
    CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
    CHECK (w.len == tn && memcmp (tmp, t, tn) == 0);
  }
  (void) on;
}

static void
test_hrr_and_key_update (void)
{
  uint8_t out[256];
  gq_wbuf w;
  gq_sh_params p;
  gq_server_hello s;
  gq_slice v, cookie;
  uint16_t g;
  static const uint8_t ck[] = { 1, 2, 3, 4, 5 };
  static const uint8_t sid[] = { 9, 9, 9, 9 };
  int req;

  memset (&p, 0, sizeof p);
  p.hello_retry_request = 1;
  p.session_id_echo = S (sid);
  p.cipher_suite = GQ_TLS_AES_256_GCM_SHA384;
  p.group = GQ_GROUP_SECP256R1;
  p.cookie = S (ck);
  gq_wbuf_init (&w, out, sizeof out);
  gq_build_server_hello (&w, &p);
  CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
  CHECK_EQ (gq_server_hello_parse (sl (out + 4, w.len - 4), &s), GQ_OK);
  CHECK (s.is_hello_retry_request);
  CHECK_EQ (s.session_id_echo.len, 4);
  CHECK_EQ (s.cipher_suite, GQ_TLS_AES_256_GCM_SHA384);
  CHECK (gq_ext_find (s.extensions, GQ_EXT_KEY_SHARE, &v));
  CHECK_EQ (gq_ext_u16 (v, &g), GQ_OK);	/* Group only, no key.  */
  CHECK_EQ (g, GQ_GROUP_SECP256R1);
  CHECK (gq_ext_find (s.extensions, GQ_EXT_COOKIE, &v));
  CHECK_EQ (gq_ext_cookie (v, &cookie), GQ_OK);
  CHECK (cookie.len == 5 && cookie.data[4] == 5);

  /* A normal ServerHello needs a random.  */
  p.hello_retry_request = 0;
  gq_wbuf_init (&w, out, sizeof out);
  gq_build_server_hello (&w, &p);
  CHECK_EQ (gq_wbuf_status (&w), GQ_ERR_INVAL);

  gq_wbuf_init (&w, out, sizeof out);
  gq_build_key_update (&w, 1);
  CHECK_EQ (w.len, 5);
  CHECK_EQ (gq_key_update_parse (sl (out + 4, 1), &req), GQ_OK);
  CHECK_EQ (req, 1);
  out[4] = 2;
  CHECK_EQ (gq_key_update_parse (sl (out + 4, 1), &req), GQ_ERR_PROTOCOL);
}

static void
test_extensions_misc (void)
{
  /* server_name checks.  */
  static const uint8_t ok[] = { 0, 9, 0, 0, 6, 's', 'e', 'r', 'v', 'e', 'r' };
  static const uint8_t ctl[] = { 0, 6, 0, 0, 3, 'a', 0x0a, 'b' };
  static const uint8_t none[] = { 0, 4, 1, 0, 1, 'x' };
  gq_slice host;

  CHECK_EQ (gq_ext_server_name (S (ok), &host), GQ_OK);
  CHECK_EQ (gq_ext_server_name (S (ctl), &host), GQ_ERR_PROTOCOL);
  CHECK_EQ (gq_ext_server_name (S (none), &host), GQ_ERR_PROTOCOL);

  /* ALPN iteration.  */
  {
    static const uint8_t alpn[] = { 0, 9, 2, 'h', '3', 5, 'h', '3', '-', '2', '9' };
    gq_slice list, name;
    int n = 0;

    CHECK_EQ (gq_ext_alpn (sl (alpn, 11), &list), GQ_OK);
    while (gq_alpn_next (&list, &name) == 1)
      n++;
    CHECK_EQ (n, 2);
    CHECK_EQ (gq_ext_alpn (sl (alpn, 10), &list), GQ_ERR_ENCODING);
  }

  /* pre_shared_key: identities, binders, and the truncation point.  */
  {
    uint8_t v[128], *p = v;
    gq_slice ids, binders, id, b;
    const uint8_t *bstart;
    uint32_t age;
    size_t i;

    *p++ = 0; *p++ = 10;			/* identities length */
    *p++ = 0; *p++ = 4; memcpy (p, "tick", 4); p += 4;
    *p++ = 0x01; *p++ = 0x02; *p++ = 0x03; *p++ = 0x04;
    *p++ = 0; *p++ = 33;			/* binders length */
    *p++ = 32;
    for (i = 0; i < 32; i++)
      *p++ = (uint8_t) i;
    CHECK_EQ (gq_ext_psk_client (sl (v, (size_t) (p - v)), &ids, &binders,
                                 &bstart), GQ_OK);
    CHECK (bstart == v + 12);
    CHECK_EQ (gq_psk_identity_next (&ids, &id, &age), 1);
    CHECK (id.len == 4 && memcmp (id.data, "tick", 4) == 0);
    CHECK_EQ (age, 0x01020304U);
    CHECK_EQ (gq_psk_identity_next (&ids, &id, &age), 0);
    CHECK_EQ (gq_psk_binder_next (&binders, &b), 1);
    CHECK_EQ (b.len, 32);
    CHECK_EQ (gq_psk_binder_next (&binders, &b), 0);
  }
}

static void
test_wbuf (void)
{
  uint8_t small[8], big[600];
  gq_wbuf w;
  size_t i;

  gq_wbuf_init (&w, small, sizeof small);
  gq_wbuf_u32 (&w, 1);
  gq_wbuf_u32 (&w, 2);
  CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
  gq_wbuf_u8 (&w, 3);
  CHECK_EQ (gq_wbuf_status (&w), GQ_ERR_BUFSIZE);
  gq_wbuf_u8 (&w, 4);				/* Sticky: still the first.  */
  CHECK_EQ (gq_wbuf_status (&w), GQ_ERR_BUFSIZE);

  /* A vector longer than its prefix allows.  */
  gq_wbuf_init (&w, big, sizeof big);
  gq_wbuf_open (&w, 1);
  for (i = 0; i < 300; i++)
    gq_wbuf_u8 (&w, 0);
  gq_wbuf_close (&w);
  CHECK_EQ (gq_wbuf_status (&w), GQ_ERR_RANGE);

  /* Nesting patches every level; unbalanced use is reported.  */
  gq_wbuf_init (&w, big, sizeof big);
  gq_wbuf_open (&w, 2);
  gq_wbuf_open (&w, 1);
  gq_wbuf_u16 (&w, 0xabcd);
  gq_wbuf_close (&w);
  gq_wbuf_close (&w);
  CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
  CHECK (w.len == 5 && big[0] == 0 && big[1] == 3 && big[2] == 2);
  gq_wbuf_open (&w, 1);
  CHECK_EQ (gq_wbuf_status (&w), GQ_ERR_INVAL);	/* Left open.  */
  gq_wbuf_init (&w, big, sizeof big);
  gq_wbuf_close (&w);
  CHECK_EQ (gq_wbuf_status (&w), GQ_ERR_INVAL);
}

int
main (void)
{
  test_framing ();
  test_client_hello ();
  test_hello_errors ();
  test_server_side_messages ();
  test_hrr_and_key_update ();
  test_extensions_misc ();
  test_wbuf ();
  TST_DONE ();
}
