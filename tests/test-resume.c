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
#include <gnuquic/tls.h>
#include <gnuquic/tlsmsg.h>
#include <gnuquic/keysched.h>
#include <gnuquic/transcript.h>

#include "tst-util.h"
#include "vectors-resume.h"

/* The 0-RTT trace has the ClientHello of a resumed session: check the PSK
   parts of the key schedule and the binder against the RFC, byte for
   byte.  */
static void
test_rfc8448_key_schedule (void)
{
  uint8_t ch[600], trunc_ch[600], sh[128], psk[32], out[32], bk[32], th[32], binder[32];
  uint8_t shared[32], chh[32], hsh[32], tmp[32], c[32], s[32];
  size_t n = tst_unhex (R8448_CLIENT_HELLO, ch, sizeof ch);
  size_t shn = tst_unhex (R8448_SERVER_HELLO, sh, sizeof sh), trunc;
  gq_ks ks;
  gq_client_hello chi;
  gq_slice v, ids, binders, id, bl;
  const uint8_t *bstart;
  uint32_t age;
  gq_transcript *t;

  CHECK_EQ (n, 512);		/* 477 bytes plus the 35-byte binders list.  */
  CHECK_EQ (tst_unhex (R8448_CLIENT_HELLO_TRUNC, trunc_ch, sizeof trunc_ch), 477);
  CHECK (memcmp (ch, trunc_ch, 477) == 0);
  tst_unhex (R8448_PSK, psk, 32);

  /* Early secret from the PSK, binder key, finished key.  */
  CHECK_EQ (gq_ks_early (&ks, GQ_HASH_SHA256, psk, 32), GQ_OK);
  CHECK (tst_eq_hex (ks.secret, 32, R8448_EARLY_SECRET));
  CHECK_EQ (gq_ks_binder_key (&ks, 1, bk), GQ_OK);
  CHECK (tst_eq_hex (bk, 32, R8448_BINDER_KEY));
  CHECK_EQ (gq_finished_key (GQ_HASH_SHA256, bk, out), GQ_OK);
  CHECK (tst_eq_hex (out, 32, R8448_BINDER_FINISHED_KEY));

  /* The pre_shared_key extension of the real ClientHello.  */
  CHECK_EQ (gq_client_hello_parse ((gq_slice) { ch + 4, n - 4 }, &chi), GQ_OK);
  CHECK (gq_ext_find (chi.extensions, GQ_EXT_PRE_SHARED_KEY, &v));
  CHECK_EQ (gq_ext_psk_client (v, &ids, &binders, &bstart), GQ_OK);
  CHECK_EQ (gq_psk_identity_next (&ids, &id, &age), 1);
  CHECK_EQ (id.len, 0xb2);
  CHECK_EQ (gq_psk_identity_next (&ids, &id, &age), 0);
  CHECK_EQ (gq_psk_binder_next (&binders, &bl), 1);
  CHECK (tst_eq_hex (bl.data, bl.len, R8448_BINDER));
  CHECK_EQ (gq_psk_binder_next (&binders, &bl), 0);

  /* The binder is over the ClientHello up to the binders list, which is
     35 bytes (2 + 1 + 32) at the end.  */
  trunc = (size_t) (bstart - ch);
  CHECK_EQ (trunc, 477);
  CHECK_EQ (n - trunc, 35);
  CHECK_EQ (gq_hash_compute (GQ_HASH_SHA256, ch, trunc, th, 32), GQ_OK);
  CHECK (tst_eq_hex (th, 32, R8448_BINDER_HASH));
  CHECK_EQ (gq_finished_verify_data (GQ_HASH_SHA256, bk, th, binder), GQ_OK);
  CHECK (tst_eq_hex (binder, 32, R8448_BINDER));

  /* Early traffic secret from the whole ClientHello.  */
  CHECK_EQ (gq_hash_compute (GQ_HASH_SHA256, ch, n, chh, 32), GQ_OK);
  CHECK (tst_eq_hex (chh, 32, R8448_CH_HASH));
  CHECK_EQ (gq_ks_client_early_traffic (&ks, chh, out), GQ_OK);
  CHECK (tst_eq_hex (out, 32, R8448_CLIENT_EARLY_TRAFFIC));

  /* Handshake, master and application secrets on top of the PSK.  */
  tst_unhex (R8448_SHARED_SECRET, shared, 32);
  CHECK_EQ (gq_ks_handshake (&ks, shared, 32), GQ_OK);
  CHECK (tst_eq_hex (ks.secret, 32, R8448_HANDSHAKE_SECRET));
  CHECK_EQ (gq_transcript_new (&t, GQ_HASH_SHA256), GQ_OK);
  CHECK_EQ (gq_transcript_update (t, ch, n), GQ_OK);
  CHECK_EQ (gq_transcript_update (t, sh, shn), GQ_OK);
  CHECK_EQ (gq_transcript_hash (t, hsh, 32), GQ_OK);
  gq_transcript_free (t);
  CHECK (tst_eq_hex (hsh, 32, R8448_HASH_CH_SH));
  CHECK_EQ (gq_ks_handshake_traffic (&ks, hsh, c, s), GQ_OK);
  CHECK (tst_eq_hex (c, 32, R8448_CLIENT_HS_TRAFFIC));
  CHECK (tst_eq_hex (s, 32, R8448_SERVER_HS_TRAFFIC));
  CHECK_EQ (gq_ks_master (&ks), GQ_OK);
  CHECK (tst_eq_hex (ks.secret, 32, R8448_MASTER_SECRET));
  tst_unhex (R8448_HASH_CH_SFIN, tmp, 32);
  CHECK_EQ (gq_ks_app_traffic (&ks, tmp, c, s), GQ_OK);
  CHECK (tst_eq_hex (c, 32, R8448_CLIENT_AP_TRAFFIC));
  CHECK (tst_eq_hex (s, 32, R8448_SERVER_AP_TRAFFIC));
  CHECK_EQ (gq_ks_exporter_master (&ks, tmp, out), GQ_OK);
  CHECK (tst_eq_hex (out, 32, R8448_EXPORTER_MASTER));
  tst_unhex (R8448_HASH_CH_CFIN, tmp, 32);
  CHECK_EQ (gq_ks_resumption_master (&ks, tmp, out), GQ_OK);
  CHECK (tst_eq_hex (out, 32, R8448_RESUMPTION_MASTER));
}

/* ---- The server engine on the RFC's ClientHello ---- */

struct log
{
  uint8_t sent[4][4096];
  size_t sent_len[4];
  int alert;
};

static int
l_send (void *u, enum gq_level lv, const uint8_t *d, size_t n)
{
  struct log *l = u;

  memcpy (l->sent[lv] + l->sent_len[lv], d, n);
  l->sent_len[lv] += n;
  return 0;
}

static int
l_secret (void *u, const gq_tls_secret *s)
{
  (void) u; (void) s;
  return 0;
}

static int
l_alert (void *u, unsigned code)
{
  ((struct log *) u)->alert = (int) code;
  return 0;
}

struct lookup
{
  uint64_t now;
  uint64_t created;
  const char *name;		/* Session's SNI binding, or "".  */
  uint16_t suite;
  int known;
};

static uint64_t
now_hook (void *u)
{
  return ((struct lookup *) u)->now;
}

static int
lookup_psk (void *u, const uint8_t *id, size_t len, gq_session_state *s)
{
  struct lookup *l = u;

  (void) id; (void) len;
  if (!l->known)
    return 1;
  memset (s, 0, sizeof *s);
  s->cipher_suite = l->suite;
  tst_unhex (R8448_PSK, s->psk, 32);
  s->psk_len = 32;
  s->created_ms = l->created;
  s->lifetime = 604800;
  s->server_name_len = strlen (l->name);
  memcpy (s->server_name, l->name, s->server_name_len);
  return 0;
}

static const gq_tls_credentials *
no_credentials (void *u, const char *name)
{
  (void) u; (void) name;
  return NULL;			/* A full handshake cannot be served.  */
}

/* Feed the RFC ClientHello to a server that finds the RFC's PSK.  */
static int
run_server (struct lookup *lk, const uint8_t *ch, size_t n, struct log *lg,
            const uint16_t *suites, size_t n_suites, gq_tls **out)
{
  gq_tls *t;
  gq_tls_server_config cfg;
  gq_tls_sink sink;
  const uint8_t *p = ch;
  size_t l = n;
  int r;

  memset (&cfg, 0, sizeof cfg);
  memset (&sink, 0, sizeof sink);
  cfg.select_credentials = no_credentials;
  cfg.psk_lookup = lookup_psk;
  cfg.psk_user = lk;
  cfg.hooks.now_ms = now_hook;
  cfg.hooks.user = lk;
  cfg.suites = suites;
  cfg.n_suites = n_suites;
  sink.user = lg;
  sink.send = l_send;
  sink.secret = l_secret;
  sink.alert = l_alert;
  memset (lg, 0, sizeof *lg);
  lg->alert = -1;
  CHECK_EQ (gq_tls_server_new (&t, &cfg, &sink), GQ_OK);
  r = gq_tls_feed (t, GQ_LEVEL_INITIAL, &p, &l);
  if (out)
    *out = t;
  else
    gq_tls_free (t);
  return r;
}

struct types
{
  unsigned t[8];
  int n;
};

static int
collect_type (void *u, unsigned type, gq_slice m, gq_slice b)
{
  struct types *ty = u;

  (void) m; (void) b;
  if (ty->n < 8)
    ty->t[ty->n++] = type;
  return 0;
}

static void
test_server_on_rfc_client_hello (void)
{
  uint8_t ch[600], bad[600];
  size_t n = tst_unhex (R8448_CLIENT_HELLO, ch, sizeof ch);
  struct lookup lk = { 1000000 + 5000, 1000000, "", GQ_TLS_AES_128_GCM_SHA256, 1 };
  struct log lg;
  gq_tls *t = NULL;
  gq_server_hello sh;
  gq_slice v;
  uint16_t sel;
  static const uint16_t chacha_only[] = { GQ_TLS_CHACHA20_POLY1305_SHA256 };
  struct types ty;
  const uint8_t *p;
  size_t l;

  /* The binder verifies against the RFC's own value: the server accepts
     the PSK, answers with a ServerHello selecting it, and sends only
     EncryptedExtensions and Finished (no certificate).  */
  CHECK_EQ (run_server (&lk, ch, n, &lg, NULL, 0, &t), GQ_OK);
  CHECK_EQ (lg.alert, -1);
  CHECK (lg.sent_len[GQ_LEVEL_INITIAL] > 4);
  CHECK_EQ (gq_server_hello_parse ((gq_slice) { lg.sent[GQ_LEVEL_INITIAL] + 4,
                                                lg.sent_len[GQ_LEVEL_INITIAL] - 4 },
                                   &sh), GQ_OK);
  CHECK_EQ (sh.cipher_suite, GQ_TLS_AES_128_GCM_SHA256);
  CHECK (gq_ext_find (sh.extensions, GQ_EXT_PRE_SHARED_KEY, &v));
  CHECK_EQ (gq_ext_u16 (v, &sel), GQ_OK);
  CHECK_EQ (sel, 0);
  memset (&ty, 0, sizeof ty);
  p = lg.sent[GQ_LEVEL_HANDSHAKE];
  l = lg.sent_len[GQ_LEVEL_HANDSHAKE];
  CHECK_EQ (gq_hs_parse (&p, &l, 1 << 16, collect_type, &ty), GQ_OK);
  CHECK (ty.n == 2 && ty.t[0] == GQ_HS_ENCRYPTED_EXTENSIONS
         && ty.t[1] == GQ_HS_FINISHED);
  /* The client asked for 0-RTT (early_data); this engine declines it.  */
  CHECK (gq_tls_early_data_offered (t));
  gq_tls_free (t);

  /* Any change to the binder, or to the bytes it covers, is fatal.  */
  memcpy (bad, ch, n);
  bad[n - 1] ^= 1;
  CHECK_EQ (run_server (&lk, bad, n, &lg, NULL, 0, NULL), GQ_ERR_CRYPTO);
  CHECK_EQ (lg.alert, GQ_ALERT_DECRYPT_ERROR);
  memcpy (bad, ch, n);
  bad[12] ^= 1;				/* Inside the client random.  */
  CHECK_EQ (run_server (&lk, bad, n, &lg, NULL, 0, NULL), GQ_ERR_CRYPTO);
  CHECK_EQ (lg.alert, GQ_ALERT_DECRYPT_ERROR);

  /* Anything that makes the PSK unacceptable falls back to a full
     handshake, which this server cannot do (no credentials): that shows
     as unrecognized_name, proving the PSK path was refused.  */
  lk.known = 0;
  CHECK_EQ (run_server (&lk, ch, n, &lg, NULL, 0, NULL), GQ_ERR_PROTOCOL);
  CHECK_EQ (lg.alert, 112);
  lk.known = 1;
  lk.now = 1000000 + 8u * 86400 * 1000;			/* Expired.  */
  CHECK_EQ (run_server (&lk, ch, n, &lg, NULL, 0, NULL), GQ_ERR_PROTOCOL);
  CHECK_EQ (lg.alert, 112);
  lk.now = 1000000 + 5000;
  lk.name = "some-other-name";				/* Bound elsewhere.  */
  CHECK_EQ (run_server (&lk, ch, n, &lg, NULL, 0, NULL), GQ_ERR_PROTOCOL);
  CHECK_EQ (lg.alert, 112);
  lk.name = "";
  CHECK_EQ (run_server (&lk, ch, n, &lg, chacha_only, 1, NULL),
            GQ_ERR_PROTOCOL);			/* Suite no longer allowed.  */
  CHECK_EQ (lg.alert, 112);
  lk.name = "server";					/* The trace's SNI.  */
  CHECK_EQ (run_server (&lk, ch, n, &lg, NULL, 0, NULL), GQ_OK);
}

/* Sessions can be stored, serialized and restored.  */
static void
test_session_storage (void)
{
  static gq_tls_session a, b;
  gq_tls_ticket tk;
  uint8_t buf[GQ_TICKET_MAX + 128], ticket[300];
  size_t n, i;

  for (i = 0; i < sizeof ticket; i++)
    ticket[i] = (uint8_t) i;
  memset (&tk, 0, sizeof tk);
  tk.ticket = (gq_slice) { ticket, sizeof ticket };
  tk.cipher_suite = GQ_TLS_AES_256_GCM_SHA384;
  tk.hash = GQ_HASH_SHA384;
  tk.psk_len = 48;
  memset (tk.psk, 0x77, 48);
  tk.lifetime = 3600;
  tk.age_add = 0xdeadbeef;
  tk.max_early_data = 16384;
  tk.received_ms = UINT64_C (0x0102030405060708);

  CHECK_EQ (gq_tls_session_store (&a, &tk), GQ_OK);
  CHECK_EQ (gq_tls_session_serialize (&a, buf, sizeof buf, &n), GQ_OK);
  CHECK_EQ (gq_tls_session_deserialize (&b, buf, n), GQ_OK);
  CHECK (memcmp (&a, &b, sizeof a) == 0);
  CHECK (b.received_ms == UINT64_C (0x0102030405060708) && b.age_add == 0xdeadbeefU);

  /* Malformed encodings are rejected, never trusted.  */
  for (i = 0; i < n; i++)
    CHECK (gq_tls_session_deserialize (&b, buf, i) != GQ_OK);
  buf[0] ^= 1;
  CHECK_EQ (gq_tls_session_deserialize (&b, buf, n), GQ_ERR_ENCODING);
  buf[0] ^= 1;
  buf[4] = 0x99;			/* Unknown suite.  */
  CHECK_EQ (gq_tls_session_deserialize (&b, buf, n), GQ_ERR_ENCODING);

  /* An oversized server ticket cannot be stored.  */
  {
    static uint8_t huge[GQ_TICKET_MAX + 1];

    tk.ticket = (gq_slice) { huge, sizeof huge };
    CHECK_EQ (gq_tls_session_store (&a, &tk), GQ_ERR_BUFSIZE);
  }
  gq_tls_session_wipe (&a);
  CHECK (a.ticket_len == 0 && a.psk[0] == 0);
}

int
main (void)
{
  CHECK_EQ (gq_crypto_init (), GQ_OK);
  test_rfc8448_key_schedule ();
  test_server_on_rfc_client_hello ();
  test_session_storage ();
  TST_DONE ();
}
