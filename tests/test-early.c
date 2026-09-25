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
#include <gnuquic/record.h>
#include <gnuquic/replay.h>
#include <gnuquic/keysched.h>

#include "tst-util.h"
#include "vectors-resume.h"

/* ---- Replay cache ---- */

static void
id_of (uint8_t id[32], unsigned n)
{
  memset (id, 0, 32);
  id[0] = (uint8_t) (n * 37);		/* Spread over the table.  */
  id[1] = (uint8_t) (n >> 8);
  id[2] = (uint8_t) n;
  id[7] = (uint8_t) (n * 11);
}

static void
test_replay_cache (void)
{
  gq_replay_cache *c;
  uint8_t id[32];
  unsigned i;

  CHECK_EQ (gq_replay_cache_new (&c, 0), GQ_ERR_INVAL);
  CHECK_EQ (gq_replay_cache_new (&c, 100), GQ_OK);

  /* First use passes, second does not.  */
  id_of (id, 1);
  CHECK (gq_replay_cache_check (c, id, 10000, 1000));
  CHECK (!gq_replay_cache_check (c, id, 10000, 1001));
  CHECK_EQ (gq_replay_cache_size (c), 1);
  id_of (id, 2);
  CHECK (gq_replay_cache_check (c, id, 10000, 1002));

  /* An already-expired ticket cannot carry early data.  */
  id_of (id, 3);
  CHECK (!gq_replay_cache_check (c, id, 1000, 2000));
  CHECK (!gq_replay_cache_check (c, id, 2000, 2000));

  /* After the ticket expires its slot is free again (a new ticket with
     the same id could not exist, but the slot is reused).  */
  id_of (id, 1);
  CHECK (gq_replay_cache_check (c, id, 30000, 20000));

  /* Capacity: fills, then fails closed rather than forgetting.  */
  gq_replay_cache_free (c);
  CHECK_EQ (gq_replay_cache_new (&c, 10), GQ_OK);
  for (i = 100; i < 110; i++)
    {
      id_of (id, i);
      CHECK (gq_replay_cache_check (c, id, 90000, 21000));
    }
  id_of (id, 999);
  CHECK (!gq_replay_cache_check (c, id, 90000, 21000));
  /* Everything already recorded is still remembered.  */
  id_of (id, 100);
  CHECK (!gq_replay_cache_check (c, id, 90000, 21000));
  /* Once entries expire there is room again.  */
  id_of (id, 999);
  CHECK (gq_replay_cache_check (c, id, 200000, 100000));
  gq_replay_cache_free (c);
  gq_replay_cache_free (NULL);
}

/* ---- RFC 8448 section 4: an accepted 0-RTT exchange ---- */

struct got
{
  unsigned type;
  size_t len;
  uint8_t d[16];
};

static int
got_cb (void *u, unsigned type, const uint8_t *d, size_t len)
{
  struct got *g = u;

  g->type = type;
  g->len = len;
  memcpy (g->d, d, len < sizeof g->d ? len : sizeof g->d);
  return 0;
}

static void
test_rfc8448_early_record (void)
{
  uint8_t secret[32], payload[16], want[64], out[64];
  size_t pn = tst_unhex (R8448_EARLY_PAYLOAD, payload, sizeof payload);
  size_t wn = tst_unhex (R8448_EARLY_RECORD, want, sizeof want), n;
  uint8_t key[16], iv[12];
  gq_record w, r;
  uint8_t in[64];
  uint8_t *p = in;
  size_t l = wn;

  tst_unhex (R8448_CLIENT_EARLY_TRAFFIC, secret, 32);
  CHECK_EQ (gq_traffic_keys (GQ_AEAD_AES_128_GCM, secret, key, iv), GQ_OK);
  CHECK (tst_eq_hex (key, 16, R8448_EARLY_KEY));
  CHECK (tst_eq_hex (iv, 12, R8448_EARLY_IV));

  /* The early application data record, byte for byte.  */
  gq_record_init (&w);
  CHECK_EQ (gq_record_set_keys (&w, GQ_DIR_WRITE, GQ_AEAD_AES_128_GCM,
                                secret, 32), GQ_OK);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, payload, pn, 0,
                               out, sizeof out, &n), GQ_OK);
  CHECK (n == wn && memcmp (out, want, wn) == 0);
  gq_record_init (&r);
  CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_AES_128_GCM, secret,
                                32), GQ_OK);
  memcpy (in, want, wn);
  {
    struct got got = { 0, 0, { 0 } };

    CHECK_EQ (gq_record_receive (&r, &p, &l, got_cb, &got), GQ_OK);
    CHECK (got.type == GQ_CT_APPLICATION_DATA && got.len == pn
           && memcmp (got.d, payload, pn) == 0);
  }
}

/* ---- The server engine on the RFC's early-data ClientHello ---- */

struct log
{
  uint8_t sent[4][4096];
  size_t sent_len[4];
  gq_tls_secret secrets[8];
  int n_secrets;
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
  struct log *l = u;

  l->secrets[l->n_secrets++] = *s;
  return 0;
}

static int
l_alert (void *u, unsigned code)
{
  ((struct log *) u)->alert = (int) code;
  return 0;
}

struct env
{
  uint64_t now;
  uint64_t created;
  uint32_t max_early;
  const char *alpn;
  gq_replay_cache *cache;
};

static uint64_t
now_hook (void *u)
{
  return ((struct env *) u)->now;
}

static int
lookup_psk (void *u, const uint8_t *id, size_t len, gq_session_state *s)
{
  struct env *e = u;

  (void) id; (void) len;
  memset (s, 0, sizeof *s);
  s->cipher_suite = GQ_TLS_AES_128_GCM_SHA256;
  tst_unhex (R8448_PSK, s->psk, 32);
  s->psk_len = 32;
  s->created_ms = e->created;
  s->age_add = 0xfad6aac5U;		/* From the NewSessionTicket of section 3.  */
  s->lifetime = 30;
  s->max_early_data = e->max_early;
  s->server_name_len = 0;
  s->alpn_len = strlen (e->alpn);
  memcpy (s->alpn, e->alpn, s->alpn_len);
  return 0;
}

static const gq_tls_credentials *
no_credentials (void *u, const char *name)
{
  (void) u; (void) name;
  return NULL;
}

static int
early_check (void *u, const uint8_t id[32], uint64_t exp, uint64_t now)
{
  return gq_replay_cache_check (u, id, exp, now);
}

static const gq_tls_secret *
find_secret (const struct log *l, enum gq_level lv, enum gq_dir d)
{
  int i;

  for (i = 0; i < l->n_secrets; i++)
    if (l->secrets[i].level == lv && l->secrets[i].dir == d)
      return &l->secrets[i];
  return NULL;
}

static int
run_server (struct env *e, const uint8_t *ch, size_t n, struct log *lg,
            uint32_t server_max, int with_replay, gq_tls **out)
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
  cfg.psk_user = e;
  cfg.hooks.now_ms = now_hook;
  cfg.hooks.user = e;
  cfg.max_early_data = server_max;
  if (with_replay)
    {
      cfg.replay_check = early_check;
      cfg.replay_user = e->cache;
    }
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
  int ee_has_early;
};

static int
scan (void *u, unsigned type, gq_slice m, gq_slice b)
{
  struct types *ty = u;
  gq_slice exts, v;

  (void) m;
  if (ty->n < 8)
    ty->t[ty->n++] = type;
  if (type == GQ_HS_ENCRYPTED_EXTENSIONS
      && gq_encrypted_extensions_parse (b, &exts) == GQ_OK
      && gq_ext_find (exts, GQ_EXT_EARLY_DATA, &v))
    ty->ee_has_early = 1;
  return 0;
}

static void
inspect (const struct log *l, struct types *ty)
{
  const uint8_t *p = l->sent[GQ_LEVEL_HANDSHAKE];
  size_t n = l->sent_len[GQ_LEVEL_HANDSHAKE];

  memset (ty, 0, sizeof *ty);
  CHECK_EQ (gq_hs_parse (&p, &n, 1 << 16, scan, ty), GQ_OK);
}

static void
test_server_on_rfc_early_data (void)
{
  uint8_t ch[600];
  size_t n = tst_unhex (R8448_CLIENT_HELLO, ch, sizeof ch);
  /* The client's ticket age is 6 ms (0xfad6aacb - age_add).  */
  struct env e = { 5000000, 5000000 - 6, 1024, "", NULL };
  struct log lg;
  gq_tls *t = NULL;
  const gq_tls_secret *early, *hsr;
  struct types ty;
  uint8_t sec[32];

  CHECK_EQ (gq_replay_cache_new (&e.cache, 16), GQ_OK);

  /* Accepted: the early read key is exactly the RFC's client early
     traffic secret, EncryptedExtensions carries early_data, and the
     handshake read keys wait for EndOfEarlyData.  */
  CHECK_EQ (run_server (&e, ch, n, &lg, 1024, 1, &t), GQ_OK);
  early = find_secret (&lg, GQ_LEVEL_EARLY, GQ_DIR_READ);
  CHECK (early != NULL);
  if (early)
    {
      CHECK (tst_eq_hex (early->secret, early->len, R8448_CLIENT_EARLY_TRAFFIC));
      CHECK_EQ (early->aead, GQ_AEAD_AES_128_GCM);
    }
  CHECK (find_secret (&lg, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE) != NULL);
  CHECK (find_secret (&lg, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ) == NULL);
  inspect (&lg, &ty);
  CHECK (ty.ee_has_early);
  CHECK (gq_tls_early_data_accepted (t));
  CHECK (!gq_tls_early_data_offered (t));

  /* EndOfEarlyData releases the handshake read keys.  */
  {
    static const uint8_t eoed[4] = { GQ_HS_END_OF_EARLY_DATA, 0, 0, 0 };
    const uint8_t *p = eoed;
    size_t l = 4;

    CHECK_EQ (gq_tls_feed (t, GQ_LEVEL_EARLY, &p, &l), GQ_OK);
  }
  hsr = find_secret (&lg, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ);
  CHECK (hsr != NULL);
  (void) sec;

  /* The same ClientHello again is a replay: resumption still works, but
     the early data is refused (the cache remembers the ticket).  */
  gq_tls_free (t);
  CHECK_EQ (run_server (&e, ch, n, &lg, 1024, 1, &t), GQ_OK);
  CHECK (find_secret (&lg, GQ_LEVEL_EARLY, GQ_DIR_READ) == NULL);
  CHECK (find_secret (&lg, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ) != NULL);
  inspect (&lg, &ty);
  CHECK (!ty.ee_has_early);
  CHECK (ty.n == 2);			/* Still resumed: EE and Finished.  */
  CHECK (!gq_tls_early_data_accepted (t));
  CHECK (gq_tls_early_data_offered (t));	/* Declined: skip early records.  */
  gq_tls_free (t);
  gq_replay_cache_free (e.cache);

  /* Each other condition also declines the early data, but not the
     resumption.  A fresh cache each time so replay is not the reason.  */
#define DECLINED(label, setup, smax, replay) \
  do { \
    struct env e2 = e; \
    CHECK_EQ (gq_replay_cache_new (&e2.cache, 16), GQ_OK); \
    setup; \
    CHECK_EQ (run_server (&e2, ch, n, &lg, smax, replay, &t), GQ_OK); \
    CHECK (find_secret (&lg, GQ_LEVEL_EARLY, GQ_DIR_READ) == NULL); \
    inspect (&lg, &ty); \
    CHECK (ty.n == 2 && !ty.ee_has_early); \
    if (find_secret (&lg, GQ_LEVEL_EARLY, GQ_DIR_READ)) \
      fprintf (stderr, "not declined: %s\n", label); \
    gq_tls_free (t); \
    gq_replay_cache_free (e2.cache); \
  } while (0)

  e.now = 5000000;
  e.created = 5000000 - 6;
  e.max_early = 1024;
  e.alpn = "";
  DECLINED ("server early disabled", (void) 0, 0, 1);
  DECLINED ("no replay protection configured", (void) 0, 1024, 0);
  DECLINED ("ticket allows none", e2.max_early = 0, 1024, 1);
  /* Older than the 10 s window but inside the 30 s ticket lifetime.  */
  DECLINED ("ticket age too far off", e2.now += 20000, 1024, 1);
  DECLINED ("ALPN differs from the original", e2.alpn = "h2", 1024, 1);
}

int
main (void)
{
  CHECK_EQ (gq_crypto_init (), GQ_OK);
  test_replay_cache ();
  test_rfc8448_early_record ();
  test_server_on_rfc_early_data ();
  TST_DONE ();
}
