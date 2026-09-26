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
#include <time.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/crypto.h>
#include <gnuquic/transcript.h>
#include <gnuquic/tlsmsg.h>
#include <gnuquic/tls.h>
#include <gnuquic/tls12.h>
#include <gnuquic/tls12msg.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

#include "tls_int.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

uint64_t
gqi_now_ms (const gq_tls *t)
{
  if (t->cfg.hooks.now_ms)
    return t->cfg.hooks.now_ms (t->cfg.hooks.user);
  return (uint64_t) time (NULL) * 1000;
}

int
gqi_fail (gq_tls *t, unsigned alert, int status)
{
  if (t->st != ST_FAILED)
    {
      t->st = ST_FAILED;
      t->alert = (int) alert;
      if (t->sink.alert)
        t->sink.alert (t->sink.user, alert);
    }
  return status;
}

/* Alert for a codec status.  */
int
gqi_fail_parse (gq_tls *t, int status)
{
  return gqi_fail (t, status == GQ_ERR_ENCODING ? GQ_ALERT_DECODE_ERROR
                                            : GQ_ALERT_ILLEGAL_PARAMETER,
               status < 0 ? status : GQ_ERR_PROTOCOL);
}

int
gqi_suite_params (unsigned suite, enum gq_aead *aead, enum gq_hash *hash)
{
  switch (suite)
    {
    case GQ_TLS_AES_128_GCM_SHA256:
      *aead = GQ_AEAD_AES_128_GCM; *hash = GQ_HASH_SHA256; return 1;
    case GQ_TLS_AES_256_GCM_SHA384:
      *aead = GQ_AEAD_AES_256_GCM; *hash = GQ_HASH_SHA384; return 1;
    case GQ_TLS_CHACHA20_POLY1305_SHA256:
      *aead = GQ_AEAD_CHACHA20_POLY1305; *hash = GQ_HASH_SHA256; return 1;
    default:
      return 0;
    }
}

int
gqi_rnd (gq_tls *t, void *buf, size_t n)
{
  if (t->cfg.hooks.random)
    return t->cfg.hooks.random (t->cfg.hooks.user, buf, n) ? GQ_ERR_CRYPTO
                                                            : GQ_OK;
  return gq_random (buf, n);
}

int
gqi_emit (gq_tls *t, enum gq_level level, const uint8_t *data, size_t len)
{
  if (t->sink.send (t->sink.user, level, data, len))
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
  return GQ_OK;
}

int
gqi_emit_secret (gq_tls *t, enum gq_level level, enum gq_dir dir,
             const uint8_t *secret)
{
  gq_tls_secret s;
  int r;

  memset (&s, 0, sizeof s);
  s.level = level;
  s.dir = dir;
  s.aead = t->aead;
  s.hash = t->hash;
  s.len = t->hlen;
  memcpy (s.secret, secret, t->hlen);
  r = t->sink.secret (t->sink.user, &s);
  gq_wipe (&s, sizeof s);
  return r ? gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER) : GQ_OK;
}

/* As gqi_emit_secret, for a secret of a suite other than the one negotiated
   (yet): the early traffic secret comes from the resumed session's suite.  */
int
gqi_emit_secret_as (gq_tls *t, enum gq_level level, enum gq_dir dir,
                    enum gq_aead aead, enum gq_hash hash,
                    const uint8_t *secret)
{
  gq_tls_secret s;
  int r;

  memset (&s, 0, sizeof s);
  s.level = level;
  s.dir = dir;
  s.aead = aead;
  s.hash = hash;
  s.len = gq_hash_size (hash);
  memcpy (s.secret, secret, s.len);
  r = t->sink.secret (t->sink.user, &s);
  gq_wipe (&s, sizeof s);
  return r ? gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER) : GQ_OK;
}

/* Feed a message to the transcript(s) in use.  */
int
gqi_tr_update (gq_tls *t, gq_slice msg)
{
  if (t->tr)
    return gq_transcript_update (t->tr, msg.data, msg.len);
  TRY (gq_transcript_update (t->t256, msg.data, msg.len));
  return gq_transcript_update (t->t384, msg.data, msg.len);
}

int
gqi_tr_hash (gq_tls *t, uint8_t *out)
{
  return gq_transcript_hash (t->tr, out, t->hlen);
}

int
gqi_in_list (const uint16_t *l, size_t n, unsigned v)
{
  size_t i;

  for (i = 0; i < n; i++)
    if (l[i] == v)
      return 1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Creation                                                           */
/* ------------------------------------------------------------------ */

static void
filter_list (uint16_t *dst, size_t *n, size_t cap, const uint16_t *src,
             size_t ns, int (*ok) (unsigned))
{
  size_t i;

  *n = 0;
  for (i = 0; i < ns && *n < cap; i++)
    if (ok (src[i]) && !gqi_in_list (dst, *n, src[i]))
      dst[(*n)++] = src[i];
}

static int
ok_suite (unsigned s)
{
  return gq_policy_allows_suite (GQ_TLS_1_3, s);
}

static int
ok_sig (unsigned s)
{
  return gq_policy_allows_sigscheme (GQ_TLS_1_3, s)
    && gq_sigscheme_available (s);
}

/* Apply policy filtering (and defaults) to the preference lists.  */
void
gqi_filter_lists (gq_tls *t, const uint16_t *suites, size_t n_suites,
                  const uint16_t *groups, size_t n_groups,
                  const uint16_t *sigs, size_t n_sigs)
{
  const uint16_t *l;
  size_t n;

  l = suites ? suites : gq_policy_default_suites (GQ_TLS_1_3, &n);
  n = suites ? n_suites : n;
  filter_list (t->suites, &t->n_suites, MAX_SUITES, l, n, ok_suite);
  l = groups ? groups : gq_policy_default_groups (&n);
  n = groups ? n_groups : n;
  filter_list (t->groups, &t->n_groups, MAX_GROUPS, l, n,
               gq_policy_allows_group);
  l = sigs ? sigs : gq_policy_default_sigschemes (&n);
  n = sigs ? n_sigs : n;
  filter_list (t->sigs, &t->n_sigs, MAX_SIGS, l, n, ok_sig);
}

int
gq_tls_client_new (gq_tls **out, const gq_tls_config *cfg,
                   const gq_tls_sink *sink)
{
  gq_tls *t;

  if (out == NULL || cfg == NULL || sink == NULL || sink->send == NULL
      || sink->secret == NULL)
    return GQ_ERR_INVAL;
  /* Refuse to run unauthenticated by accident.  */
  if (cfg->trust == NULL && sink->verify_peer == NULL)
    return GQ_ERR_INVAL;
  if (cfg->server_name && strlen (cfg->server_name) > 255)
    return GQ_ERR_INVAL;
  if ((cfg->quic || cfg->transport_params)
      && (cfg->transport_params == NULL || cfg->n_alpn == 0))
    return GQ_ERR_INVAL;
  /* DTLS 1.3 has no 0-RTT here and is not QUIC.  */
  if (cfg->dtls && (cfg->quic || cfg->transport_params || cfg->early_data))
    return GQ_ERR_INVAL;
  if (cfg->n_alpn && cfg->alpn == NULL)
    return GQ_ERR_INVAL;
  TRY (gq_crypto_init ());

  t = calloc (1, sizeof *t);
  if (t == NULL)
    return GQ_ERR_NOMEM;
  t->role = ROLE_CLIENT;
  t->cfg = *cfg;
  t->sink = *sink;
  t->quic = cfg->quic || cfg->transport_params != NULL;
  t->dtls = cfg->dtls != 0;
  t->alert = -1;
  if (t->cfg.max_message_len == 0)
    t->cfg.max_message_len = 65536;

  if (cfg->also_tls12)
    {
      if (cfg->quic || cfg->transport_params
          || gq_tls12_client_offer (cfg, t->suites12, &t->n_suites12,
                                    t->sigs12, &t->n_sigs12) != GQ_OK)
        {
          free (t);
          return GQ_ERR_INVAL;
        }
    }
  gqi_filter_lists (t, cfg->suites, cfg->n_suites, cfg->groups, cfg->n_groups,
                    cfg->sigschemes, cfg->n_sigschemes);
  if (t->n_suites == 0 || t->n_groups == 0 || t->n_sigs == 0)
    {
      free (t);
      return GQ_ERR_INVAL;
    }
  if (gq_transcript_new (&t->t256, GQ_HASH_SHA256) != GQ_OK
      || gq_transcript_new (&t->t384, GQ_HASH_SHA384) != GQ_OK)
    {
      gq_tls_free (t);
      return GQ_ERR_NOMEM;
    }
  t->st = ST_NEW;
  *out = t;
  return GQ_OK;
}

void
gq_tls_free (gq_tls *t)
{
  if (t == NULL)
    return;
  gq_transcript_free (t->t256);
  gq_transcript_free (t->t384);
  gq_pubkey_free (t->peer_key);
  if (t->msg)
    {
      gq_wipe (t->msg, t->msg_cap);
      free (t->msg);
    }
  gq_wipe (t, sizeof *t);
  free (t);
}

/* ------------------------------------------------------------------ */
/* ClientHello                                                        */
/* ------------------------------------------------------------------ */

static int
is_hybrid (unsigned g)
{
  return g == GQ_GROUP_X25519_MLKEM768 || g == GQ_GROUP_SECP256R1_MLKEM768
    || g == GQ_GROUP_SECP384R1_MLKEM1024;
}

static int
gen_kx (gq_tls *t, unsigned group, gq_kx_key *key)
{
  if (t->cfg.hooks.kx_generate)
    return t->cfg.hooks.kx_generate (t->cfg.hooks.user, group, key)
      ? GQ_ERR_CRYPTO : GQ_OK;
  return gq_kx_generate (group, key);
}

/* Legacy RSA PKCS#1 schemes are advertised only for certificate
   signatures (signature_algorithms_cert), never for CertificateVerify,
   so servers with common RSA chains can still answer.  */
static const uint16_t cert_only_sigs[] = { 0x0401, 0x0501, 0x0601 };

static void
put_ch (gq_tls *t, gq_wbuf *w, int second, size_t *binders_off)
{
  size_t i, nshares = second ? (t->n_kx ? 1 : 0) : t->n_kx;
  static const uint8_t zeros[GQ_MAX_HASH_LEN];

  gq_wbuf_hs_open (w, GQ_HS_CLIENT_HELLO);
  gq_wbuf_u16 (w, t->dtls ? 0xfefd : 0x0303);
  gq_wbuf_bytes (w, t->random, 32);
  gq_wbuf_open (w, 1);
  gq_wbuf_bytes (w, t->sid, t->sid_len);
  gq_wbuf_close (w);
  if (t->dtls)			/* legacy_cookie: always empty (RFC 9147 5.3).  */
    gq_wbuf_u8 (w, 0);
  gq_wbuf_open (w, 2);
  for (i = 0; i < t->n_suites; i++)
    gq_wbuf_u16 (w, t->suites[i]);
  for (i = 0; i < t->n_suites12; i++)
    gq_wbuf_u16 (w, t->suites12[i]);
  gq_wbuf_close (w);
  gq_wbuf_open (w, 1);
  gq_wbuf_u8 (w, 0);
  gq_wbuf_close (w);

  gq_wbuf_open (w, 2);
  if (t->dtls && second && t->cookie_len)
    {
      /* First, so that it is in the first fragment of a fragmented hello
         (see dtlscookie.h).  */
      gq_wbuf_ext_open (w, GQ_EXT_COOKIE);
      gq_wbuf_open (w, 2);
      gq_wbuf_bytes (w, t->cookie, t->cookie_len);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
    }
  if (t->cfg.server_name)
    {
      gq_wbuf_ext_open (w, GQ_EXT_SERVER_NAME);
      gq_wbuf_open (w, 2);
      gq_wbuf_u8 (w, 0);
      gq_wbuf_open (w, 2);
      gq_wbuf_bytes (w, t->cfg.server_name, strlen (t->cfg.server_name));
      gq_wbuf_close (w);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
    }
  gq_wbuf_ext_open (w, GQ_EXT_SUPPORTED_GROUPS);
  gq_wbuf_open (w, 2);
  for (i = 0; i < t->n_groups; i++)
    gq_wbuf_u16 (w, t->groups[i]);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
  gq_wbuf_ext_open (w, GQ_EXT_SIGNATURE_ALGORITHMS);
  gq_wbuf_open (w, 2);
  for (i = 0; i < t->n_sigs; i++)
    gq_wbuf_u16 (w, t->sigs[i]);
  /* Also what a TLS 1.2 server may sign its key exchange with.  */
  for (i = 0; i < t->n_sigs12; i++)
    {
      size_t k;
      int dup = 0;

      for (k = 0; k < t->n_sigs; k++)
        dup |= t->sigs[k] == t->sigs12[i];
      if (!dup)
        gq_wbuf_u16 (w, t->sigs12[i]);
    }
  gq_wbuf_close (w);
  gq_wbuf_close (w);
  gq_wbuf_ext_open (w, 50);			/* signature_algorithms_cert */
  gq_wbuf_open (w, 2);
  for (i = 0; i < t->n_sigs; i++)
    gq_wbuf_u16 (w, t->sigs[i]);
  for (i = 0; i < sizeof cert_only_sigs / sizeof cert_only_sigs[0]; i++)
    gq_wbuf_u16 (w, cert_only_sigs[i]);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
  gq_wbuf_ext_open (w, GQ_EXT_SUPPORTED_VERSIONS);
  gq_wbuf_open (w, 1);
  gq_wbuf_u16 (w, t->dtls ? 0xfefc : 0x0304);
  if (t->n_suites12)
    gq_wbuf_u16 (w, t->dtls ? 0xfefd : 0x0303);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
  gq_wbuf_ext_open (w, GQ_EXT_KEY_SHARE);
  gq_wbuf_open (w, 2);
  for (i = 0; i < nshares; i++)
    {
      gq_wbuf_u16 (w, t->kx[i].group);
      gq_wbuf_open (w, 2);
      gq_wbuf_bytes (w, t->kx[i].share, t->kx[i].share_len);
      gq_wbuf_close (w);
    }
  gq_wbuf_close (w);
  gq_wbuf_close (w);
  if (t->cfg.n_alpn)
    {
      gq_wbuf_ext_open (w, GQ_EXT_ALPN);
      gq_wbuf_open (w, 2);
      for (i = 0; i < t->cfg.n_alpn; i++)
        {
          gq_wbuf_open (w, 1);
          gq_wbuf_slice (w, t->cfg.alpn[i]);
          gq_wbuf_close (w);
        }
      gq_wbuf_close (w);
      gq_wbuf_close (w);
    }
  if (t->n_suites12)
    {
      /* The TLS 1.2 profile's hardening extensions (extended master secret,
         secure renegotiation indication), the point format and the empty
         ticket request, which a TLS 1.2 server answers.  A TLS 1.3 server
         ignores all of them.  */
      gq_wbuf_ext_open (w, GQ_EXT12_EXTENDED_MASTER_SECRET);
      gq_wbuf_close (w);
      gq_wbuf_ext_open (w, GQ_EXT12_RENEGOTIATION_INFO);
      gq_wbuf_u8 (w, 0);
      gq_wbuf_close (w);
      gq_wbuf_ext_open (w, GQ_EXT12_EC_POINT_FORMATS);
      gq_wbuf_open (w, 1);
      gq_wbuf_u8 (w, 0);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
      gq_wbuf_ext_open (w, GQ_EXT12_SESSION_TICKET);
      gq_wbuf_close (w);
    }
  if (t->quic)
    {
      gq_wbuf_ext_open (w, GQ_EXT_QUIC_TRANSPORT_PARAMETERS);
      gq_wbuf_bytes (w, t->cfg.transport_params, t->cfg.transport_params_len);
      gq_wbuf_close (w);
    }
  if (second && t->cookie_len && !t->dtls)
    {
      gq_wbuf_ext_open (w, GQ_EXT_COOKIE);
      gq_wbuf_open (w, 2);
      gq_wbuf_bytes (w, t->cookie, t->cookie_len);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
    }
  /* Always say we accept tickets (psk_dhe_ke), so a server may issue them
     even on a first connection.  pre_shared_key, if we have a session to
     resume, must come last; its binder is a placeholder here and is filled
     in once the rest of the message is final.  */
  gq_wbuf_ext_open (w, GQ_EXT_PSK_KEY_EXCHANGE_MODES);
  gq_wbuf_open (w, 1);
  gq_wbuf_u8 (w, GQ_PSK_DHE_KE);
  gq_wbuf_close (w);
  gq_wbuf_close (w);
  if (t->early_offered && !second)
    {
      gq_wbuf_ext_open (w, GQ_EXT_EARLY_DATA);	/* Empty; before the PSK.  */
      gq_wbuf_close (w);
    }
  if (t->offered)
    {
      const gq_tls_session *r = t->offered;
      uint64_t now = gqi_now_ms (t);
      uint32_t age = (uint32_t) ((now > r->received_ms ? now - r->received_ms
                                                       : 0) + r->age_add);

      gq_wbuf_ext_open (w, GQ_EXT_PRE_SHARED_KEY);
      gq_wbuf_open (w, 2);			/* identities */
      gq_wbuf_open (w, 2);
      gq_wbuf_bytes (w, r->ticket, r->ticket_len);
      gq_wbuf_close (w);
      gq_wbuf_u32 (w, age);
      gq_wbuf_close (w);
      *binders_off = w->len;
      gq_wbuf_open (w, 2);			/* binders */
      gq_wbuf_open (w, 1);
      gq_wbuf_bytes (w, zeros, r->psk_len);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
      gq_wbuf_close (w);
    }
  gq_wbuf_close (w);
  gq_wbuf_close (w);
}

/* Compute the PSK binder over the ClientHello truncated before the binders
   (RFC 8446 section 4.2.11.2) and write it over the placeholder.  After a
   HelloRetryRequest the transcript so far (message_hash and the retry) is
   part of the input.  */
static int
fill_binder (gq_tls *t, uint8_t *buf, size_t len, size_t boff, int second)
{
  const gq_tls_session *s = t->offered;
  size_t hl = s->psk_len;
  gq_transcript *tmp = NULL;
  uint8_t th[GQ_MAX_HASH_LEN], bk[GQ_MAX_HASH_LEN];
  gq_ks ks;
  int r;

  r = second ? gq_transcript_copy (t->tr, &tmp)
             : gq_transcript_new (&tmp, s->hash);
  if (r == GQ_OK)
    r = gq_transcript_update (tmp, buf, boff);
  if (r == GQ_OK)
    r = gq_transcript_hash (tmp, th, hl);
  gq_transcript_free (tmp);
  if (r == GQ_OK)
    r = gq_ks_early_v (&ks, s->hash, s->psk, hl, t->dtls);
  if (r == GQ_OK)
    r = gq_ks_binder_key (&ks, 1, bk);
  if (r == GQ_OK)
    r = gq_finished_verify_data_v (s->hash, t->dtls, bk, th, buf + len - hl);
  gq_wipe (bk, sizeof bk);
  gq_ks_wipe (&ks);
  return r;
}

/* Build the ClientHello, send it and hash it.  */
static int
send_ch (gq_tls *t, int second)
{
  uint8_t *buf = malloc (CH_BUF);
  gq_wbuf w;
  size_t binders_off = 0;
  int r;

  if (buf == NULL)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  gq_wbuf_init (&w, buf, CH_BUF);
  put_ch (t, &w, second, &binders_off);
  r = gq_wbuf_status (&w);
  if (r == GQ_OK && t->offered)
    r = fill_binder (t, buf, w.len, binders_off, second);
  if (r == GQ_OK)
    r = gqi_emit (t, GQ_LEVEL_INITIAL, buf, w.len);
  if (r == GQ_OK)
    {
      gq_slice m = { buf, w.len };

      r = gqi_tr_update (t, m);
      if (r != GQ_OK)
        r = gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
    }
  else if (t->st != ST_FAILED)
    r = gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
  /* 0-RTT: the early traffic secret comes from the PSK and the hash of
     this very ClientHello (RFC 8446 section 7.1); the transport may start
     sending early data right away.  */
  if (r == GQ_OK && !second && t->early_offered)
    {
      const gq_tls_session *o = t->offered;
      enum gq_aead a;
      enum gq_hash h;
      uint8_t th[GQ_MAX_HASH_LEN], sec[GQ_MAX_HASH_LEN];
      gq_ks ks;

      gqi_suite_params (o->cipher_suite, &a, &h);
      r = gq_hash_compute (h, buf, w.len, th, o->psk_len);
      if (r == GQ_OK)
        r = gq_ks_early_v (&ks, h, o->psk, o->psk_len, t->dtls);
      if (r == GQ_OK)
        r = gq_ks_client_early_traffic (&ks, th, sec);
      if (r == GQ_OK)
        r = gqi_emit_secret_as (t, GQ_LEVEL_EARLY, GQ_DIR_WRITE, a, h, sec);
      gq_wipe (sec, sizeof sec);
      gq_ks_wipe (&ks);
      if (r != GQ_OK && t->st != ST_FAILED)
        r = gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
    }
  free (buf);
  return r;
}

int
gq_tls_start (gq_tls *t)
{
  size_t i, want;
  unsigned first;

  if (t == NULL || t->st != ST_NEW || t->role != ROLE_CLIENT)
    return GQ_ERR_INVAL;

  TRY (gqi_rnd (t, t->random, 32));
  if (!t->quic && !t->dtls)
    {
      /* Compatibility session ID for middleboxes (RFC 8446 appendix D.4).
         QUIC and DTLS send an empty one.  */
      t->sid_len = 32;
      TRY (gqi_rnd (t, t->sid, 32));
    }

  /* One key share for the preferred group; if that is a hybrid, add a
     plain-curve share too so a server without post-quantum support does
     not force a HelloRetryRequest.  */
  first = t->groups[0];
  if (t->dtls && is_hybrid (first))
    {
      /* A big first hello would need several datagrams, which a server
         answering statelessly (dtlscookie.h) cannot judge.  Offer one
         small share; a server that wants the hybrid group asks for it in
         its HelloRetryRequest, which the cookie exchange needs anyway.  */
      for (i = 0; i < t->n_groups; i++)
        if (!is_hybrid (t->groups[i])
            && (first == t->groups[0] || t->groups[i] == GQ_GROUP_X25519))
          first = t->groups[i];
    }
  if (t->dtls && is_hybrid (first))
    t->n_kx = 0;	/* Only hybrids: no share yet, let the server ask.  */
  else
    {
      TRY (gen_kx (t, first, &t->kx[0]));
      t->n_kx = 1;
    }
  if (is_hybrid (first) && !t->dtls)
    {
      want = 0;
      for (i = 0; i < t->n_groups; i++)
        if (!is_hybrid (t->groups[i])
            && (want == 0 || t->groups[i] == GQ_GROUP_X25519))
          want = t->groups[i];
      if (want)
        {
          TRY (gen_kx (t, want, &t->kx[1]));
          t->n_kx = 2;
        }
    }
  if (t->cfg.resume)
    {
      const gq_tls_session *r = t->cfg.resume;
      enum gq_aead a;
      enum gq_hash h;
      uint64_t now = gqi_now_ms (t);

      /* Offer only a usable, unexpired session for a suite we offer.  */
      if (r->ticket_len > 0 && r->ticket_len <= GQ_TICKET_MAX
          && gqi_suite_params (r->cipher_suite, &a, &h) && h == r->hash
          && r->psk_len == gq_hash_size (h)
          && gqi_in_list (t->suites, t->n_suites, r->cipher_suite)
          && now >= r->received_ms
          && now - r->received_ms <= (uint64_t) r->lifetime * 1000)
        t->offered = r;
    }
  /* Early data: only if asked for, the session allows it, and we will
     offer the protocol it was established with (RFC 8446 section 4.2.10).  */
  if (t->offered && t->cfg.early_data && t->offered->max_early_data > 0)
    {
      size_t k;
      int alpn_ok = t->offered->alpn_len == 0;

      for (k = 0; k < t->cfg.n_alpn && !alpn_ok; k++)
        alpn_ok = t->cfg.alpn[k].len == t->offered->alpn_len
          && memcmp (t->cfg.alpn[k].data, t->offered->alpn,
                     t->offered->alpn_len) == 0;
      t->early_offered = alpn_ok;
    }
  t->st = ST_WAIT_SH;
  return send_ch (t, 0);
}

/* ------------------------------------------------------------------ */
/* ServerHello and HelloRetryRequest                                  */
/* ------------------------------------------------------------------ */

static int
select_transcript (gq_tls *t)
{
  if (t->hash == GQ_HASH_SHA256)
    {
      t->tr = t->t256;
      t->t256 = NULL;
      gq_transcript_free (t->t384);
      t->t384 = NULL;
    }
  else
    {
      t->tr = t->t384;
      t->t384 = NULL;
      gq_transcript_free (t->t256);
      t->t256 = NULL;
    }
  return GQ_OK;
}

static int
on_hrr (gq_tls *t, gq_slice msg, const gq_server_hello *sh)
{
  gq_slice v, rest = sh->extensions;
  unsigned type;
  uint16_t group = 0, ver = 0;
  int have_ks = 0, have_ver = 0;
  gq_kx_key nk;
  size_t i;

  if (t->hrr_seen)
    return gqi_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
  t->hrr_seen = 1;
  t->hrr_suite = sh->cipher_suite;
  if (!gqi_in_list (t->suites, t->n_suites, sh->cipher_suite)
      || !gqi_suite_params (sh->cipher_suite, &t->aead, &t->hash))
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  t->suite = sh->cipher_suite;
  t->hlen = gq_hash_size (t->hash);
  /* A PSK is only usable with the hash of its own suite.  */
  if (t->offered && t->offered->hash != t->hash)
    t->offered = NULL;
  /* A retry always rejects early data (RFC 8446 section 4.1.2).  */
  if (t->early_offered)
    {
      t->early_offered = 0;
      if (t->sink.early_data && t->sink.early_data (t->sink.user, 0))
        return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
    }
  if (sh->session_id_echo.len != t->sid_len
      || memcmp (sh->session_id_echo.data, t->sid, t->sid_len) != 0)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);

  while (gq_ext_next (&rest, &type, &v) == 1)
    switch (type)
      {
      case GQ_EXT_SUPPORTED_VERSIONS:
        if (gq_ext_u16 (v, &ver) != GQ_OK || ver != (t->dtls ? 0xfefc : 0x0304))
          return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        have_ver = 1;
        break;
      case GQ_EXT_KEY_SHARE:
        if (gq_ext_u16 (v, &group) != GQ_OK)
          return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
        have_ks = 1;
        break;
      case GQ_EXT_COOKIE:
        {
          gq_slice c;

          if (gq_ext_cookie (v, &c) != GQ_OK)
            return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
          if (c.len > MAX_COOKIE)
            return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
          memcpy (t->cookie, c.data, c.len);
          t->cookie_len = c.len;
          break;
        }
      default:
        return gqi_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
      }
  if (!have_ver)
    return gqi_fail (t, GQ_ALERT_MISSING_EXTENSION, GQ_ERR_PROTOCOL);
  if (!have_ks && t->cookie_len == 0)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);

  if (have_ks)
    {
      /* The group must be one we support and did not already send a
         share for (RFC 8446 section 4.2.8).  */
      if (!gqi_in_list (t->groups, t->n_groups, group))
        return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      for (i = 0; i < t->n_kx; i++)
        if (t->kx[i].group == group)
          return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      i = gen_kx (t, group, &nk);
      if (i != GQ_OK)
        return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, (int) i);
      for (i = 0; i < t->n_kx; i++)
        gq_kx_key_wipe (&t->kx[i]);
      t->kx[0] = nk;
      t->n_kx = 1;
      gq_wipe (&nk, sizeof nk);
    }
  else if (t->n_kx > 1)
    t->n_kx = 1;		/* Cookie-only retry: keep the first share.  */

  /* Transcript restarts from message_hash (ClientHello1).  */
  select_transcript (t);
  if (gq_transcript_hello_retry (t->tr) != GQ_OK
      || gq_transcript_update (t->tr, msg.data, msg.len) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  t->info.hello_retry = 1;
  t->st = ST_WAIT_SH2;
  return send_ch (t, 1);
}

static int
on_server_hello (gq_tls *t, gq_slice msg, gq_slice body)
{
  gq_server_hello sh;
  gq_slice v, rest, kx = { NULL, 0 };
  unsigned type;
  uint16_t group = 0, ver = 0;
  int have_ks = 0, have_ver = 0, r;
  uint8_t th[GQ_MAX_HASH_LEN], shared[GQ_KX_SHARED_MAX];
  size_t shared_len = 0, i;
  gq_kx_key *key = NULL;

  r = gq_server_hello_parse (body, &sh);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  if (sh.is_hello_retry_request)
    {
      if (t->st != ST_WAIT_SH)
        return gqi_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
      return on_hrr (t, msg, &sh);
    }
  if (sh.legacy_version != (t->dtls ? 0xfefd : 0x0303))
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  if (sh.session_id_echo.len != t->sid_len
      || memcmp (sh.session_id_echo.data, t->sid, t->sid_len) != 0)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  if (!gqi_in_list (t->suites, t->n_suites, sh.cipher_suite)
      || !gqi_suite_params (sh.cipher_suite, &t->aead, &t->hash))
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  if (t->st == ST_WAIT_SH2 && sh.cipher_suite != t->hrr_suite)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);

  rest = sh.extensions;
  while (gq_ext_next (&rest, &type, &v) == 1)
    switch (type)
      {
      case GQ_EXT_SUPPORTED_VERSIONS:
        if (gq_ext_u16 (v, &ver) != GQ_OK)
          return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
        have_ver = 1;
        break;
      case GQ_EXT_KEY_SHARE:
        if (gq_ext_key_share_server (v, &group, &kx) != GQ_OK)
          return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
        have_ks = 1;
        break;
      case GQ_EXT_PRE_SHARED_KEY:
        {
          uint16_t sel;

          if (!t->offered)		/* We offered no PSK.  */
            return gqi_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
          if (gq_ext_u16 (v, &sel) != GQ_OK)
            return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
          if (sel != 0)			/* We offered exactly one.  */
            return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
          t->resumed = 1;
          break;
        }
      default:
        return gqi_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
      }
  /* No supported_versions means the server chose an older protocol.  */
  if (!have_ver)
    return gqi_fail (t, GQ_ALERT_PROTOCOL_VERSION, GQ_ERR_PROTOCOL);
  if (ver != (t->dtls ? 0xfefc : 0x0304))
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  if (!have_ks)
    return gqi_fail (t, GQ_ALERT_MISSING_EXTENSION, GQ_ERR_PROTOCOL);

  for (i = 0; i < t->n_kx; i++)
    if (t->kx[i].group == group)
      key = &t->kx[i];
  if (key == NULL)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);

  t->suite = sh.cipher_suite;
  t->hlen = gq_hash_size (t->hash);
  /* A selected PSK must go with a suite of the same hash (RFC 8446
     section 4.2.11).  */
  if (t->resumed && t->offered->hash != t->hash)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  t->info.resumed = t->resumed;
  if (!t->tr)
    select_transcript (t);
  if (gqi_tr_update (t, msg) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);

  r = gq_kx_complete (key, kx.data, kx.len, shared, sizeof shared,
                      &shared_len);
  if (r == GQ_ERR_ENCODING)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  if (r != GQ_OK)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, r);
  t->info.group = group;
  t->info.cipher_suite = sh.cipher_suite;

  r = t->resumed ? gq_ks_early_v (&t->ks, t->hash, t->offered->psk, t->hlen,
                                  t->dtls)
                 : gq_ks_early_v (&t->ks, t->hash, NULL, 0, t->dtls);
  if (r == GQ_OK)
    r = gq_ks_handshake (&t->ks, shared, shared_len);
  gq_wipe (shared, sizeof shared);
  if (r == GQ_OK)
    r = gqi_tr_hash (t, th);
  if (r == GQ_OK)
    r = gq_ks_handshake_traffic (&t->ks, th, t->chs, t->shs);
  for (i = 0; i < t->n_kx; i++)
    gq_kx_key_wipe (&t->kx[i]);
  t->n_kx = 0;
  if (r != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);

  TRY (gqi_emit_secret (t, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ, t->shs));
  /* If early data is in play over a byte stream, our early keys stay in
     use for writing until EndOfEarlyData has been sent, which is after
     the server's Finished (or at once if the server declines it).  QUIC
     keeps a separate key per level and needs no waiting.  */
  if (t->early_offered && !t->quic)
    t->hs_write_deferred = 1;
  else
    TRY (gqi_emit_secret (t, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE, t->chs));
  t->st = ST_WAIT_EE;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* EncryptedExtensions, certificates, Finished                        */
/* ------------------------------------------------------------------ */

static int
on_encrypted_extensions (gq_tls *t, gq_slice msg, gq_slice body)
{
  gq_slice exts, rest, v, list, chosen = { NULL, 0 };
  unsigned type;
  int r, have_tp = 0, i, found;

  r = gq_encrypted_extensions_parse (body, &exts);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  rest = exts;
  while (gq_ext_next (&rest, &type, &v) == 1)
    switch (type)
      {
      case GQ_EXT_SERVER_NAME:
        if (v.len != 0 || t->cfg.server_name == NULL)
          return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        break;
      case GQ_EXT_SUPPORTED_GROUPS:
        break;			/* Advice for future connections.  */
      case GQ_EXT_ALPN:
        if (t->cfg.n_alpn == 0)
          return gqi_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
        if (gq_ext_alpn (v, &list) != GQ_OK
            || gq_alpn_next (&list, &chosen) != 1 || list.len != 0)
          return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        found = 0;
        for (i = 0; i < (int) t->cfg.n_alpn; i++)
          if (t->cfg.alpn[i].len == chosen.len
              && memcmp (t->cfg.alpn[i].data, chosen.data, chosen.len) == 0)
            found = 1;
        if (!found)
          return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        memcpy (t->info.alpn, chosen.data, chosen.len);
        t->info.alpn_len = chosen.len;
        break;
      case GQ_EXT_EARLY_DATA:
        /* The server accepts our early data (empty extension).  */
        if (!t->early_offered)
          return gqi_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
        if (v.len != 0 || !t->resumed)
          return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        t->early_accepted = 1;
        break;
      case GQ_EXT_QUIC_TRANSPORT_PARAMETERS:
        if (!t->quic)
          return gqi_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
        have_tp = 1;
        if (t->sink.peer_params
            && t->sink.peer_params (t->sink.user, v.data, v.len))
          return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
        break;
      default:
        return gqi_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
      }
  if (t->quic)
    {
      if (!have_tp)
        return gqi_fail (t, GQ_ALERT_MISSING_EXTENSION, GQ_ERR_PROTOCOL);
      if (t->info.alpn_len == 0)		/* RFC 9001 section 8.1.  */
        return gqi_fail (t, GQ_ALERT_NO_APPLICATION_PROTOCOL, GQ_ERR_PROTOCOL);
    }
  if (gqi_tr_update (t, msg) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  if (t->early_offered)
    {
      t->info.early_data_accepted = t->early_accepted;
      if (t->sink.early_data
          && t->sink.early_data (t->sink.user, t->early_accepted))
        return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
      /* Declined: the handshake write keys are needed right away.  */
      if (t->hs_write_deferred && !t->early_accepted)
        {
          t->hs_write_deferred = 0;
          TRY (gqi_emit_secret (t, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE, t->chs));
        }
    }
  /* A resumed session is authenticated by the PSK: straight to Finished.  */
  t->st = t->resumed ? ST_WAIT_FIN : ST_WAIT_CR_OR_CERT;
  return GQ_OK;
}

static int
on_certificate_request (gq_tls *t, gq_slice msg, gq_slice body)
{
  gq_slice ctx, exts, v, list;
  int r;
  size_t i;

  r = gq_certificate_request_parse (body, &ctx, &exts);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  if (!gq_ext_find (exts, GQ_EXT_SIGNATURE_ALGORITHMS, &v))
    return gqi_fail (t, GQ_ALERT_MISSING_EXTENSION, GQ_ERR_PROTOCOL);
  if (gq_list_u16 (v, 2, &list) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
  t->n_cr_sigs = 0;
  for (i = 0; i < gq_u16_count (list) && t->n_cr_sigs < MAX_SIGS; i++)
    t->cr_sigs[t->n_cr_sigs++] = (uint16_t) gq_u16_at (list, i);
  memcpy (t->cr_ctx, ctx.data, ctx.len);
  t->cr_ctx_len = ctx.len;
  t->cert_req = 1;
  t->info.client_auth_requested = 1;
  if (gqi_tr_update (t, msg) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  t->st = ST_WAIT_CERT;
  return GQ_OK;
}

unsigned
gqi_cert_error_alert (enum gq_cert_error e)
{
  switch (e)
    {
    case GQ_CERT_UNTRUSTED: return GQ_ALERT_UNKNOWN_CA;
    case GQ_CERT_EXPIRED: return GQ_ALERT_CERTIFICATE_EXPIRED;
    case GQ_CERT_REVOKED: return GQ_ALERT_CERTIFICATE_REVOKED;
    case GQ_CERT_WEAK_ALGORITHM: return GQ_ALERT_INSUFFICIENT_SECURITY;
    default: return GQ_ALERT_BAD_CERTIFICATE;
    }
}

static int
on_certificate (gq_tls *t, gq_slice msg, gq_slice body)
{
  gq_slice ctx, entries, der, ex, chain[MAX_CHAIN];
  size_t n = 0;
  int r;

  r = gq_certificate_parse (body, &ctx, &entries);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  if (ctx.len != 0)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  while ((r = gq_cert_entry_next (&entries, &der, &ex)) == 1)
    {
      if (n == MAX_CHAIN)
        return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      if (ex.len != 0)		/* We asked for no certificate extensions.  */
        return gqi_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
      chain[n++] = der;
    }
  if (r < 0)
    return gqi_fail_parse (t, r);
  if (n == 0)
    return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);

  if (t->sink.verify_peer)
    {
      if (t->sink.verify_peer (t->sink.user, chain, n, t->cfg.server_name))
        return gqi_fail (t, GQ_ALERT_BAD_CERTIFICATE, GQ_ERR_CERT);
    }
  else
    {
      enum gq_cert_error why;

      if (gq_trust_verify_chain (t->cfg.trust, chain, n, t->cfg.server_name,
                                 &why) != GQ_OK)
        return gqi_fail (t, gqi_cert_error_alert (why), GQ_ERR_CERT);
    }
  if (gq_pubkey_from_cert (&t->peer_key, chain[0].data, chain[0].len) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_BAD_CERTIFICATE, GQ_ERR_CERT);
  if (gqi_tr_update (t, msg) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  t->st = ST_WAIT_CV;
  return GQ_OK;
}

/* Content signed by CertificateVerify (RFC 8446 section 4.4.3).  */
size_t
gqi_cv_content (uint8_t *out, int server, const uint8_t *th, size_t hlen)
{
  static const char srv[] = "TLS 1.3, server CertificateVerify";
  static const char cli[] = "TLS 1.3, client CertificateVerify";
  const char *ctx = server ? srv : cli;
  size_t off = 0;

  memset (out, 0x20, 64);
  off = 64;
  memcpy (out + off, ctx, 33);
  off += 33;
  out[off++] = 0;
  memcpy (out + off, th, hlen);
  return off + hlen;
}

static int
on_certificate_verify (gq_tls *t, gq_slice msg, gq_slice body)
{
  uint16_t scheme;
  gq_slice sig;
  uint8_t th[GQ_MAX_HASH_LEN], content[64 + 34 + GQ_MAX_HASH_LEN];
  size_t n;
  int r;

  r = gq_certificate_verify_parse (body, &scheme, &sig);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  /* Only a scheme we offered, and never one of the certificate-only
     legacy schemes, may sign the handshake.  */
  if (!gqi_in_list (t->sigs, t->n_sigs, scheme))
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  if (gqi_tr_hash (t, th) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  n = gqi_cv_content (content, 1, th, t->hlen);
  if (gq_pubkey_verify (t->peer_key, scheme, content, n, sig.data,
                        sig.len) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_DECRYPT_ERROR, GQ_ERR_CRYPTO);
  if (gqi_tr_update (t, msg) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  t->st = ST_WAIT_FIN;
  return GQ_OK;
}

/* Send one handshake message at the handshake level and hash it.  */
int
gqi_send_hs (gq_tls *t, const gq_wbuf *w)
{
  gq_slice m;

  if (gq_wbuf_status (w) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, gq_wbuf_status (w));
  m.data = w->p;
  m.len = w->len;
  TRY (gqi_emit (t, GQ_LEVEL_HANDSHAKE, m.data, m.len));
  if (gqi_tr_update (t, m) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  return GQ_OK;
}

/* Client certificate flight in answer to a CertificateRequest.  An empty
   Certificate is sent if we have no suitable key (RFC 8446 section
   4.4.2.4).  */
static int
send_client_auth (gq_tls *t)
{
  uint8_t th[GQ_MAX_HASH_LEN], content[64 + 34 + GQ_MAX_HASH_LEN];
  uint8_t sig[GQ_SIGNATURE_MAX];
  size_t i, n, siglen, total = 0, cap;
  unsigned scheme = 0;
  gq_wbuf w;
  gq_slice ctx = { t->cr_ctx, t->cr_ctx_len };
  int have = t->cfg.client_key && t->cfg.client_chain
    && t->cfg.n_client_chain, r;
  uint8_t *heap;

  if (have)
    for (i = 0; i < t->n_cr_sigs && !scheme; i++)
      if (gqi_in_list (t->sigs, t->n_sigs, t->cr_sigs[i])
          && gq_privkey_supports (t->cfg.client_key, t->cr_sigs[i]))
        scheme = t->cr_sigs[i];
  if (!scheme)
    have = 0;
  for (i = 0; have && i < t->cfg.n_client_chain; i++)
    total += t->cfg.client_chain[i].len + 8;

  cap = total + 1024;
  heap = malloc (cap);
  if (heap == NULL)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);

  gq_wbuf_init (&w, heap, cap);
  gq_build_certificate (&w, ctx, have ? t->cfg.client_chain : NULL,
                        have ? t->cfg.n_client_chain : 0);
  r = gqi_send_hs (t, &w);
  if (r == GQ_OK && have)
    {
      t->info.client_auth_sent = 1;
      if (gqi_tr_hash (t, th) != GQ_OK)
        r = gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
      else
        {
          n = gqi_cv_content (content, 0, th, t->hlen);
          if (gq_privkey_sign (t->cfg.client_key, scheme, content, n, sig,
                               sizeof sig, &siglen) != GQ_OK)
            r = gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
          else
            {
              gq_slice s = { sig, siglen };

              gq_wbuf_init (&w, heap, cap);
              gq_build_certificate_verify (&w, (uint16_t) scheme, s);
              r = gqi_send_hs (t, &w);
            }
        }
    }
  free (heap);
  return r;
}

static int
on_finished (gq_tls *t, gq_slice msg, gq_slice body)
{
  gq_slice verify;
  uint8_t th[GQ_MAX_HASH_LEN], want[GQ_MAX_HASH_LEN];
  uint8_t fin[4 + GQ_MAX_HASH_LEN];
  gq_wbuf w;
  int r;

  r = gq_finished_parse (body, t->hlen, &verify);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  if (gqi_tr_hash (t, th) != GQ_OK
      || gq_finished_verify_data_v (t->hash, t->dtls, t->shs, th, want)
         != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  if (!gq_ct_equal (want, verify.data, t->hlen))
    return gqi_fail (t, GQ_ALERT_DECRYPT_ERROR, GQ_ERR_CRYPTO);
  if (gqi_tr_update (t, msg) != GQ_OK || gqi_tr_hash (t, th) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);

  /* Application secrets come from the transcript through the server
     Finished; read keys can be used at once.  */
  r = gq_ks_master (&t->ks);
  if (r == GQ_OK)
    r = gq_ks_app_traffic (&t->ks, th, t->cas, t->sas);
  if (r == GQ_OK)
    r = gq_ks_exporter_master (&t->ks, th, t->exp);
  if (r != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
  TRY (gqi_emit_secret (t, GQ_LEVEL_APPLICATION, GQ_DIR_READ, t->sas));

  /* Over a byte stream the early data ends with EndOfEarlyData, under the
     early keys, before we switch to the handshake keys.  It is part of the
     transcript that our Finished covers.  */
  if (t->hs_write_deferred)
    {
      uint8_t eoed[8];
      gq_wbuf ew;

      gq_wbuf_init (&ew, eoed, sizeof eoed);
      gq_wbuf_hs_open (&ew, GQ_HS_END_OF_EARLY_DATA);
      gq_wbuf_close (&ew);
      if (gq_wbuf_status (&ew) != GQ_OK)
        return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, gq_wbuf_status (&ew));
      TRY (gqi_emit (t, GQ_LEVEL_EARLY, eoed, ew.len));
      if (gqi_tr_update (t, (gq_slice) { eoed, ew.len }) != GQ_OK)
        return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
      t->hs_write_deferred = 0;
      TRY (gqi_emit_secret (t, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE, t->chs));
    }

  if (t->cert_req)
    TRY (send_client_auth (t));

  /* Client Finished.  */
  if (gqi_tr_hash (t, th) != GQ_OK
      || gq_finished_verify_data_v (t->hash, t->dtls, t->chs, th, want)
         != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  gq_wbuf_init (&w, fin, sizeof fin);
  {
    gq_slice v = { want, t->hlen };

    gq_build_finished (&w, v);
  }
  TRY (gqi_send_hs (t, &w));
  if (gqi_tr_hash (t, th) != GQ_OK
      || gq_ks_resumption_master (&t->ks, th, t->resm) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);

  TRY (gqi_emit_secret (t, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE, t->cas));
  t->st = ST_CONNECTED;
  if (t->sink.complete && t->sink.complete (t->sink.user, &t->info))
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* After the handshake                                                */
/* ------------------------------------------------------------------ */

static int
on_new_session_ticket (gq_tls *t, gq_slice body)
{
  gq_new_session_ticket n;
  gq_tls_ticket tk;
  gq_slice v, rest;
  unsigned type;
  int r;

  r = gq_new_session_ticket_parse (body, &n);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  if (t->sink.ticket == NULL)
    return GQ_OK;
  memset (&tk, 0, sizeof tk);
  tk.ticket = n.ticket;
  tk.lifetime = n.lifetime;
  tk.age_add = n.age_add;
  tk.received_ms = gqi_now_ms (t);
  tk.alpn_len = t->info.alpn_len;
  memcpy (tk.alpn, t->info.alpn, t->info.alpn_len);
  tk.cipher_suite = t->suite;
  tk.hash = t->hash;
  tk.psk_len = t->hlen;
  rest = n.extensions;
  while (gq_ext_next (&rest, &type, &v) == 1)
    if (type == GQ_EXT_EARLY_DATA
        && gq_ext_early_data_nst (v, &tk.max_early_data) != GQ_OK)
      return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
  if (gq_resumption_psk_v (t->hash, t->dtls, t->resm, n.nonce.data, n.nonce.len,
                         tk.psk) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  r = t->sink.ticket (t->sink.user, &tk);
  gq_wipe (tk.psk, sizeof tk.psk);
  return r ? gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER) : GQ_OK;
}

/* Application traffic secrets by direction: the client writes with the
   client secret, the server with the server secret.  */
static uint8_t *
write_secret (gq_tls *t)
{
  return t->role == ROLE_CLIENT ? t->cas : t->sas;
}

static uint8_t *
read_secret (gq_tls *t)
{
  return t->role == ROLE_CLIENT ? t->sas : t->cas;
}

/* Rekey our sending direction and tell the transport.  */
static int
rekey_write (gq_tls *t)
{
  uint8_t next[GQ_MAX_HASH_LEN];

  if (gq_traffic_secret_update_v (t->hash, t->dtls, write_secret (t), next)
      != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  memcpy (write_secret (t), next, t->hlen);
  gq_wipe (next, sizeof next);
  return gqi_emit_secret (t, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE,
                          write_secret (t));
}

int
gqi_on_key_update (gq_tls *t, gq_slice body)
{
  int request, r;
  uint8_t next[GQ_MAX_HASH_LEN], msg[8];
  gq_wbuf w;

  if (t->quic)		/* RFC 9001 section 6: QUIC has its own.  */
    return gqi_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
  r = gq_key_update_parse (body, &request);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  if (gq_traffic_secret_update_v (t->hash, t->dtls, read_secret (t), next)
      != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  memcpy (read_secret (t), next, t->hlen);
  gq_wipe (next, sizeof next);
  TRY (gqi_emit_secret (t, GQ_LEVEL_APPLICATION, GQ_DIR_READ,
                        read_secret (t)));
  if (request && !t->ku_busy)
    {
      /* Answer under the old write keys, then switch.  (DTLS: not while
         one of ours is unacknowledged; RFC 9147 section 8.)  */
      gq_wbuf_init (&w, msg, sizeof msg);
      gq_build_key_update (&w, 0);
      TRY (gqi_emit (t, GQ_LEVEL_APPLICATION, msg, w.len));
      TRY (rekey_write (t));
    }
  return GQ_OK;
}

int
gq_tls_key_update (gq_tls *t, int request_peer)
{
  uint8_t msg[8];
  gq_wbuf w;

  if (t == NULL || t->st != ST_CONNECTED || t->quic || t->ku_busy)
    return GQ_ERR_INVAL;
  gq_wbuf_init (&w, msg, sizeof msg);
  gq_build_key_update (&w, request_peer);
  TRY (gqi_emit (t, GQ_LEVEL_APPLICATION, msg, w.len));
  return rekey_write (t);
}

/* ------------------------------------------------------------------ */
/* Input                                                              */
/* ------------------------------------------------------------------ */

static int
dispatch (gq_tls *t, enum gq_level level, gq_slice msg)
{
  unsigned type = msg.data[0];
  gq_slice body = { msg.data + 4, msg.len - 4 };
  enum gq_level want;

  switch (t->st)
    {
    case ST_WAIT_SH:
    case ST_WAIT_SH2:
      if (type != GQ_HS_SERVER_HELLO)
        break;
      if (level != GQ_LEVEL_INITIAL)
        break;
      return on_server_hello (t, msg, body);
    case ST_WAIT_EE:
      if (type == GQ_HS_ENCRYPTED_EXTENSIONS && level == GQ_LEVEL_HANDSHAKE)
        return on_encrypted_extensions (t, msg, body);
      break;
    case ST_WAIT_CR_OR_CERT:
      if (level != GQ_LEVEL_HANDSHAKE)
        break;
      if (type == GQ_HS_CERTIFICATE_REQUEST)
        return on_certificate_request (t, msg, body);
      if (type == GQ_HS_CERTIFICATE)
        return on_certificate (t, msg, body);
      break;
    case ST_WAIT_CERT:
      if (type == GQ_HS_CERTIFICATE && level == GQ_LEVEL_HANDSHAKE)
        return on_certificate (t, msg, body);
      break;
    case ST_WAIT_CV:
      if (type == GQ_HS_CERTIFICATE_VERIFY && level == GQ_LEVEL_HANDSHAKE)
        return on_certificate_verify (t, msg, body);
      break;
    case ST_WAIT_FIN:
      if (type == GQ_HS_FINISHED && level == GQ_LEVEL_HANDSHAKE)
        return on_finished (t, msg, body);
      break;
    case ST_CONNECTED:
      want = GQ_LEVEL_APPLICATION;
      if (level != want)
        break;
      if (type == GQ_HS_NEW_SESSION_TICKET)
        return on_new_session_ticket (t, body);
      if (type == GQ_HS_KEY_UPDATE)
        return gqi_on_key_update (t, body);
      break;
    default:
      break;
    }
  return gqi_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
}

static int
dispatch_any (gq_tls *t, enum gq_level level, gq_slice msg)
{
  if (t->role == ROLE_SERVER)
    return gqi_server_dispatch (t, level, msg);
  return dispatch (t, level, msg);
}

static size_t
body_len (const uint8_t *p)
{
  return ((size_t) p[1] << 16) | ((size_t) p[2] << 8) | p[3];
}

int
gq_tls_feed (gq_tls *t, enum gq_level level, const uint8_t **buf, size_t *len)
{
  if (t == NULL || buf == NULL || len == NULL || t->st == ST_NEW
      || t->st == ST_FAILED)
    return GQ_ERR_INVAL;

  while (*len > 0)
    {
      int r;

      /* Fast path: a whole message is in the caller's buffer.  */
      if (t->msg_len == 0 && *len >= 4)
        {
          size_t n = body_len (*buf);
          gq_slice m;

          if (n > t->cfg.max_message_len)
            return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
          if (*len >= 4 + n)
            {
              m.data = *buf;
              m.len = 4 + n;
              *buf += 4 + n;
              *len -= 4 + n;
              r = dispatch_any (t, level, m);
              if (r != GQ_OK)
                return r;
              continue;
            }
        }

      /* Slow path: accumulate a partial message.  */
      if (t->msg_len > 0 && t->msg_level != level)
        return gqi_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
      if (t->msg == NULL)
        {
          t->msg_cap = 4 + t->cfg.max_message_len;
          t->msg = malloc (t->msg_cap);
          if (t->msg == NULL)
            return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
        }
      t->msg_level = level;
      {
        size_t need, take;

        if (t->msg_len < 4)
          need = 4 - t->msg_len;
        else
          need = 4 + body_len (t->msg) - t->msg_len;
        take = *len < need ? *len : need;
        memcpy (t->msg + t->msg_len, *buf, take);
        t->msg_len += take;
        *buf += take;
        *len -= take;
      }
      if (t->msg_len >= 4)
        {
          size_t n = body_len (t->msg);

          if (n > t->cfg.max_message_len)
            return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
          if (t->msg_len == 4 + n)
            {
              gq_slice m = { t->msg, t->msg_len };

              t->msg_len = 0;
              r = dispatch_any (t, level, m);
              if (r != GQ_OK)
                return r;
            }
        }
    }
  return GQ_OK;
}

void
gq_tls_set_key_update_busy (gq_tls *t, int busy)
{
  if (t)
    t->ku_busy = busy != 0;
}

int
gq_tls_is_complete (const gq_tls *t)
{
  return t != NULL && t->st == ST_CONNECTED;
}

int
gq_tls_is_failed (const gq_tls *t)
{
  return t != NULL && t->st == ST_FAILED;
}

int
gq_tls_alert (const gq_tls *t)
{
  return t ? t->alert : -1;
}

int
gq_tls_export (const gq_tls *t, const char *label, const uint8_t *context,
               size_t context_len, uint8_t *out, size_t out_len)
{
  uint8_t eh[GQ_MAX_HASH_LEN], ch[GQ_MAX_HASH_LEN], derived[GQ_MAX_HASH_LEN];

  if (t == NULL || t->st != ST_CONNECTED || label == NULL || out == NULL
      || (context == NULL && context_len > 0))
    return GQ_ERR_INVAL;
  TRY (gq_hash_compute (t->hash, "", 0, eh, t->hlen));
  TRY (gq_hash_compute (t->hash, context, context_len, ch, t->hlen));
  TRY (gq_hkdf_expand_label_v (t->hash, t->dtls, t->exp, t->hlen, label, eh,
                               t->hlen, derived, t->hlen));
  return gq_hkdf_expand_label_v (t->hash, t->dtls, derived, t->hlen,
                                 "exporter", ch, t->hlen, out, out_len);
}

/* ------------------------------------------------------------------ */
/* Stored sessions                                                    */
/* ------------------------------------------------------------------ */

int
gq_tls_session_store (gq_tls_session *s, const gq_tls_ticket *t)
{
  if (s == NULL || t == NULL || t->ticket.len == 0
      || t->ticket.len > GQ_TICKET_MAX || t->psk_len > GQ_MAX_HASH_LEN)
    return t && t->ticket.len > GQ_TICKET_MAX ? GQ_ERR_BUFSIZE : GQ_ERR_INVAL;
  memset (s, 0, sizeof *s);
  memcpy (s->ticket, t->ticket.data, t->ticket.len);
  s->ticket_len = t->ticket.len;
  s->cipher_suite = t->cipher_suite;
  s->hash = t->hash;
  memcpy (s->psk, t->psk, t->psk_len);
  s->psk_len = t->psk_len;
  s->lifetime = t->lifetime;
  s->age_add = t->age_add;
  s->max_early_data = t->max_early_data;
  s->received_ms = t->received_ms;
  s->alpn_len = t->alpn_len < sizeof s->alpn ? t->alpn_len : 0;
  memcpy (s->alpn, t->alpn, s->alpn_len);
  return GQ_OK;
}

void
gq_tls_session_wipe (gq_tls_session *s)
{
  gq_wipe (s, sizeof *s);
}

/* Encoding: magic "GQS1", then fixed fields, the PSK and the ticket.  */
int
gq_tls_session_serialize (const gq_tls_session *s, uint8_t *out, size_t cap,
                          size_t *out_len)
{
  size_t need, i;
  uint8_t *p = out;

  if (s == NULL || out == NULL || out_len == NULL || s->ticket_len == 0
      || s->ticket_len > GQ_TICKET_MAX || s->psk_len > GQ_MAX_HASH_LEN)
    return GQ_ERR_INVAL;
  need = 4 + 2 + 1 + 1 + s->psk_len + 4 + 4 + 4 + 8 + 1 + s->alpn_len + 2
    + s->ticket_len;
  if (cap < need)
    return GQ_ERR_BUFSIZE;
  memcpy (p, "GQS2", 4);
  p += 4;
  *p++ = (uint8_t) (s->cipher_suite >> 8);
  *p++ = (uint8_t) s->cipher_suite;
  *p++ = (uint8_t) s->hash;
  *p++ = (uint8_t) s->psk_len;
  memcpy (p, s->psk, s->psk_len);
  p += s->psk_len;
#define PUT32(v) do { *p++ = (uint8_t) ((v) >> 24); *p++ = (uint8_t) ((v) >> 16); \
                      *p++ = (uint8_t) ((v) >> 8); *p++ = (uint8_t) (v); } while (0)
  PUT32 (s->lifetime);
  PUT32 (s->age_add);
  PUT32 (s->max_early_data);
  for (i = 0; i < 8; i++)
    *p++ = (uint8_t) (s->received_ms >> (8 * (7 - i)));
  if (s->alpn_len > sizeof s->alpn)
    return GQ_ERR_INVAL;
  *p++ = (uint8_t) s->alpn_len;
  memcpy (p, s->alpn, s->alpn_len);
  p += s->alpn_len;
  *p++ = (uint8_t) (s->ticket_len >> 8);
  *p++ = (uint8_t) s->ticket_len;
  memcpy (p, s->ticket, s->ticket_len);
  p += s->ticket_len;
  *out_len = (size_t) (p - out);
  return GQ_OK;
}

int
gq_tls_session_deserialize (gq_tls_session *s, const uint8_t *d, size_t len)
{
  const uint8_t *p = d, *end = d + len;
  enum gq_aead a;
  enum gq_hash h;
  size_t i, tl;
  uint32_t v;

  if (s == NULL || d == NULL || len < 4 + 4 || memcmp (d, "GQS2", 4) != 0)
    return GQ_ERR_ENCODING;
  memset (s, 0, sizeof *s);
  p += 4;
  s->cipher_suite = (uint16_t) ((p[0] << 8) | p[1]);
  s->hash = (enum gq_hash) p[2];
  s->psk_len = p[3];
  p += 4;
  if (!gqi_suite_params (s->cipher_suite, &a, &h) || h != s->hash
      || s->psk_len != gq_hash_size (h))
    return GQ_ERR_ENCODING;
  if ((size_t) (end - p) < s->psk_len + 4 + 4 + 4 + 8 + 1)
    return GQ_ERR_ENCODING;
  memcpy (s->psk, p, s->psk_len);
  p += s->psk_len;
#define GET32(dst) do { v = ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) \
                          | ((uint32_t) p[2] << 8) | p[3]; p += 4; dst = v; } while (0)
  GET32 (s->lifetime);
  GET32 (s->age_add);
  GET32 (s->max_early_data);
  for (i = 0; i < 8; i++)
    s->received_ms = (s->received_ms << 8) | *p++;
  s->alpn_len = *p++;
  if ((size_t) (end - p) < s->alpn_len + 2)
    return GQ_ERR_ENCODING;
  memcpy (s->alpn, p, s->alpn_len);
  p += s->alpn_len;
  tl = ((size_t) p[0] << 8) | p[1];
  p += 2;
  if (tl == 0 || tl > GQ_TICKET_MAX || (size_t) (end - p) != tl)
    return GQ_ERR_ENCODING;
  memcpy (s->ticket, p, tl);
  s->ticket_len = tl;
  return GQ_OK;
}

int
gq_tls_early_data_accepted (const gq_tls *t)
{
  return t != NULL && t->early_accepted;
}
