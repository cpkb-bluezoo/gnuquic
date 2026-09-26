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

/* TLS 1.2 engine: state shared by both roles, and the client.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/crypto.h>

#include "tls12_int.h"
#include "tls_int.h"		/* gqi_cert_error_alert */

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* Certificate types we can sign with, in preference order.  RSA is signed
   with PKCS#1 v1.5 only; RSA-PSS is verified but never produced.  */
static const uint16_t sign_pref[] = {
  GQ_SIG_ECDSA_SECP256R1_SHA256,
  GQ_SIG_ECDSA_SECP384R1_SHA384,
  GQ_SIG_RSA_PKCS1_SHA256,
  GQ_SIG_RSA_PKCS1_SHA384,
  GQ_SIG_RSA_PKCS1_SHA512
};

/* What we accept in a certificate chain's own signatures, advertised in
   signature_algorithms_cert.  The trust layer enforces it.  */
static const uint16_t cert_sigs[] = {
  GQ_SIG_ECDSA_SECP256R1_SHA256,
  GQ_SIG_ECDSA_SECP384R1_SHA384,
  GQ_SIG_RSA_PKCS1_SHA256,
  GQ_SIG_RSA_PKCS1_SHA384,
  GQ_SIG_RSA_PKCS1_SHA512
};

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

uint64_t
g12_now_ms (const gq_tls12 *t)
{
  if (t->cfg.hooks.now_ms)
    return t->cfg.hooks.now_ms (t->cfg.hooks.user);
  return (uint64_t) time (NULL) * 1000;
}

int
g12_fail (gq_tls12 *t, unsigned alert, int status)
{
  if (t->st != S12_FAILED)
    {
      t->st = S12_FAILED;
      t->alert = (int) alert;
      if (t->sink.alert)
        t->sink.alert (t->sink.user, alert);
    }
  return status;
}

int
g12_fail_parse (gq_tls12 *t, int status)
{
  return g12_fail (t, status == GQ_ERR_ENCODING ? GQ_ALERT_DECODE_ERROR
                                                : GQ_ALERT_ILLEGAL_PARAMETER,
                   status < 0 ? status : GQ_ERR_PROTOCOL);
}

int
g12_rnd (gq_tls12 *t, void *buf, size_t n)
{
  if (t->cfg.hooks.random)
    return t->cfg.hooks.random (t->cfg.hooks.user, buf, n) ? GQ_ERR_CRYPTO
                                                            : GQ_OK;
  return gq_random (buf, n);
}

int
g12_in_list (const uint16_t *l, size_t n, unsigned v)
{
  size_t i;

  for (i = 0; i < n; i++)
    if (l[i] == v)
      return 1;
  return 0;
}

static void
filter_list (uint16_t *dst, size_t *n, size_t cap, const uint16_t *src,
             size_t ns, int (*ok) (unsigned))
{
  size_t i;

  *n = 0;
  for (i = 0; i < ns && *n < cap; i++)
    if (ok (src[i]) && !g12_in_list (dst, *n, src[i]))
      dst[(*n)++] = src[i];
}

static int
ok_suite (unsigned s)
{
  return gq_policy_allows_suite (GQ_TLS_1_2, s);
}

static int
ok_sig (unsigned s)
{
  return gq_policy_allows_sigscheme (GQ_TLS_1_2, s)
    && gq_sigscheme_available (s);
}

/* Apply the TLS 1.2 policy (and the defaults) to the preference lists.  */
void
g12_filter (gq_tls12 *t, const uint16_t *suites, size_t n_suites,
            const uint16_t *sigs, size_t n_sigs)
{
  const uint16_t *l;
  size_t n;

  l = suites ? suites : gq_policy_default_suites (GQ_TLS_1_2, &n);
  n = suites ? n_suites : n;
  filter_list (t->suites, &t->n_suites, T12_MAX_SUITES, l, n, ok_suite);
  l = sigs ? sigs : gq_policy_default_sigschemes_for (GQ_TLS_1_2, &n);
  n = sigs ? n_sigs : n;
  filter_list (t->sigs, &t->n_sigs, T12_MAX_SIGS, l, n, ok_sig);
}

static int
tb_append (gq_tls12 *t, const uint8_t *data, size_t len)
{
  if (len > T12_TB_MAX - t->tb_len)
    return GQ_ERR_RANGE;
  if (t->tb_len + len > t->tb_cap)
    {
      size_t cap = t->tb_cap ? t->tb_cap * 2 : 4096;
      uint8_t *nb;

      while (cap < t->tb_len + len)
        cap *= 2;
      nb = malloc (cap);
      if (nb == NULL)
        return GQ_ERR_NOMEM;
      if (t->tb)
        {
          memcpy (nb, t->tb, t->tb_len);
          gq_wipe (t->tb, t->tb_cap);
          free (t->tb);
        }
      t->tb = nb;
      t->tb_cap = cap;
    }
  memcpy (t->tb + t->tb_len, data, len);
  t->tb_len += len;
  return GQ_OK;
}

static int
tb_add_seq (gq_tls12 *t, const uint8_t *msg, size_t len, uint16_t seq)
{
  uint8_t h[12];

  if (!t->dtls)
    return tb_append (t, msg, len);
  memcpy (h, msg, 4);			/* type, length */
  h[4] = (uint8_t) (seq >> 8);
  h[5] = (uint8_t) seq;
  h[6] = h[7] = h[8] = 0;		/* fragment_offset 0 */
  memcpy (h + 9, msg + 1, 3);		/* fragment_length = length */
  TRY (tb_append (t, h, 12));
  return tb_append (t, msg + 4, len - 4);
}

int
g12_tb_add (gq_tls12 *t, const uint8_t *data, size_t len)
{
  return tb_add_seq (t, data, len, t->rx_seq);
}

int
g12_tb_add_tx (gq_tls12 *t, const uint8_t *data, size_t len)
{
  return tb_add_seq (t, data, len, t->tx_seq);
}

int
g12_tb_hash (const gq_tls12 *t, uint8_t *out)
{
  return gq_hash_compute (t->hash, t->tb, t->tb_len, out,
                          gq_hash_size (t->hash));
}

int
g12_send (gq_tls12 *t, const gq_wbuf *w)
{
  if (gq_wbuf_status (w) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, gq_wbuf_status (w));
  if (g12_tb_add_tx (t, w->p, w->len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  t->tx_seq++;
  if (t->sink.send (t->sink.user, w->p, w->len))
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
  return GQ_OK;
}

int
g12_gen_kx (gq_tls12 *t)
{
  int r;

  if (t->cfg.hooks.kx_generate)
    r = t->cfg.hooks.kx_generate (t->cfg.hooks.user, GQ_GROUP_SECP256R1,
                                  &t->kx) ? GQ_ERR_CRYPTO : GQ_OK;
  else
    r = gq_kx_generate (GQ_GROUP_SECP256R1, &t->kx);
  if (r == GQ_OK && t->kx.share_len != GQ_TLS12_POINT_LEN)
    r = GQ_ERR_CRYPTO;
  if (r != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
  t->have_kx = 1;
  return GQ_OK;
}

/* Master secret from the premaster and the session hash, then wipe the
   premaster and the ephemeral key.  The transcript must end at
   ClientKeyExchange.  */
int
g12_derive_master (gq_tls12 *t)
{
  uint8_t sh[GQ_MAX_HASH_LEN];
  int r;

  r = g12_tb_hash (t, sh);
  if (r == GQ_OK)
    r = gq_tls12_master_secret (t->hash, t->pms, t->pms_len, sh, t->master);
  gq_wipe (t->pms, sizeof t->pms);
  t->pms_len = 0;
  if (t->have_kx)
    {
      gq_kx_key_wipe (&t->kx);
      t->have_kx = 0;
    }
  if (r != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
  return GQ_OK;
}

int
g12_derive_keys (gq_tls12 *t)
{
  int r = gq_tls12_key_block (t->hash, t->aead, t->master, t->server_random,
                              t->client_random, &t->keys);

  if (r != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
  t->have_keys = 1;
  return GQ_OK;
}

static int
install (gq_tls12 *t, enum gq_dir dir, int client_half)
{
  const uint8_t *k = client_half ? t->keys.client_key : t->keys.server_key;
  const uint8_t *iv = client_half ? t->keys.client_iv : t->keys.server_iv;

  if (!t->have_keys)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_INVAL);
  if (t->sink.change_keys (t->sink.user, dir, t->keys.aead, k,
                           t->keys.key_len, iv, t->keys.iv_len))
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
  return GQ_OK;
}

int
g12_install_write (gq_tls12 *t)
{
  return install (t, GQ_DIR_WRITE, !t->server);
}

int
g12_install_read (gq_tls12 *t)
{
  return install (t, GQ_DIR_READ, t->server);
}

int
g12_send_finished (gq_tls12 *t)
{
  uint8_t h[GQ_MAX_HASH_LEN], v[GQ_TLS12_VERIFY_LEN], buf[4 + GQ_TLS12_VERIFY_LEN];
  gq_wbuf w;
  gq_slice vs = { v, sizeof v };

  if (g12_tb_hash (t, h) != GQ_OK
      || gq_tls12_verify_data (t->hash, t->master, !t->server, h, v) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  gq_wbuf_init (&w, buf, sizeof buf);
  gq_build_finished (&w, vs);
  return g12_send (t, &w);
}

int
g12_check_finished (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  uint8_t h[GQ_MAX_HASH_LEN], v[GQ_TLS12_VERIFY_LEN];
  gq_slice got;
  int r = gq_finished_parse (body, GQ_TLS12_VERIFY_LEN, &got);

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (g12_tb_hash (t, h) != GQ_OK
      || gq_tls12_verify_data (t->hash, t->master, t->server, h, v) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  if (!gq_ct_equal (v, got.data, sizeof v))
    return g12_fail (t, GQ_ALERT_DECRYPT_ERROR, GQ_ERR_CRYPTO);
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  return GQ_OK;
}

int
g12_complete (gq_tls12 *t)
{
  t->st = S12_DONE;
  t->info.cipher_suite = t->suite;
  t->info.group = GQ_GROUP_SECP256R1;
  t->info.resumed = t->resumed;
  t->info.client_auth_sent = t->server ? t->client_verified
                                       : t->info.client_auth_sent;
  if (t->server)
    {
      memcpy (t->info.server_name, t->sni, t->sni_len);
      t->info.server_name_len = t->sni_len;
    }
  /* The wire keys are installed; the derivation is no longer needed.  */
  gq_wipe (&t->keys, sizeof t->keys);
  t->have_keys = 0;
  if (t->tb)
    {
      gq_wipe (t->tb, t->tb_cap);
      free (t->tb);
      t->tb = NULL;
      t->tb_len = t->tb_cap = 0;
    }

  if (!t->server && t->nst_len && t->sink.ticket)
    {
      gq_tls_ticket k;

      memset (&k, 0, sizeof k);
      k.ticket.data = t->nst;
      k.ticket.len = t->nst_len;
      k.lifetime = t->nst_lifetime;
      k.received_ms = g12_now_ms (t);
      k.cipher_suite = t->suite;
      k.hash = t->hash;
      k.psk_len = GQ_TLS12_MASTER_LEN;
      memcpy (k.psk, t->master, GQ_TLS12_MASTER_LEN);
      k.alpn_len = t->info.alpn_len;
      memcpy (k.alpn, t->info.alpn, t->info.alpn_len);
      if (t->sink.ticket (t->sink.user, &k))
        {
          gq_wipe (&k, sizeof k);
          return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
        }
      gq_wipe (&k, sizeof k);
    }
  if (t->sink.complete && t->sink.complete (t->sink.user, &t->info))
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
  return GQ_OK;
}

unsigned
g12_pick_scheme (const gq_tls12 *t, const gq_privkey *key, gq_slice peer_list)
{
  size_t i;

  for (i = 0; i < sizeof sign_pref / sizeof sign_pref[0]; i++)
    if (g12_in_list (t->sigs, t->n_sigs, sign_pref[i])
        && gq_u16_contains (peer_list, sign_pref[i])
        && gq_privkey_supports (key, sign_pref[i]))
      return sign_pref[i];
  return 0;
}

/* ------------------------------------------------------------------ */
/* Creation                                                           */
/* ------------------------------------------------------------------ */

int
gq_tls12_client_new (gq_tls12 **out, const gq_tls_config *cfg,
                     const gq_tls12_sink *sink)
{
  gq_tls12 *t;

  if (out == NULL || cfg == NULL || sink == NULL || sink->send == NULL
      || sink->change_keys == NULL)
    return GQ_ERR_INVAL;
  /* QUIC is TLS 1.3 only, and TLS 1.2 has no 0-RTT.  */
  if (cfg->quic || cfg->transport_params || cfg->early_data)
    return GQ_ERR_INVAL;
  /* Refuse to run unauthenticated by accident.  */
  if (cfg->trust == NULL && sink->verify_peer == NULL)
    return GQ_ERR_INVAL;
  if (cfg->server_name && (strlen (cfg->server_name) > 255
                           || cfg->server_name[0] == '\0'))
    return GQ_ERR_INVAL;
  if (cfg->n_alpn && cfg->alpn == NULL)
    return GQ_ERR_INVAL;
  TRY (gq_crypto_init ());

  t = calloc (1, sizeof *t);
  if (t == NULL)
    return GQ_ERR_NOMEM;
  t->cfg = *cfg;
  t->sink = *sink;
  t->dtls = cfg->dtls != 0;
  t->alert = -1;
  if (t->cfg.max_message_len == 0)
    t->cfg.max_message_len = 65536;
  t->offered = cfg->resume;
  g12_filter (t, cfg->suites, cfg->n_suites, cfg->sigschemes,
              cfg->n_sigschemes);
  if (t->n_suites == 0 || t->n_sigs == 0)
    {
      free (t);
      return GQ_ERR_INVAL;
    }
  t->st = S12_NEW;
  *out = t;
  return GQ_OK;
}

void
gq_tls12_free (gq_tls12 *t)
{
  if (t == NULL)
    return;
  gq_pubkey_free (t->peer_key);
  if (t->msg)
    {
      gq_wipe (t->msg, t->msg_cap);
      free (t->msg);
    }
  if (t->tb)
    {
      gq_wipe (t->tb, t->tb_cap);
      free (t->tb);
    }
  gq_wipe (t, sizeof *t);
  free (t);
}

/* ------------------------------------------------------------------ */
/* Client                                                             */
/* ------------------------------------------------------------------ */

/* Is the session we hold usable for resumption?  */
static int
session_usable (const gq_tls12 *t)
{
  const gq_tls_session *s = t->offered;
  uint64_t now = g12_now_ms (t);

  if (s == NULL || s->ticket_len == 0 || s->psk_len != GQ_TLS12_MASTER_LEN)
    return 0;
  if (!g12_in_list (t->suites, t->n_suites, s->cipher_suite))
    return 0;
  /* received_ms + lifetime: an expired ticket would only cost a round
     trip, but there is no point offering it.  */
  return now >= s->received_ms
    && now - s->received_ms < (uint64_t) s->lifetime * 1000;
}

/* Build and send the ClientHello (again, with the cookie, after a
   HelloVerifyRequest).  */
static int
send_ch (gq_tls12 *t)
{
  uint8_t buf[GQ_TICKET_MAX + 2048];
  gq_wbuf w;
  gq_tls12_ch_params p;
  gq_slice sid = { t->sid, t->sid_len };

  memset (&p, 0, sizeof p);
  p.have_ticket = 1;
  if (t->offered)
    {
      p.ticket.data = t->offered->ticket;
      p.ticket.len = t->offered->ticket_len;
    }
  p.random = t->client_random;
  p.session_id = sid;
  p.suites = t->suites;
  p.n_suites = t->n_suites;
  p.server_name = t->cfg.server_name;
  p.alpn = t->cfg.alpn;
  p.n_alpn = t->cfg.n_alpn;
  p.sigalgs = t->sigs;
  p.n_sigalgs = t->n_sigs;
  p.cert_sigalgs = cert_sigs;
  p.n_cert_sigalgs = sizeof cert_sigs / sizeof cert_sigs[0];
  p.dtls = t->dtls;
  p.cookie = (gq_slice) { t->cookie, t->cookie_len };

  gq_wbuf_init (&w, buf, sizeof buf);
  gq_tls12_build_client_hello (&w, &p);
  if (gq_wbuf_status (&w) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, gq_wbuf_status (&w));
  /* The transcript hash is chosen with the suite; until then the raw
     messages are kept.  */
  if (g12_tb_add_tx (t, w.p, w.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  t->tx_seq++;
  t->st = S12_C_WAIT_SH;
  if (t->sink.send (t->sink.user, w.p, w.len))
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
  return GQ_OK;
}

int
gq_tls12_start (gq_tls12 *t)
{
  if (t == NULL || t->server || t->st != S12_NEW)
    return GQ_ERR_INVAL;
  TRY (g12_rnd (t, t->client_random, 32));
  if (session_usable (t))
    {
      /* RFC 5077 section 3.4: a fresh random session ID lets the server
         signal acceptance by echoing it.  */
      TRY (g12_rnd (t, t->sid, 32));
      t->sid_len = 32;
    }
  else
    t->offered = NULL;
  return send_ch (t);
}

/* DTLS: the server wants a cookie (RFC 6347 section 4.2.1).  The first
   ClientHello and this message are not part of the transcript; the
   second ClientHello repeats the first with the cookie added.  */
static int
c_on_hello_verify_request (gq_tls12 *t, gq_slice body)
{
  uint16_t ver;
  gq_slice cookie;
  int r = gq_tls12_hvr_parse (body, &ver, &cookie);

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (t->hvr_seen || (ver != 0xfefd && ver != 0xfeff))
    return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  memcpy (t->cookie, cookie.data, cookie.len);
  t->cookie_len = cookie.len;
  t->hvr_seen = 1;
  gq_wipe (t->tb, t->tb_len);
  t->tb_len = 0;
  return send_ch (t);
}

/* Validate the ServerHello extensions.  Every one must be something we
   offered, and the two hardening extensions must be present and exact.  */
static int
check_sh_exts (gq_tls12 *t, gq_slice exts, gq_slice *alpn)
{
  gq_slice rest = exts, v;
  unsigned type;
  int ems = 0, reneg = 0, r;

  alpn->len = 0;
  while ((r = gq_ext_next (&rest, &type, &v)) == 1)
    switch (type)
      {
      case GQ_EXT_SERVER_NAME:
        if (v.len != 0 || t->cfg.server_name == NULL)
          return g12_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
        break;
      case GQ_EXT12_EC_POINT_FORMATS:
        {
          size_t i;
          int ok = 0;

          if (v.len < 2 || v.data[0] != v.len - 1)
            return g12_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
          for (i = 1; i < v.len; i++)
            ok |= v.data[i] == 0;
          if (!ok)		/* Uncompressed is mandatory (RFC 8422).  */
            return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        }
        break;
      case GQ_EXT_ALPN:
        {
          gq_slice list, name, more;
          size_t i;
          int found = 0;

          if (t->cfg.n_alpn == 0)
            return g12_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION,
                             GQ_ERR_PROTOCOL);
          if (gq_ext_alpn (v, &list) != GQ_OK
              || gq_alpn_next (&list, &name) != 1
              || gq_alpn_next (&list, &more) != 0 || list.len != 0)
            return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
          for (i = 0; i < t->cfg.n_alpn; i++)
            if (t->cfg.alpn[i].len == name.len
                && memcmp (t->cfg.alpn[i].data, name.data, name.len) == 0)
              found = 1;
          if (!found || name.len > sizeof t->info.alpn)
            return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
          memcpy (t->info.alpn, name.data, name.len);
          t->info.alpn_len = name.len;
          *alpn = name;
        }
        break;
      case GQ_EXT12_EXTENDED_MASTER_SECRET:
        if (v.len != 0)
          return g12_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
        ems = 1;
        break;
      case GQ_EXT12_SESSION_TICKET:
        if (v.len != 0)
          return g12_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
        t->ticket_expected = 1;
        break;
      case GQ_EXT12_RENEGOTIATION_INFO:
        /* Initial handshake: exactly one zero byte (RFC 5746 section 3.4).  */
        if (v.len != 1 || v.data[0] != 0)
          return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_PROTOCOL);
        reneg = 1;
        break;
      default:
        return g12_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
      }
  if (r < 0)
    return g12_fail_parse (t, r);
  /* Mandatory: RFC 7627 (closes the triple handshake) and RFC 5746.  */
  if (!ems || !reneg)
    return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_PROTOCOL);
  return GQ_OK;
}

static int
c_on_server_hello (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  gq_server_hello sh;
  gq_slice alpn, sv;
  int r = gq_server_hello_parse (body, &sh);

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (t->dtls ? sh.legacy_version == 0xfeff : sh.legacy_version < 0x0303)
    return g12_fail (t, GQ_ALERT_PROTOCOL_VERSION, GQ_ERR_PROTOCOL);
  if (sh.legacy_version != (t->dtls ? 0xfefd : 0x0303)
      || sh.is_hello_retry_request)
    return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  /* A TLS 1.3 server would say so here; we do not speak it.  */
  if (gq_ext_find (sh.extensions, GQ_EXT_SUPPORTED_VERSIONS, &sv))
    return g12_fail (t, GQ_ALERT_PROTOCOL_VERSION, GQ_ERR_PROTOCOL);
  if (!g12_in_list (t->suites, t->n_suites, sh.cipher_suite)
      || !gq_tls12_suite_params (sh.cipher_suite, &t->aead, &t->hash))
    return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  TRY (check_sh_exts (t, sh.extensions, &alpn));

  t->suite = sh.cipher_suite;
  memcpy (t->server_random, sh.random, 32);
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);

  /* Accepted ticket: the server echoes the session ID we made up.  */
  if (t->offered && t->sid_len && sh.session_id_echo.len == t->sid_len
      && memcmp (sh.session_id_echo.data, t->sid, t->sid_len) == 0)
    {
      if (sh.cipher_suite != t->offered->cipher_suite)
        return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      t->resumed = 1;
      memcpy (t->master, t->offered->psk, GQ_TLS12_MASTER_LEN);
      TRY (g12_derive_keys (t));
      t->st = S12_C_WAIT_TICKET_OR_CCS;
      return GQ_OK;
    }
  t->st = S12_C_WAIT_CERT;
  return GQ_OK;
}

static int
c_on_certificate (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  gq_slice chain[T12_MAX_CHAIN];
  size_t n;
  int r = gq_tls12_certificate_parse (body, chain, T12_MAX_CHAIN, &n);

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (n == 0)
    return g12_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);

  if (t->sink.verify_peer)
    {
      if (t->sink.verify_peer (t->sink.user, chain, n, t->cfg.server_name))
        return g12_fail (t, GQ_ALERT_BAD_CERTIFICATE, GQ_ERR_CERT);
    }
  else
    {
      enum gq_cert_error why;

      if (gq_trust_verify_chain (t->cfg.trust, chain, n, t->cfg.server_name,
                                 &why) != GQ_OK)
        return g12_fail (t, gqi_cert_error_alert (why), GQ_ERR_CERT);
    }
  if (gq_pubkey_from_cert (&t->peer_key, chain[0].data, chain[0].len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_BAD_CERTIFICATE, GQ_ERR_CERT);
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  t->st = S12_C_WAIT_SKE;
  return GQ_OK;
}

static int
c_on_server_key_exchange (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  gq_tls12_ske ske;
  uint8_t data[64 + 128];
  int r = gq_tls12_ske_parse (body, &ske);

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  /* The scheme must be one we offered, and fit the suite's key type.  */
  if (!g12_in_list (t->sigs, t->n_sigs, ske.scheme))
    return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  {
    int rsa_scheme = ske.scheme == GQ_SIG_RSA_PKCS1_SHA256
      || ske.scheme == GQ_SIG_RSA_PKCS1_SHA384
      || ske.scheme == GQ_SIG_RSA_PKCS1_SHA512
      || (ske.scheme >= GQ_SIG_RSA_PSS_RSAE_SHA256
          && ske.scheme <= GQ_SIG_RSA_PSS_RSAE_SHA512);

    if (rsa_scheme != gq_tls12_suite_is_rsa (t->suite))
      return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  }
  /* Signed: client_random, server_random, ServerECDHParams.  */
  memcpy (data, t->client_random, 32);
  memcpy (data + 32, t->server_random, 32);
  memcpy (data + 64, ske.params.data, ske.params.len);
  if (gq_pubkey_verify (t->peer_key, ske.scheme, data, 64 + ske.params.len,
                        ske.signature.data, ske.signature.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_DECRYPT_ERROR, GQ_ERR_CRYPTO);

  /* Our half of the exchange; the shared secret is the premaster.  */
  TRY (g12_gen_kx (t));
  if (gq_kx_complete (&t->kx, ske.point.data, ske.point.len, t->pms,
                      sizeof t->pms, &t->pms_len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_CRYPTO);
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  t->st = S12_C_WAIT_CR_OR_SHD;
  return GQ_OK;
}

static int
c_on_certificate_request (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  gq_slice sigs;
  int r = gq_tls12_certreq_parse (body, &sigs);

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (sigs.len > sizeof t->cr_sigs)
    sigs.len = sizeof t->cr_sigs;	/* Extra schemes are never used.  */
  memcpy (t->cr_sigs, sigs.data, sigs.len);
  t->cr_sigs_len = sigs.len;
  t->cert_req = 1;
  t->info.client_auth_requested = 1;
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  t->st = S12_C_WAIT_SHD;
  return GQ_OK;
}

/* ServerHelloDone: answer with our whole flight up to Finished.  */
static int
c_on_server_hello_done (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  uint8_t small[128];
  gq_wbuf w;
  unsigned scheme = 0;
  gq_slice raw = { t->cr_sigs, t->cr_sigs_len };

  if (body.len != 0)
    return g12_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);

  if (t->cert_req)
    {
      int have = t->cfg.client_key && t->cfg.client_chain
        && t->cfg.n_client_chain;
      size_t i, total = 16;
      uint8_t *heap;

      if (have)
        scheme = g12_pick_scheme (t, t->cfg.client_key, raw);
      if (!scheme)
        have = 0;
      for (i = 0; have && i < t->cfg.n_client_chain; i++)
        total += t->cfg.client_chain[i].len + 3;
      heap = malloc (total);
      if (heap == NULL)
        return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
      gq_wbuf_init (&w, heap, total);
      /* No suitable certificate: an empty list, and the server decides
         (RFC 5246 section 7.4.6).  */
      gq_tls12_build_certificate (&w, t->cfg.client_chain,
                                  have ? t->cfg.n_client_chain : 0);
      {
        int r = g12_send (t, &w);

        gq_wipe (heap, total);
        free (heap);
        if (r != GQ_OK)
          return r;
      }
      t->info.client_auth_sent = have;
    }

  gq_wbuf_init (&w, small, sizeof small);
  gq_tls12_build_cke (&w, (gq_slice) { t->kx.share, t->kx.share_len });
  TRY (g12_send (t, &w));
  TRY (g12_derive_master (t));

  if (scheme)
    {
      uint8_t sig[GQ_SIGNATURE_MAX], *cv;
      size_t sl;
      int r;

      /* CertificateVerify signs every handshake message so far.  */
      if (gq_privkey_sign (t->cfg.client_key, scheme, t->tb, t->tb_len, sig,
                           sizeof sig, &sl) != GQ_OK)
        return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
      cv = malloc (sl + 16);
      if (cv == NULL)
        return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
      gq_wbuf_init (&w, cv, sl + 16);
      gq_build_certificate_verify (&w, (uint16_t) scheme,
                                   (gq_slice) { sig, sl });
      r = g12_send (t, &w);
      free (cv);
      if (r != GQ_OK)
        return r;
    }

  TRY (g12_derive_keys (t));
  TRY (g12_install_write (t));
  TRY (g12_send_finished (t));
  t->st = S12_C_WAIT_TICKET_OR_CCS;
  return GQ_OK;
}

static int
c_on_new_session_ticket (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  uint32_t lifetime;
  gq_slice ticket;
  int r;

  if (!t->ticket_expected)
    return g12_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
  r = gq_tls12_nst_parse (body, &lifetime, &ticket);
  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (ticket.len <= sizeof t->nst)
    {
      memcpy (t->nst, ticket.data, ticket.len);
      t->nst_len = ticket.len;
      t->nst_lifetime = lifetime;
    }
  /* A ticket too big to keep is not an error; we simply cannot resume.  */
  t->ticket_expected = 0;
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  t->st = S12_C_WAIT_CCS;
  return GQ_OK;
}

static int
c_on_finished (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  TRY (g12_check_finished (t, msg, body));
  if (t->resumed)
    {
      /* Abbreviated handshake: now it is our turn (RFC 5246 figure 3).  */
      TRY (g12_install_write (t));
      TRY (g12_send_finished (t));
    }
  return g12_complete (t);
}

static int
c_dispatch (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  unsigned type = msg.data[0];

  switch (t->st)
    {
    case S12_C_WAIT_SH:
      if (type == GQ_HS_SERVER_HELLO)
        return c_on_server_hello (t, msg, body);
      if (type == GQ_HS12_HELLO_VERIFY_REQUEST && t->dtls)
        return c_on_hello_verify_request (t, body);
      break;
    case S12_C_WAIT_CERT:
      if (type == GQ_HS_CERTIFICATE)
        return c_on_certificate (t, msg, body);
      break;
    case S12_C_WAIT_SKE:
      if (type == GQ_HS12_SERVER_KEY_EXCHANGE)
        return c_on_server_key_exchange (t, msg, body);
      break;
    case S12_C_WAIT_CR_OR_SHD:
      if (type == GQ_HS_CERTIFICATE_REQUEST)
        return c_on_certificate_request (t, msg, body);
      if (type == GQ_HS12_SERVER_HELLO_DONE)
        return c_on_server_hello_done (t, msg, body);
      break;
    case S12_C_WAIT_SHD:
      if (type == GQ_HS12_SERVER_HELLO_DONE)
        return c_on_server_hello_done (t, msg, body);
      break;
    case S12_C_WAIT_TICKET_OR_CCS:
      if (type == GQ_HS_NEW_SESSION_TICKET)
        return c_on_new_session_ticket (t, msg, body);
      break;
    case S12_C_WAIT_FIN:
      if (type == GQ_HS_FINISHED)
        return c_on_finished (t, msg, body);
      break;
    case S12_DONE:
      /* A HelloRequest (or anything else) after the handshake would start
         a renegotiation, which we never do.  */
      return g12_fail (t, GQ_ALERT_NO_RENEGOTIATION, GQ_ERR_PROTOCOL);
    default:
      break;
    }
  return g12_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
}

/* ------------------------------------------------------------------ */
/* Input                                                              */
/* ------------------------------------------------------------------ */

static int
dispatch (gq_tls12 *t, gq_slice msg)
{
  gq_slice body = { msg.data + 4, msg.len - 4 };
  int r = t->server ? g12_server_dispatch (t, msg, body)
                    : c_dispatch (t, msg, body);

  /* The message just handled has used its message_seq (DTLS).  */
  t->rx_seq++;
  return r;
}

static size_t
body_len (const uint8_t *p)
{
  return ((size_t) p[1] << 16) | ((size_t) p[2] << 8) | p[3];
}

int
gq_tls12_feed (gq_tls12 *t, const uint8_t **buf, size_t *len)
{
  if (t == NULL || buf == NULL || len == NULL || t->st == S12_NEW
      || t->st == S12_FAILED)
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
            return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
          if (*len >= 4 + n)
            {
              m.data = *buf;
              m.len = 4 + n;
              *buf += 4 + n;
              *len -= 4 + n;
              r = dispatch (t, m);
              if (r != GQ_OK)
                return r;
              continue;
            }
        }

      /* Slow path: accumulate a partial message.  */
      if (t->msg == NULL)
        {
          t->msg_cap = 4 + t->cfg.max_message_len;
          t->msg = malloc (t->msg_cap);
          if (t->msg == NULL)
            return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
        }
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
            return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
          if (t->msg_len == 4 + n)
            {
              gq_slice m = { t->msg, t->msg_len };

              t->msg_len = 0;
              r = dispatch (t, m);
              if (r != GQ_OK)
                return r;
            }
        }
    }
  return GQ_OK;
}

int
gq_tls12_change_cipher_spec (gq_tls12 *t)
{
  if (t == NULL || t->st == S12_NEW || t->st == S12_FAILED)
    return GQ_ERR_INVAL;
  /* A handshake message may not straddle the key change.  */
  if (t->msg_len != 0)
    return g12_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
  if (t->server)
    return g12_server_ccs (t);
  if (t->st != S12_C_WAIT_TICKET_OR_CCS && t->st != S12_C_WAIT_CCS)
    return g12_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
  /* A ticket the server announced must arrive before ChangeCipherSpec
     (RFC 5077 section 3.3).  */
  if (t->ticket_expected)
    return g12_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
  TRY (g12_install_read (t));
  t->st = S12_C_WAIT_FIN;
  return GQ_OK;
}

int
gq_tls12_dtls_prime (gq_tls12 *t, uint16_t rx_seq, uint16_t tx_seq)
{
  if (t == NULL || !t->dtls || !t->server || t->st != S12_S_WAIT_CH)
    return GQ_ERR_INVAL;
  t->rx_seq = rx_seq;
  t->tx_seq = tx_seq;
  return GQ_OK;
}

int
gq_tls12_expects_ccs (const gq_tls12 *t)
{
  if (t == NULL)
    return 0;
  return t->server ? t->st == S12_S_WAIT_CCS
                   : (t->st == S12_C_WAIT_CCS
                      || (t->st == S12_C_WAIT_TICKET_OR_CCS
                          && !t->ticket_expected));
}

int
gq_tls12_is_complete (const gq_tls12 *t)
{
  return t != NULL && t->st == S12_DONE;
}

int
gq_tls12_is_failed (const gq_tls12 *t)
{
  return t != NULL && t->st == S12_FAILED;
}

int
gq_tls12_alert (const gq_tls12 *t)
{
  return t == NULL ? -1 : t->alert;
}

int
gq_tls12_export (const gq_tls12 *t, const char *label, const uint8_t *context,
                 size_t context_len, uint8_t *out, size_t out_len)
{
  if (t == NULL || t->st != S12_DONE)
    return GQ_ERR_INVAL;
  return gq_tls12_exporter (t->hash, t->master, t->client_random,
                            t->server_random, label, context, context_len,
                            out, out_len);
}
