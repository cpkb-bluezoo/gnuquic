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

#include "tls_int.h"

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* ------------------------------------------------------------------ */
/* Creation                                                           */
/* ------------------------------------------------------------------ */

int
gq_tls_server_new (gq_tls **out, const gq_tls_server_config *cfg,
                   const gq_tls_sink *sink)
{
  gq_tls *t;
  int quic;

  if (out == NULL || cfg == NULL || sink == NULL || sink->send == NULL
      || sink->secret == NULL)
    return GQ_ERR_INVAL;
  if (cfg->select_credentials == NULL
      && (cfg->credentials.key == NULL || cfg->credentials.chain == NULL
          || cfg->credentials.n_chain == 0))
    return GQ_ERR_INVAL;
  quic = cfg->quic || cfg->transport_params != NULL;
  if (quic && (cfg->transport_params == NULL || cfg->n_alpn == 0))
    return GQ_ERR_INVAL;
  if (cfg->n_alpn && cfg->alpn == NULL)
    return GQ_ERR_INVAL;
  /* Never ask for client certificates without a way to check them.  */
  if (cfg->client_auth != GQ_CLIENT_AUTH_NONE && cfg->client_trust == NULL
      && sink->verify_peer == NULL)
    return GQ_ERR_INVAL;
  TRY (gq_crypto_init ());

  t = calloc (1, sizeof *t);
  if (t == NULL)
    return GQ_ERR_NOMEM;
  t->role = ROLE_SERVER;
  t->scfg = *cfg;
  t->sink = *sink;
  t->quic = quic;
  t->alert = -1;
  /* Reuse the fields the shared code reads from the client config.  */
  t->cfg.alpn = cfg->alpn;
  t->cfg.n_alpn = cfg->n_alpn;
  t->cfg.transport_params = cfg->transport_params;
  t->cfg.transport_params_len = cfg->transport_params_len;
  t->cfg.trust = cfg->client_trust;
  t->cfg.hooks = cfg->hooks;
  t->cfg.max_message_len = cfg->max_message_len ? cfg->max_message_len : 65536;

  gqi_filter_lists (t, cfg->suites, cfg->n_suites, cfg->groups, cfg->n_groups,
                    cfg->sigschemes, cfg->n_sigschemes);
  if (t->n_suites == 0 || t->n_groups == 0 || t->n_sigs == 0)
    {
      free (t);
      return GQ_ERR_INVAL;
    }
  t->st = ST_S_WAIT_CH1;
  *out = t;
  return GQ_OK;
}

int
gq_tls_early_data_offered (const gq_tls *t)
{
  return t != NULL && t->role == ROLE_SERVER && t->early_offered
    && !t->early_accepted;
}

/* ------------------------------------------------------------------ */
/* Sending helpers                                                    */
/* ------------------------------------------------------------------ */

/* Send a finished message at LEVEL, then hash it.  */
static int
send_at (gq_tls *t, enum gq_level level, const gq_wbuf *w)
{
  gq_slice m;

  if (gq_wbuf_status (w) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, gq_wbuf_status (w));
  m.data = w->p;
  m.len = w->len;
  TRY (gqi_emit (t, level, m.data, m.len));
  if (gqi_tr_update (t, m) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* ClientHello                                                        */
/* ------------------------------------------------------------------ */

/* Everything decided from the ClientHello.  */
struct choice
{
  gq_slice sni;			/* Empty if none.  */
  gq_slice tp;			/* Client transport parameters.  */
  int have_tp;
  gq_slice cookie;
  int have_cookie;
  gq_slice groups;		/* Client supported_groups list.  */
  gq_slice shares;		/* key_share entries.  */
  gq_slice alpn;		/* Client ALPN list.  */
  int have_alpn;
  int have_psk;			/* pre_shared_key present and usable.  */
  gq_slice psk_ids, psk_binders;
  const uint8_t *binders_start;
};

/* Check each key_share entry: group must be one the client says it
   supports, and no group repeats (RFC 8446 section 4.2.8).  */
static int
check_shares (gq_tls *t, const struct choice *c)
{
  gq_slice rest = c->shares, kx;
  uint16_t seen[MAX_GROUPS + 8];
  size_t n = 0, i;
  uint16_t g;
  int r;

  while ((r = gq_key_share_next (&rest, &g, &kx)) == 1)
    {
      if (!gq_u16_contains (c->groups, g) || n == sizeof seen / sizeof seen[0])
        return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      for (i = 0; i < n; i++)
        if (seen[i] == g)
          return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      seen[n++] = g;
    }
  if (r < 0)
    return gqi_fail_parse (t, r);
  return GQ_OK;
}

static int
select_alpn (gq_tls *t, const struct choice *c)
{
  size_t i;
  gq_slice list, name;

  t->info.alpn_len = 0;
  if (!c->have_alpn)
    {
      if (t->quic)		/* RFC 9001 section 8.1.  */
        return gqi_fail (t, GQ_ALERT_NO_APPLICATION_PROTOCOL, GQ_ERR_PROTOCOL);
      return GQ_OK;
    }
  if (t->cfg.n_alpn == 0)
    return GQ_OK;		/* We have no opinion: ignore the offer.  */
  for (i = 0; i < t->cfg.n_alpn; i++)
    {
      list = c->alpn;
      while (gq_alpn_next (&list, &name) == 1)
        if (name.len == t->cfg.alpn[i].len
            && memcmp (name.data, t->cfg.alpn[i].data, name.len) == 0)
          {
            if (name.len > sizeof t->info.alpn)
              break;
            memcpy (t->info.alpn, name.data, name.len);
            t->info.alpn_len = name.len;
            return GQ_OK;
          }
    }
  return gqi_fail (t, GQ_ALERT_NO_APPLICATION_PROTOCOL, GQ_ERR_PROTOCOL);
}

/* Server flight: ServerHello (or its retry) through Finished.  */
static int
send_flight (gq_tls *t, unsigned group, gq_slice kx)
{
  uint8_t sh_kx[GQ_KX_SHARE_MAX], shared[GQ_KX_SHARED_MAX];
  uint8_t th[GQ_MAX_HASH_LEN], content[64 + 34 + GQ_MAX_HASH_LEN];
  uint8_t sig[GQ_SIGNATURE_MAX], vd[GQ_MAX_HASH_LEN];
  size_t slen = 0, sharedlen = 0, cn, siglen, i, cap, total = 0;
  const gq_tls_credentials *cr = t->creds;
  uint8_t *buf;
  gq_wbuf w;
  gq_sh_params sp;
  uint8_t rnd[32];
  int r;

  r = gq_kx_respond (group, kx.data, kx.len, sh_kx, sizeof sh_kx, &slen,
                     shared, sizeof shared, &sharedlen);
  if (r != GQ_OK)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  t->info.group = (uint16_t) group;
  t->info.cipher_suite = t->suite;

  for (i = 0; !t->resumed && i < cr->n_chain; i++)
    total += cr->chain[i].len + 8;
  cap = total + 8192 + slen;
  buf = malloc (cap);
  if (buf == NULL)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);

  /* ServerHello, in the clear.  */
  r = gqi_rnd (t, rnd, 32);
  if (r != GQ_OK)
    {
      free (buf);
      return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
    }
  memset (&sp, 0, sizeof sp);
  sp.random = rnd;
  sp.session_id_echo = (gq_slice) { t->sid, t->sid_len };
  sp.cipher_suite = t->suite;
  sp.group = (uint16_t) group;
  sp.key_exchange = (gq_slice) { sh_kx, slen };
  sp.psk_selected = t->resumed;
  sp.psk_identity = (uint16_t) t->psk_index;
  t->info.resumed = t->resumed;
  gq_wbuf_init (&w, buf, cap);
  gq_build_server_hello (&w, &sp);
  r = send_at (t, GQ_LEVEL_INITIAL, &w);

  if (r == GQ_OK)
    r = t->resumed ? gq_ks_early (&t->ks, t->hash, t->sess.psk, t->hlen)
                   : gq_ks_early (&t->ks, t->hash, NULL, 0);
  /* 0-RTT: accept only a first use of this ticket, and only if no
     HelloRetryRequest happened.  The key comes from the early secret
     before the handshake secret replaces it.  */
  if (r == GQ_OK && t->early_candidate && !t->info.hello_retry)
    {
      uint32_t life = t->sess.lifetime < 604800 ? t->sess.lifetime : 604800;
      uint64_t expires = t->sess.created_ms + (uint64_t) life * 1000;

      if (t->scfg.replay_check (t->scfg.replay_user, t->psk_id_hash, expires,
                                gqi_now_ms (t)))
        t->early_accepted = 1;
    }
  if (r == GQ_OK && t->early_accepted)
    {
      uint8_t ec[GQ_MAX_HASH_LEN];

      r = gq_ks_client_early_traffic (&t->ks, t->hash_ch, ec);
      if (r == GQ_OK)
        r = gqi_emit_secret (t, GQ_LEVEL_EARLY, GQ_DIR_READ, ec);
      gq_wipe (ec, sizeof ec);
      t->info.early_data_accepted = 1;
    }
  if (r == GQ_OK)
    r = gq_ks_handshake (&t->ks, shared, sharedlen);
  gq_wipe (shared, sizeof shared);
  if (r == GQ_OK)
    r = gqi_tr_hash (t, th);
  if (r == GQ_OK)
    r = gq_ks_handshake_traffic (&t->ks, th, t->chs, t->shs);
  if (r != GQ_OK)
    {
      free (buf);
      return t->st == ST_FAILED ? r : gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
    }
  r = gqi_emit_secret (t, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE, t->shs);
  /* Over a byte stream the client keeps using its early keys until
     EndOfEarlyData, so the handshake read keys wait for it.  */
  if (r == GQ_OK && t->early_accepted && !t->quic)
    t->hs_read_deferred = 1;
  else if (r == GQ_OK)
    r = gqi_emit_secret (t, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ, t->chs);
  if (r != GQ_OK)
    {
      free (buf);
      return r;
    }

  /* EncryptedExtensions.  */
  {
    gq_ext exts[4];
    size_t n = 0;
    uint8_t alpn_val[300];
    gq_wbuf a;

    if (t->info.alpn_len)
      {
        gq_wbuf_init (&a, alpn_val, sizeof alpn_val);
        gq_wbuf_open (&a, 2);
        gq_wbuf_open (&a, 1);
        gq_wbuf_bytes (&a, t->info.alpn, t->info.alpn_len);
        gq_wbuf_close (&a);
        gq_wbuf_close (&a);
        exts[n].type = GQ_EXT_ALPN;
        exts[n].value = (gq_slice) { alpn_val, a.len };
        n++;
      }
    if (t->early_accepted)
      {
        exts[n].type = GQ_EXT_EARLY_DATA;	/* Accepted: empty.  */
        exts[n].value = (gq_slice) { NULL, 0 };
        n++;
      }
    if (t->quic)
      {
        exts[n].type = GQ_EXT_QUIC_TRANSPORT_PARAMETERS;
        exts[n].value = (gq_slice) { t->cfg.transport_params,
                                     t->cfg.transport_params_len };
        n++;
      }
    gq_wbuf_init (&w, buf, cap);
    gq_build_encrypted_extensions (&w, exts, n);
    r = send_at (t, GQ_LEVEL_HANDSHAKE, &w);
  }

  /* CertificateRequest.  */
  if (r == GQ_OK && !t->resumed && t->scfg.client_auth != GQ_CLIENT_AUTH_NONE)
    {
      gq_wbuf_init (&w, buf, cap);
      gq_wbuf_hs_open (&w, GQ_HS_CERTIFICATE_REQUEST);
      gq_wbuf_open (&w, 1);			/* Empty context.  */
      gq_wbuf_close (&w);
      gq_wbuf_open (&w, 2);
      gq_wbuf_ext_open (&w, GQ_EXT_SIGNATURE_ALGORITHMS);
      gq_wbuf_open (&w, 2);
      for (i = 0; i < t->n_sigs; i++)
        gq_wbuf_u16 (&w, t->sigs[i]);
      gq_wbuf_close (&w);
      gq_wbuf_close (&w);
      gq_wbuf_close (&w);
      gq_wbuf_close (&w);
      t->info.client_auth_requested = 1;
      r = send_at (t, GQ_LEVEL_HANDSHAKE, &w);
    }

  /* Certificate and CertificateVerify (a resumed session authenticates
     with the PSK instead).  */
  if (r == GQ_OK && !t->resumed)
    {
      gq_wbuf_init (&w, buf, cap);
      gq_build_certificate (&w, (gq_slice) { NULL, 0 }, cr->chain,
                            cr->n_chain);
      r = send_at (t, GQ_LEVEL_HANDSHAKE, &w);
    }
  if (r == GQ_OK && !t->resumed)
    {
      if (gqi_tr_hash (t, th) != GQ_OK)
        r = gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
      else
        {
          cn = gqi_cv_content (content, 1, th, t->hlen);
          if (gq_privkey_sign (cr->key, t->sign_scheme, content, cn, sig,
                               sizeof sig, &siglen) != GQ_OK)
            r = gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
          else
            {
              gq_wbuf_init (&w, buf, cap);
              gq_build_certificate_verify (&w, t->sign_scheme,
                                           (gq_slice) { sig, siglen });
              r = send_at (t, GQ_LEVEL_HANDSHAKE, &w);
            }
        }
    }

  /* Finished, then our application secrets (the server may send at once).  */
  if (r == GQ_OK)
    {
      if (gqi_tr_hash (t, th) != GQ_OK
          || gq_finished_verify_data (t->hash, t->shs, th, vd) != GQ_OK)
        r = gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
      else
        {
          gq_wbuf_init (&w, buf, cap);
          gq_build_finished (&w, (gq_slice) { vd, t->hlen });
          r = send_at (t, GQ_LEVEL_HANDSHAKE, &w);
        }
    }
  free (buf);
  if (r != GQ_OK)
    return r;
  if (gqi_tr_hash (t, th) != GQ_OK || gq_ks_master (&t->ks) != GQ_OK
      || gq_ks_app_traffic (&t->ks, th, t->cas, t->sas) != GQ_OK
      || gq_ks_exporter_master (&t->ks, th, t->exp) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  TRY (gqi_emit_secret (t, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE, t->sas));

  if (t->hs_read_deferred)
    t->st = ST_S_WAIT_EOED;
  else
    t->st = (!t->resumed && t->scfg.client_auth != GQ_CLIENT_AUTH_NONE)
      ? ST_S_WAIT_CCERT : ST_S_WAIT_FIN;
  return GQ_OK;
}

static int
send_hrr (gq_tls *t, unsigned group)
{
  uint8_t buf[256];
  gq_sh_params sp;
  gq_wbuf w;

  memset (&sp, 0, sizeof sp);
  sp.hello_retry_request = 1;
  sp.session_id_echo = (gq_slice) { t->sid, t->sid_len };
  sp.cipher_suite = t->suite;
  sp.group = (uint16_t) group;
  if (t->scfg.hello_retry_cookie)
    {
      TRY (gqi_rnd (t, t->hrr_cookie, sizeof t->hrr_cookie));
      t->hrr_cookie_sent = 1;
      sp.cookie = (gq_slice) { t->hrr_cookie, sizeof t->hrr_cookie };
    }
  gq_wbuf_init (&w, buf, sizeof buf);
  gq_build_server_hello (&w, &sp);
  if (gq_wbuf_status (&w) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, gq_wbuf_status (&w));
  /* The transcript restarts from message_hash (ClientHello1).  */
  if (gq_transcript_hello_retry (t->tr) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  TRY (gqi_emit (t, GQ_LEVEL_INITIAL, w.p, w.len));
  if (gqi_tr_update (t, (gq_slice) { w.p, w.len }) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  t->hrr_group = (uint16_t) group;
  t->info.hello_retry = 1;
  t->st = ST_S_WAIT_CH2;
  return GQ_OK;
}

/* Is the session behind an identity acceptable for this ClientHello?  */
static int
psk_acceptable (gq_tls *t, const gq_session_state *s, const gq_client_hello *ch,
                const struct choice *c)
{
  enum gq_aead a;
  enum gq_hash h;
  uint64_t now = gqi_now_ms (t), life;

  if (!gqi_suite_params (s->cipher_suite, &a, &h) || s->psk_len != gq_hash_size (h))
    return 0;
  /* The suite must be one the client offers and we allow.  */
  if (!gq_u16_contains (ch->cipher_suites, s->cipher_suite)
      || !gqi_in_list (t->suites, t->n_suites, s->cipher_suite))
    return 0;
  life = s->lifetime < 604800 ? s->lifetime : 604800;
  if (s->created_ms > now + 60000 || now - s->created_ms > life * 1000)
    return 0;
  /* A ticket is bound to the server name it was issued for.  */
  if (s->server_name_len
      && (s->server_name_len != c->sni.len
          || memcmp (s->server_name, c->sni.data, c->sni.len) != 0))
    return 0;
  /* Client certificates required: only sessions that had one may resume.  */
  if (t->scfg.client_auth == GQ_CLIENT_AUTH_REQUIRED
      && !s->client_authenticated)
    return 0;
  return 1;
}

/* Find the first identity that opens and is acceptable.  */
static int
choose_psk (gq_tls *t, const gq_client_hello *ch, const struct choice *c)
{
  gq_slice ids = c->psk_ids, id;
  uint32_t age;
  size_t index = 0;
  gq_session_state s;
  int ok;

  while (gq_psk_identity_next (&ids, &id, &age) == 1)
    {
      ok = 0;
      if (t->scfg.ticket_keys
          && gq_ticket_open (t->scfg.ticket_keys, id.data, id.len, &s, NULL)
             == GQ_OK)
        ok = 1;
      else if (t->scfg.psk_lookup
               && t->scfg.psk_lookup (t->scfg.psk_user, id.data, id.len, &s)
                  == 0)
        ok = 1;
      if (ok && psk_acceptable (t, &s, ch, c))
        {
          t->sess = s;
          t->psk_index = index;
          t->psk_age = age;
          gq_hash_compute (GQ_HASH_SHA256, id.data, id.len, t->psk_id_hash, 32);
          gq_wipe (&s, sizeof s);
          return 1;
        }
      gq_wipe (&s, sizeof s);
      index++;
    }
  return 0;
}

/* Check the binder of the accepted identity against the transcript so far
   plus the ClientHello truncated at the binders (RFC 8446 section 4.2.11.2).  */
static int
verify_binder (gq_tls *t, gq_slice msg, const struct choice *c)
{
  gq_slice binders = c->psk_binders, b;
  gq_transcript *tmp;
  uint8_t th[GQ_MAX_HASH_LEN], bk[GQ_MAX_HASH_LEN], want[GQ_MAX_HASH_LEN];
  gq_ks ks;
  size_t i;
  int r;

  for (i = 0; i <= t->psk_index; i++)
    if (gq_psk_binder_next (&binders, &b) != 1)
      return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  if (b.len != t->hlen)
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);

  r = gq_transcript_copy (t->tr, &tmp);
  if (r == GQ_OK)
    r = gq_transcript_update (tmp, msg.data, (size_t) (c->binders_start - msg.data));
  if (r == GQ_OK)
    r = gq_transcript_hash (tmp, th, t->hlen);
  gq_transcript_free (tmp);
  if (r == GQ_OK)
    r = gq_ks_early (&ks, t->hash, t->sess.psk, t->hlen);
  if (r == GQ_OK)
    r = gq_ks_binder_key (&ks, 1, bk);
  if (r == GQ_OK)
    r = gq_finished_verify_data (t->hash, bk, th, want);
  gq_wipe (bk, sizeof bk);
  gq_ks_wipe (&ks);
  if (r != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
  if (!gq_ct_equal (want, b.data, t->hlen))
    return gqi_fail (t, GQ_ALERT_DECRYPT_ERROR, GQ_ERR_CRYPTO);
  return GQ_OK;
}

/* May early data be accepted on this resumption?  Everything the RFC
   requires short of the replay check itself (RFC 8446 section 4.2.10 and
   section 8): early data enabled, the first identity, a ticket that allows
   it, the same ALPN as the original connection, and a ticket age that
   agrees with ours (a stale one may be a replay).  */
static int
early_eligible (gq_tls *t)
{
  uint64_t now = gqi_now_ms (t);
  uint32_t window = t->scfg.early_data_window_ms
    ? t->scfg.early_data_window_ms : 10000;
  uint32_t client_age = t->psk_age - t->sess.age_add;	/* Modulo 2^32.  */
  uint32_t server_age = (uint32_t) (now > t->sess.created_ms
                                    ? now - t->sess.created_ms : 0);
  int32_t diff = (int32_t) (client_age - server_age);

  if (t->scfg.max_early_data == 0 || t->scfg.replay_check == NULL)
    return 0;
  if (t->psk_index != 0 || t->sess.max_early_data == 0)
    return 0;
  if (t->info.alpn_len != t->sess.alpn_len
      || memcmp (t->info.alpn, t->sess.alpn, t->sess.alpn_len) != 0)
    return 0;
  if (diff < 0)
    diff = -diff;
  return (uint32_t) diff <= window;
}

static int
on_client_hello (gq_tls *t, gq_slice msg, gq_slice body)
{
  gq_client_hello ch;
  struct choice c;
  gq_slice v, list, rest, kx = { NULL, 0 };
  unsigned type, last = 0;
  uint16_t g;
  int r, second = t->st == ST_S_WAIT_CH2;
  size_t i;
  unsigned group = 0;
  int have_share = 0;
  uint8_t suites_hash[32];

  memset (&c, 0, sizeof c);
  r = gq_client_hello_parse (body, &ch);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  if (ch.legacy_version < 0x0303)
    return gqi_fail (t, GQ_ALERT_PROTOCOL_VERSION, GQ_ERR_PROTOCOL);

  /* Only TLS 1.3 is served: the client must offer it explicitly.  */
  if (!gq_ext_find (ch.extensions, GQ_EXT_SUPPORTED_VERSIONS, &v))
    return gqi_fail (t, GQ_ALERT_PROTOCOL_VERSION, GQ_ERR_PROTOCOL);
  if (gq_list_u16 (v, 1, &list) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
  if (!gq_u16_contains (list, 0x0304))
    return gqi_fail (t, GQ_ALERT_PROTOCOL_VERSION, GQ_ERR_PROTOCOL);

  /* A pre_shared_key must come last, with its modes extension.  */
  rest = ch.extensions;
  while (gq_ext_next (&rest, &type, &v) == 1)
    last = type;
  {
    gq_slice modes, pskv;
    int has_psk = gq_ext_find (ch.extensions, GQ_EXT_PRE_SHARED_KEY, &pskv);
    int has_modes = gq_ext_find (ch.extensions, GQ_EXT_PSK_KEY_EXCHANGE_MODES, &v);

    if (has_modes)
      {
        r = gq_ext_psk_modes (v, &modes);
        if (r != GQ_OK)
          return gqi_fail_parse (t, r);
        for (i = 0; i < modes.len; i++)
          if (modes.data[i] == GQ_PSK_DHE_KE)
            t->cli_psk_dhe = 1;
      }
    if (has_psk)
      {
        if (last != GQ_EXT_PRE_SHARED_KEY)
          return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        if (!has_modes)
          return gqi_fail (t, GQ_ALERT_MISSING_EXTENSION, GQ_ERR_PROTOCOL);
        r = gq_ext_psk_client (pskv, &c.psk_ids, &c.psk_binders,
                               &c.binders_start);
        if (r != GQ_OK)
          return gqi_fail_parse (t, r);
        /* One binder per identity.  */
        {
          gq_slice a = c.psk_ids, b = c.psk_binders, x;
          uint32_t age;
          size_t ni = 0, nb = 0;

          while ((r = gq_psk_identity_next (&a, &x, &age)) == 1)
            ni++;
          if (r < 0)
            return gqi_fail_parse (t, r);
          while ((r = gq_psk_binder_next (&b, &x)) == 1)
            nb++;
          if (r < 0)
            return gqi_fail_parse (t, r);
          if (ni != nb)
            return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        }
        /* Only the (EC)DHE mode is supported, and only with a way to
           recognise tickets.  */
        c.have_psk = t->cli_psk_dhe
          && (t->scfg.ticket_keys != NULL || t->scfg.psk_lookup != NULL);
      }
  }
  if (gq_ext_find (ch.extensions, GQ_EXT_EARLY_DATA, &v))
    {
      if (second)		/* RFC 8446 section 4.2.10.  */
        return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      t->early_offered = 1;
    }

  /* Signature algorithms, groups and shares are all mandatory here.  */
  if (!gq_ext_find (ch.extensions, GQ_EXT_SIGNATURE_ALGORITHMS, &v))
    return gqi_fail (t, GQ_ALERT_MISSING_EXTENSION, GQ_ERR_PROTOCOL);
  if (gq_list_u16 (v, 2, &list) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
  t->n_cli_sigs = 0;
  for (i = 0; i < gq_u16_count (list) && t->n_cli_sigs < MAX_SIGS; i++)
    t->cli_sigs[t->n_cli_sigs++] = (uint16_t) gq_u16_at (list, i);
  if (!gq_ext_find (ch.extensions, GQ_EXT_SUPPORTED_GROUPS, &v)
      || !gq_ext_find (ch.extensions, GQ_EXT_KEY_SHARE, &rest))
    return gqi_fail (t, GQ_ALERT_MISSING_EXTENSION, GQ_ERR_PROTOCOL);
  if (gq_list_u16 (v, 2, &c.groups) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
  r = gq_ext_key_share_client (rest, &c.shares);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  TRY (check_shares (t, &c));

  if (gq_ext_find (ch.extensions, GQ_EXT_SERVER_NAME, &v))
    {
      r = gq_ext_server_name (v, &c.sni);
      if (r != GQ_OK)
        return gqi_fail_parse (t, r);
    }
  if (gq_ext_find (ch.extensions, GQ_EXT_ALPN, &v))
    {
      r = gq_ext_alpn (v, &c.alpn);
      if (r != GQ_OK)
        return gqi_fail_parse (t, r);
      c.have_alpn = 1;
    }
  if (t->quic)
    {
      if (!gq_ext_find (ch.extensions, GQ_EXT_QUIC_TRANSPORT_PARAMETERS, &c.tp))
        return gqi_fail (t, GQ_ALERT_MISSING_EXTENSION, GQ_ERR_PROTOCOL);
      c.have_tp = 1;
    }
  if (gq_ext_find (ch.extensions, GQ_EXT_COOKIE, &v))
    {
      r = gq_ext_cookie (v, &c.cookie);
      if (r != GQ_OK)
        return gqi_fail_parse (t, r);
      c.have_cookie = 1;
    }
  TRY (gq_hash_compute (GQ_HASH_SHA256, ch.cipher_suites.data,
                        ch.cipher_suites.len, suites_hash, 32));

  if (!second)
    {
      int have_sess;

      if (c.sni.len)
        {
          memcpy (t->sni, c.sni.data, c.sni.len);
          t->sni[c.sni.len] = 0;
          t->sni_len = c.sni.len;
          memcpy (t->info.server_name, c.sni.data, c.sni.len);
          t->info.server_name[c.sni.len] = 0;
          t->info.server_name_len = c.sni.len;
        }

      /* A usable ticket decides the cipher suite; otherwise server
         preference among what the client offers.  */
      have_sess = c.have_psk && choose_psk (t, &ch, &c);
      t->suite = 0;
      if (have_sess)
        t->suite = t->sess.cipher_suite;
      for (i = 0; i < t->n_suites && t->suite == 0; i++)
        if (gq_u16_contains (ch.cipher_suites, t->suites[i]))
          t->suite = t->suites[i];
      if (t->suite == 0 || !gqi_suite_params (t->suite, &t->aead, &t->hash))
        return gqi_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_UNSUPPORTED);
      t->hlen = gq_hash_size (t->hash);
      memcpy (t->ch_random, ch.random, 32);
      memcpy (t->ch_suites_hash, suites_hash, 32);
      memcpy (t->sid, ch.session_id.data, ch.session_id.len);
      t->sid_len = ch.session_id.len;
      if (gq_transcript_new (&t->tr, t->hash) != GQ_OK)
        return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
      t->resumed = have_sess;

      if (!t->resumed)
        {
          /* Credentials for the requested name.  */
          t->creds = t->scfg.select_credentials
            ? t->scfg.select_credentials (t->scfg.select_user,
                                          t->sni_len ? t->sni : NULL)
            : &t->scfg.credentials;
          if (t->creds == NULL || t->creds->key == NULL
              || t->creds->n_chain == 0)
            return gqi_fail (t, 112 /* unrecognized_name */, GQ_ERR_PROTOCOL);

          /* Signature scheme: the client's first choice that we allow and
             the key can produce.  */
          t->sign_scheme = 0;
          for (i = 0; i < t->n_cli_sigs && !t->sign_scheme; i++)
            if (gqi_in_list (t->sigs, t->n_sigs, t->cli_sigs[i])
                && gq_privkey_supports (t->creds->key, t->cli_sigs[i]))
              t->sign_scheme = t->cli_sigs[i];
          if (!t->sign_scheme)
            return gqi_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_UNSUPPORTED);
        }
      TRY (select_alpn (t, &c));
    }
  else
    {
      /* ClientHello2 must repeat ClientHello1 apart from the key share
         (RFC 8446 section 4.1.2).  */
      if (memcmp (t->ch_random, ch.random, 32) != 0
          || ch.session_id.len != t->sid_len
          || memcmp (ch.session_id.data, t->sid, t->sid_len) != 0
          || memcmp (t->ch_suites_hash, suites_hash, 32) != 0)
        return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      if (t->hrr_cookie_sent)
        {
          if (!c.have_cookie)
            return gqi_fail (t, GQ_ALERT_MISSING_EXTENSION, GQ_ERR_PROTOCOL);
          if (c.cookie.len != sizeof t->hrr_cookie
              || !gq_ct_equal (c.cookie.data, t->hrr_cookie,
                               sizeof t->hrr_cookie))
            return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        }
      if (t->resumed)
        {
          /* The ticket must be the one from ClientHello1.  */
          uint8_t before[32];

          memcpy (before, t->psk_id_hash, 32);
          if (!c.have_psk || !choose_psk (t, &ch, &c)
              || !gq_ct_equal (before, t->psk_id_hash, 32))
            return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
        }
    }

  if (t->resumed)
    TRY (verify_binder (t, msg, &c));

  if (gqi_tr_update (t, msg) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);

  /* Early data needs the hash of ClientHello1 alone, for its key.  */
  if (!second && t->early_offered && t->resumed)
    {
      t->early_candidate = early_eligible (t);
      if (t->early_candidate && gqi_tr_hash (t, t->hash_ch) != GQ_OK)
        return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
    }

  /* Key exchange group.  */
  if (second)
    {
      /* Exactly one share, for the group we asked for.  */
      rest = c.shares;
      if (gq_key_share_next (&rest, &g, &kx) != 1 || g != t->hrr_group
          || rest.len != 0)
        return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      group = g;
      have_share = 1;
    }
  else
    {
      /* Prefer a group the client already sent a share for, in our order.  */
      for (i = 0; i < t->n_groups && !have_share; i++)
        {
          if (!gq_u16_contains (c.groups, t->groups[i]))
            continue;
          rest = c.shares;
          while (gq_key_share_next (&rest, &g, &kx) == 1)
            if (g == t->groups[i])
              {
                group = g;
                have_share = 1;
                break;
              }
        }
      if (!have_share)
        {
          /* Ask for the most preferred group we share with the client.  */
          for (i = 0; i < t->n_groups; i++)
            if (gq_u16_contains (c.groups, t->groups[i]))
              return send_hrr (t, t->groups[i]);
          return gqi_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_UNSUPPORTED);
        }
    }

  if (c.have_tp && t->sink.peer_params
      && t->sink.peer_params (t->sink.user, c.tp.data, c.tp.len))
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
  return send_flight (t, group, kx);
}

/* ------------------------------------------------------------------ */
/* Client authentication and Finished                                 */
/* ------------------------------------------------------------------ */

/* The end of the early data (byte streams only).  Now the client's
   records are under the handshake keys.  */
static int
on_end_of_early_data (gq_tls *t, gq_slice msg, gq_slice body)
{
  if (body.len != 0)
    return gqi_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
  if (gqi_tr_update (t, msg) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  t->hs_read_deferred = 0;
  TRY (gqi_emit_secret (t, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ, t->chs));
  t->st = (!t->resumed && t->scfg.client_auth != GQ_CLIENT_AUTH_NONE)
    ? ST_S_WAIT_CCERT : ST_S_WAIT_FIN;
  return GQ_OK;
}

static int
on_client_certificate (gq_tls *t, gq_slice msg, gq_slice body)
{
  gq_slice ctx, entries, der, ex, chain[MAX_CHAIN];
  size_t n = 0;
  int r;

  r = gq_certificate_parse (body, &ctx, &entries);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  if (ctx.len != 0)		/* Must echo our (empty) request context.  */
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  while ((r = gq_cert_entry_next (&entries, &der, &ex)) == 1)
    {
      if (n == MAX_CHAIN)
        return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
      if (ex.len != 0)
        return gqi_fail (t, GQ_ALERT_UNSUPPORTED_EXTENSION, GQ_ERR_PROTOCOL);
      chain[n++] = der;
    }
  if (r < 0)
    return gqi_fail_parse (t, r);

  if (gqi_tr_update (t, msg) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);

  if (n == 0)
    {
      /* The client has no certificate to offer.  */
      if (t->scfg.client_auth == GQ_CLIENT_AUTH_REQUIRED)
        return gqi_fail (t, 116 /* certificate_required */, GQ_ERR_CERT);
      t->st = ST_S_WAIT_FIN;
      return GQ_OK;
    }

  if (t->sink.verify_peer)
    {
      if (t->sink.verify_peer (t->sink.user, chain, n, NULL))
        return gqi_fail (t, GQ_ALERT_BAD_CERTIFICATE, GQ_ERR_CERT);
    }
  else
    {
      enum gq_cert_error why;

      if (gq_trust_verify_chain_for (t->scfg.client_trust, chain, n, NULL,
                                     GQ_PURPOSE_CLIENT, &why) != GQ_OK)
        return gqi_fail (t, gqi_cert_error_alert (why), GQ_ERR_CERT);
    }
  if (gq_pubkey_from_cert (&t->peer_key, chain[0].data, chain[0].len)
      != GQ_OK)
    return gqi_fail (t, GQ_ALERT_BAD_CERTIFICATE, GQ_ERR_CERT);
  t->st = ST_S_WAIT_CCV;
  return GQ_OK;
}

static int
on_client_certificate_verify (gq_tls *t, gq_slice msg, gq_slice body)
{
  uint16_t scheme;
  gq_slice sig;
  uint8_t th[GQ_MAX_HASH_LEN], content[64 + 34 + GQ_MAX_HASH_LEN];
  size_t n;
  int r;

  r = gq_certificate_verify_parse (body, &scheme, &sig);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  /* Only a scheme we listed in the CertificateRequest.  */
  if (!gqi_in_list (t->sigs, t->n_sigs, scheme))
    return gqi_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  if (gqi_tr_hash (t, th) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  n = gqi_cv_content (content, 0, th, t->hlen);
  if (gq_pubkey_verify (t->peer_key, scheme, content, n, sig.data,
                        sig.len) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_DECRYPT_ERROR, GQ_ERR_CRYPTO);
  if (gqi_tr_update (t, msg) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  t->client_verified = 1;
  t->st = ST_S_WAIT_FIN;
  return GQ_OK;
}

/* Issue NewSessionTickets under the current keys (RFC 8446 section 4.6.1).
   They are post-handshake messages and are not part of the transcript.  */
static int
send_tickets (gq_tls *t)
{
  unsigned n = t->scfg.n_tickets ? t->scfg.n_tickets : 2, i;
  uint32_t life = t->scfg.ticket_lifetime ? t->scfg.ticket_lifetime : 86400;
  uint64_t now = gqi_now_ms (t);

  if (n > 8)
    n = 8;
  if (life > 604800)
    life = 604800;
  for (i = 0; i < n; i++)
    {
      gq_session_state s;
      uint8_t nonce[1], ticket[GQ_TICKET_MAX], buf[GQ_TICKET_MAX + 64], age[4];
      size_t tn;
      gq_wbuf w;
      int r;

      memset (&s, 0, sizeof s);
      nonce[0] = (uint8_t) i;
      s.cipher_suite = t->suite;
      r = gq_resumption_psk (t->hash, t->resm, nonce, 1, s.psk);
      if (r == GQ_OK)
        r = gqi_rnd (t, age, sizeof age);
      if (r != GQ_OK)
        return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
      s.psk_len = t->hlen;
      s.created_ms = now;
      s.age_add = ((uint32_t) age[0] << 24) | ((uint32_t) age[1] << 16)
        | ((uint32_t) age[2] << 8) | age[3];
      s.lifetime = life;
      s.client_authenticated = t->client_verified
        || (t->resumed && t->sess.client_authenticated);
      s.server_name_len = t->sni_len;
      memcpy (s.server_name, t->sni, t->sni_len);
      s.alpn_len = t->info.alpn_len;
      memcpy (s.alpn, t->info.alpn, t->info.alpn_len);
      /* Advertise early data if we accept any: QUIC fixes the limit at the
         maximum (RFC 9001 section 4.6.1).  */
      s.max_early_data = t->scfg.max_early_data
        ? (t->quic ? 0xffffffffU : t->scfg.max_early_data) : 0;
      r = gq_ticket_seal (t->scfg.ticket_keys, &s, ticket, sizeof ticket, &tn);
      if (r != GQ_OK)
        {
          gq_wipe (&s, sizeof s);
          return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
        }
      {
        uint8_t max_be[4];
        gq_ext ex;

        max_be[0] = (uint8_t) (s.max_early_data >> 24);
        max_be[1] = (uint8_t) (s.max_early_data >> 16);
        max_be[2] = (uint8_t) (s.max_early_data >> 8);
        max_be[3] = (uint8_t) s.max_early_data;
        ex.type = GQ_EXT_EARLY_DATA;
        ex.value = (gq_slice) { max_be, 4 };
        gq_wbuf_init (&w, buf, sizeof buf);
        gq_build_new_session_ticket (&w, life, ((uint32_t) age[0] << 24)
                                     | ((uint32_t) age[1] << 16)
                                     | ((uint32_t) age[2] << 8) | age[3],
                                     (gq_slice) { nonce, 1 },
                                     (gq_slice) { ticket, tn }, &ex,
                                     s.max_early_data ? 1 : 0);
      }
      gq_wipe (&s, sizeof s);
      if (gq_wbuf_status (&w) != GQ_OK)
        return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, gq_wbuf_status (&w));
      TRY (gqi_emit (t, GQ_LEVEL_APPLICATION, buf, w.len));
    }
  return GQ_OK;
}

static int
on_client_finished (gq_tls *t, gq_slice msg, gq_slice body)
{
  gq_slice verify;
  uint8_t th[GQ_MAX_HASH_LEN], want[GQ_MAX_HASH_LEN];
  int r;

  r = gq_finished_parse (body, t->hlen, &verify);
  if (r != GQ_OK)
    return gqi_fail_parse (t, r);
  if (gqi_tr_hash (t, th) != GQ_OK
      || gq_finished_verify_data (t->hash, t->chs, th, want) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  if (!gq_ct_equal (want, verify.data, t->hlen))
    return gqi_fail (t, GQ_ALERT_DECRYPT_ERROR, GQ_ERR_CRYPTO);
  if (gqi_tr_update (t, msg) != GQ_OK || gqi_tr_hash (t, th) != GQ_OK
      || gq_ks_resumption_master (&t->ks, th, t->resm) != GQ_OK)
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);

  /* Now the client's application data can be read.  */
  TRY (gqi_emit_secret (t, GQ_LEVEL_APPLICATION, GQ_DIR_READ, t->cas));
  t->info.client_auth_sent = t->client_verified
    || (t->resumed && t->sess.client_authenticated);
  if (t->scfg.ticket_keys && t->cli_psk_dhe)
    TRY (send_tickets (t));
  t->early_offered = 0;		/* No more early records can arrive.  */
  t->st = ST_CONNECTED;
  if (t->sink.complete && t->sink.complete (t->sink.user, &t->info))
    return gqi_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_HANDLER);
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                           */
/* ------------------------------------------------------------------ */

int
gqi_server_dispatch (gq_tls *t, enum gq_level level, gq_slice msg)
{
  unsigned type = msg.data[0];
  gq_slice body = { msg.data + 4, msg.len - 4 };

  switch (t->st)
    {
    case ST_S_WAIT_CH1:
    case ST_S_WAIT_CH2:
      if (type == GQ_HS_CLIENT_HELLO && level == GQ_LEVEL_INITIAL)
        return on_client_hello (t, msg, body);
      break;
    case ST_S_WAIT_EOED:
      if (type == GQ_HS_END_OF_EARLY_DATA && level == GQ_LEVEL_EARLY)
        return on_end_of_early_data (t, msg, body);
      break;
    case ST_S_WAIT_CCERT:
      if (type == GQ_HS_CERTIFICATE && level == GQ_LEVEL_HANDSHAKE)
        return on_client_certificate (t, msg, body);
      break;
    case ST_S_WAIT_CCV:
      if (type == GQ_HS_CERTIFICATE_VERIFY && level == GQ_LEVEL_HANDSHAKE)
        return on_client_certificate_verify (t, msg, body);
      break;
    case ST_S_WAIT_FIN:
      if (type == GQ_HS_FINISHED && level == GQ_LEVEL_HANDSHAKE)
        return on_client_finished (t, msg, body);
      break;
    case ST_CONNECTED:
      if (type == GQ_HS_KEY_UPDATE && level == GQ_LEVEL_APPLICATION)
        return gqi_on_key_update (t, body);
      break;
    default:
      break;
    }
  return gqi_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
}
