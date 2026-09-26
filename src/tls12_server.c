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

/* TLS 1.2 engine: the server.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/crypto.h>

#include "tls12_int.h"
#include "tls_int.h"		/* gqi_cert_error_alert */

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

#define DEFAULT_TICKET_LIFETIME 86400u
#define MAX_TICKET_LIFETIME 604800u
/* Alert codes with no enumerator.  */
#define ALERT_UNRECOGNIZED_NAME 112

int
gq_tls12_server_new (gq_tls12 **out, const gq_tls_server_config *cfg,
                     const gq_tls12_sink *sink)
{
  gq_tls12 *t;

  if (out == NULL || cfg == NULL || sink == NULL || sink->send == NULL
      || sink->change_keys == NULL)
    return GQ_ERR_INVAL;
  if (cfg->quic || cfg->transport_params)
    return GQ_ERR_INVAL;
  if (cfg->select_credentials == NULL
      && (cfg->credentials.key == NULL || cfg->credentials.chain == NULL
          || cfg->credentials.n_chain == 0))
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
  t->server = 1;
  t->dtls = cfg->dtls != 0;
  t->scfg = *cfg;
  t->sink = *sink;
  t->alert = -1;
  t->cfg.alpn = cfg->alpn;
  t->cfg.n_alpn = cfg->n_alpn;
  t->cfg.trust = cfg->client_trust;
  t->cfg.hooks = cfg->hooks;
  t->cfg.max_message_len = cfg->max_message_len ? cfg->max_message_len : 65536;
  g12_filter (t, cfg->suites, cfg->n_suites, cfg->sigschemes,
              cfg->n_sigschemes);
  if (t->n_suites == 0 || t->n_sigs == 0)
    {
      free (t);
      return GQ_ERR_INVAL;
    }
  t->st = S12_S_WAIT_CH;
  *out = t;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* ClientHello                                                        */
/* ------------------------------------------------------------------ */

/* Everything read from the ClientHello's extensions.  */
struct choice
{
  gq_slice alpn;
  int have_alpn;
  gq_slice sigalgs;		/* Raw list.  */
  gq_slice ticket;
  int have_ticket_ext;
};

/* Does the key suit an RSA (1) or ECDSA (0) certificate suite?  */
static int
key_matches_suite (const gq_privkey *key, unsigned suite)
{
  if (gq_tls12_suite_is_rsa (suite))
    return gq_privkey_supports (key, GQ_SIG_RSA_PKCS1_SHA256);
  return gq_privkey_supports (key, GQ_SIG_ECDSA_SECP256R1_SHA256)
    || gq_privkey_supports (key, GQ_SIG_ECDSA_SECP384R1_SHA384);
}

/* Read and check the extensions we care about.  Anything else is ignored,
   as RFC 5246 requires of unknown extensions.  */
static int
read_exts (gq_tls12 *t, const gq_client_hello *ch, struct choice *c)
{
  gq_slice v, list;
  int r;

  memset (c, 0, sizeof *c);

  /* supported_versions, if sent, must include TLS 1.2 (RFC 9846 section
     1.4 makes it a MUST for 1.2 ClientHellos to be consistent; absence
     is tolerated).  */
  if (gq_ext_find (ch->extensions, GQ_EXT_SUPPORTED_VERSIONS, &v))
    {
      r = gq_list_u16 (v, 1, &list);
      if (r != GQ_OK)
        return g12_fail_parse (t, r);
      if (!gq_u16_contains (list, t->dtls ? 0xfefd : 0x0303))
        return g12_fail (t, GQ_ALERT_PROTOCOL_VERSION, GQ_ERR_PROTOCOL);
    }

  /* Extended master secret is mandatory (RFC 7627).  */
  if (!gq_ext_find (ch->extensions, GQ_EXT12_EXTENDED_MASTER_SECRET, &v))
    return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_PROTOCOL);
  if (v.len != 0)
    return g12_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);

  /* Secure renegotiation indication is mandatory (RFC 5746): the
     extension, empty, or the signalling suite value.  */
  if (gq_ext_find (ch->extensions, GQ_EXT12_RENEGOTIATION_INFO, &v))
    {
      if (v.len != 1 || v.data[0] != 0)
        return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_PROTOCOL);
    }
  else if (!gq_u16_contains (ch->cipher_suites, GQ_TLS12_SCSV_RENEGOTIATION))
    return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_PROTOCOL);

  /* ECDHE needs secp256r1 offered (RFC 8422 section 5.1).  */
  if (!gq_ext_find (ch->extensions, GQ_EXT_SUPPORTED_GROUPS, &v))
    return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_PROTOCOL);
  r = gq_list_u16 (v, 2, &list);
  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (!gq_u16_contains (list, GQ_GROUP_SECP256R1))
    return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_PROTOCOL);

  /* Uncompressed points; absence means the same.  */
  if (gq_ext_find (ch->extensions, GQ_EXT12_EC_POINT_FORMATS, &v))
    {
      size_t i;
      int ok = 0;

      if (v.len < 2 || v.data[0] != v.len - 1)
        return g12_fail (t, GQ_ALERT_DECODE_ERROR, GQ_ERR_ENCODING);
      for (i = 1; i < v.len; i++)
        ok |= v.data[i] == 0;
      if (!ok)
        return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_PROTOCOL);
    }

  /* Without signature_algorithms RFC 5246 assumes SHA-1, which we do not
     do.  */
  if (!gq_ext_find (ch->extensions, GQ_EXT_SIGNATURE_ALGORITHMS, &v))
    return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_PROTOCOL);
  r = gq_list_u16 (v, 2, &c->sigalgs);
  if (r != GQ_OK)
    return g12_fail_parse (t, r);

  if (gq_ext_find (ch->extensions, GQ_EXT_SERVER_NAME, &v))
    {
      gq_slice host;

      r = gq_ext_server_name (v, &host);
      if (r != GQ_OK)
        return g12_fail_parse (t, r);
      memcpy (t->sni, host.data, host.len);
      t->sni_len = host.len;
    }
  if (gq_ext_find (ch->extensions, GQ_EXT_ALPN, &v))
    {
      r = gq_ext_alpn (v, &c->alpn);
      if (r != GQ_OK)
        return g12_fail_parse (t, r);
      c->have_alpn = 1;
    }
  if (gq_ext_find (ch->extensions, GQ_EXT12_SESSION_TICKET, &c->ticket))
    c->have_ticket_ext = 1;
  return GQ_OK;
}

static int
select_alpn (gq_tls12 *t, const struct choice *c)
{
  gq_slice list, name;
  size_t i;

  t->info.alpn_len = 0;
  if (!c->have_alpn || t->cfg.n_alpn == 0)
    return GQ_OK;
  for (i = 0; i < t->cfg.n_alpn; i++)
    {
      list = c->alpn;
      while (gq_alpn_next (&list, &name) == 1)
        if (name.len == t->cfg.alpn[i].len
            && memcmp (name.data, t->cfg.alpn[i].data, name.len) == 0)
          {
            if (name.len > sizeof t->info.alpn)
              return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
            memcpy (t->info.alpn, name.data, name.len);
            t->info.alpn_len = name.len;
            return GQ_OK;
          }
    }
  return g12_fail (t, GQ_ALERT_NO_APPLICATION_PROTOCOL, GQ_ERR_PROTOCOL);
}

/* Try to resume from the client's ticket.  Anything wrong with it only
   means a full handshake, never an error.  */
static void
try_resume (gq_tls12 *t, const gq_client_hello *ch, const struct choice *c)
{
  gq_session_state *s = &t->sess;
  uint64_t now = g12_now_ms (t), life;
  int active;

  if (!c->have_ticket_ext || c->ticket.len == 0 || t->scfg.ticket_keys == NULL
      || ch->session_id.len == 0)
    return;
  if (gq_ticket_open (t->scfg.ticket_keys, c->ticket.data, c->ticket.len, s,
                      &active) != GQ_OK)
    return;
  life = (uint64_t) s->lifetime * 1000;
  if (s->psk_len != GQ_TLS12_MASTER_LEN || s->lifetime > MAX_TICKET_LIFETIME)
    return;
  /* Expired, or issued implausibly far in the future.  */
  if (s->created_ms > now + 60000
      || (now > s->created_ms && now - s->created_ms >= life))
    return;
  /* The suite must be one we still allow and the client still offers; a
     TLS 1.3 ticket fails here because its suites are not in the list.  */
  if (!g12_in_list (t->suites, t->n_suites, s->cipher_suite)
      || !gq_u16_contains (ch->cipher_suites, s->cipher_suite))
    return;
  if (s->server_name_len != t->sni_len
      || memcmp (s->server_name, t->sni, t->sni_len) != 0)
    return;
  if (t->scfg.client_auth == GQ_CLIENT_AUTH_REQUIRED
      && !s->client_authenticated)
    return;
  t->resumed = 1;
}

static int
s_send_full_flight (gq_tls12 *t, int issue_ticket)
{
  uint8_t buf[1024], sig[GQ_SIGNATURE_MAX], data[64 + 128], *heap;
  gq_wbuf w, pw;
  gq_tls12_sh_params sp;
  size_t i, total = 16, sl;
  uint8_t params[128];

  /* ServerHello.  */
  memset (&sp, 0, sizeof sp);
  sp.random = t->server_random;
  sp.cipher_suite = t->suite;
  sp.issue_ticket = issue_ticket;
  sp.dtls = t->dtls;
  sp.alpn.data = t->info.alpn;
  sp.alpn.len = t->info.alpn_len;
  gq_wbuf_init (&w, buf, sizeof buf);
  gq_tls12_build_server_hello (&w, &sp);
  TRY (g12_send (t, &w));

  /* Certificate.  */
  for (i = 0; i < t->creds->n_chain; i++)
    total += t->creds->chain[i].len + 3;
  heap = malloc (total);
  if (heap == NULL)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  gq_wbuf_init (&w, heap, total);
  gq_tls12_build_certificate (&w, t->creds->chain, t->creds->n_chain);
  {
    int r = g12_send (t, &w);

    free (heap);
    if (r != GQ_OK)
      return r;
  }

  /* ServerKeyExchange: fresh ECDHE key, signed with the certificate.  */
  TRY (g12_gen_kx (t));
  gq_wbuf_init (&pw, params, sizeof params);
  gq_tls12_put_ecdh_params (&pw, (gq_slice) { t->kx.share, t->kx.share_len });
  if (gq_wbuf_status (&pw) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, gq_wbuf_status (&pw));
  memcpy (data, t->client_random, 32);
  memcpy (data + 32, t->server_random, 32);
  memcpy (data + 64, params, pw.len);
  if (gq_privkey_sign (t->creds->key, t->sign_scheme, data, 64 + pw.len, sig,
                       sizeof sig, &sl) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_CRYPTO);
  gq_wbuf_init (&w, buf, sizeof buf);
  gq_tls12_build_ske (&w, (gq_slice) { params, pw.len }, t->sign_scheme,
                      (gq_slice) { sig, sl });
  TRY (g12_send (t, &w));

  if (t->scfg.client_auth != GQ_CLIENT_AUTH_NONE)
    {
      gq_wbuf_init (&w, buf, sizeof buf);
      gq_tls12_build_certreq (&w, t->req_sigs, t->n_req_sigs);
      TRY (g12_send (t, &w));
      t->info.client_auth_requested = 1;
    }
  gq_wbuf_init (&w, buf, sizeof buf);
  gq_tls12_build_server_hello_done (&w);
  TRY (g12_send (t, &w));
  return GQ_OK;
}

static int
s_on_client_hello (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  gq_client_hello ch;
  struct choice c;
  size_t i;
  int r = gq_client_hello_parse (body, &ch);
  int issue;

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (t->dtls ? ch.legacy_version != 0xfefd : ch.legacy_version < 0x0303)
    return g12_fail (t, GQ_ALERT_PROTOCOL_VERSION, GQ_ERR_PROTOCOL);
  memcpy (t->client_random, ch.random, 32);
  TRY (read_exts (t, &ch, &c));

  /* Credentials for the requested name.  */
  t->creds = t->scfg.select_credentials
    ? t->scfg.select_credentials (t->scfg.select_user,
                                  t->sni_len ? t->sni : NULL)
    : &t->scfg.credentials;
  if (t->creds == NULL || t->creds->key == NULL || t->creds->n_chain == 0)
    return g12_fail (t, ALERT_UNRECOGNIZED_NAME, GQ_ERR_PROTOCOL);

  /* Cipher suite by our preference, among those the client offers and
     that suit the certificate's key type.  */
  t->suite = 0;
  for (i = 0; i < t->n_suites && !t->suite; i++)
    if (gq_u16_contains (ch.cipher_suites, t->suites[i])
        && key_matches_suite (t->creds->key, t->suites[i]))
      t->suite = t->suites[i];
  if (!t->suite)
    return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_UNSUPPORTED);
  TRY (select_alpn (t, &c));

  try_resume (t, &ch, &c);
  if (t->resumed)
    t->suite = t->sess.cipher_suite;
  gq_tls12_suite_params (t->suite, &t->aead, &t->hash);

  if (!t->resumed)
    {
      t->sign_scheme = (uint16_t) g12_pick_scheme (t, t->creds->key,
                                                   c.sigalgs);
      if (!t->sign_scheme)
        return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_UNSUPPORTED);
    }
  TRY (g12_rnd (t, t->server_random, 32));
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);

  if (t->resumed)
    {
      uint8_t buf[512];
      gq_wbuf w;
      gq_tls12_sh_params sp;

      memcpy (t->sid, ch.session_id.data, ch.session_id.len);
      t->sid_len = ch.session_id.len;
      memcpy (t->master, t->sess.psk, GQ_TLS12_MASTER_LEN);
      t->client_verified = t->sess.client_authenticated;
      memset (&sp, 0, sizeof sp);
      sp.random = t->server_random;
      sp.session_id = (gq_slice) { t->sid, t->sid_len };
      sp.cipher_suite = t->suite;
      sp.dtls = t->dtls;
      sp.alpn.data = t->info.alpn;
      sp.alpn.len = t->info.alpn_len;
      gq_wbuf_init (&w, buf, sizeof buf);
      gq_tls12_build_server_hello (&w, &sp);
      TRY (g12_send (t, &w));
      TRY (g12_derive_keys (t));
      TRY (g12_install_write (t));
      TRY (g12_send_finished (t));
      t->st = S12_S_WAIT_CCS;
      return GQ_OK;
    }

  /* What we will accept from a client certificate.  */
  t->n_req_sigs = t->n_sigs;
  memcpy (t->req_sigs, t->sigs, t->n_sigs * sizeof t->sigs[0]);
  issue = t->scfg.ticket_keys != NULL && c.have_ticket_ext;
  t->ticket_expected = issue;	/* Server: a ticket will be sent.  */
  TRY (s_send_full_flight (t, issue));
  t->st = t->scfg.client_auth != GQ_CLIENT_AUTH_NONE ? S12_S_WAIT_CCERT
                                                     : S12_S_WAIT_CKE;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Client's second flight                                             */
/* ------------------------------------------------------------------ */

static int
s_on_certificate (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  gq_slice chain[T12_MAX_CHAIN];
  size_t n;
  int r = gq_tls12_certificate_parse (body, chain, T12_MAX_CHAIN, &n);

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (n == 0)
    {
      /* No certificate: fine if optional (RFC 5246 section 7.4.6).  */
      if (t->scfg.client_auth == GQ_CLIENT_AUTH_REQUIRED)
        return g12_fail (t, GQ_ALERT_HANDSHAKE_FAILURE, GQ_ERR_CERT);
    }
  else
    {
      if (t->sink.verify_peer)
        {
          if (t->sink.verify_peer (t->sink.user, chain, n, NULL))
            return g12_fail (t, GQ_ALERT_BAD_CERTIFICATE, GQ_ERR_CERT);
        }
      else
        {
          enum gq_cert_error why;

          if (gq_trust_verify_chain_for (t->scfg.client_trust, chain, n, NULL,
                                         GQ_PURPOSE_CLIENT, &why) != GQ_OK)
            return g12_fail (t, gqi_cert_error_alert (why), GQ_ERR_CERT);
        }
      if (gq_pubkey_from_cert (&t->peer_key, chain[0].data, chain[0].len)
          != GQ_OK)
        return g12_fail (t, GQ_ALERT_BAD_CERTIFICATE, GQ_ERR_CERT);
      t->peer_cert = 1;
    }
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  t->st = S12_S_WAIT_CKE;
  return GQ_OK;
}

static int
s_on_cke (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  gq_slice point;
  int r = gq_tls12_cke_parse (body, &point);

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (gq_kx_complete (&t->kx, point.data, point.len, t->pms, sizeof t->pms,
                      &t->pms_len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_CRYPTO);
  /* The session hash covers everything through ClientKeyExchange.  */
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  TRY (g12_derive_master (t));
  TRY (g12_derive_keys (t));
  t->st = t->peer_cert ? S12_S_WAIT_CV : S12_S_WAIT_CCS;
  return GQ_OK;
}

static int
s_on_certificate_verify (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  uint16_t scheme;
  gq_slice sig;
  int r = gq_certificate_verify_parse (body, &scheme, &sig);

  if (r != GQ_OK)
    return g12_fail_parse (t, r);
  if (!g12_in_list (t->req_sigs, t->n_req_sigs, scheme))
    return g12_fail (t, GQ_ALERT_ILLEGAL_PARAMETER, GQ_ERR_PROTOCOL);
  /* The signature covers the handshake messages before this one.  */
  if (gq_pubkey_verify (t->peer_key, scheme, t->tb, t->tb_len, sig.data,
                        sig.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_DECRYPT_ERROR, GQ_ERR_CRYPTO);
  if (g12_tb_add (t, msg.data, msg.len) != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  t->client_verified = 1;
  t->st = S12_S_WAIT_CCS;
  return GQ_OK;
}

/* RFC 5077: seal the session and send it before our ChangeCipherSpec.  */
static int
s_send_ticket (gq_tls12 *t)
{
  gq_session_state s;
  uint8_t ticket[GQ_TICKET_MAX], *buf;
  size_t tl;
  uint32_t life = t->scfg.ticket_lifetime ? t->scfg.ticket_lifetime
                                          : DEFAULT_TICKET_LIFETIME;
  gq_wbuf w;
  int r;

  if (life > MAX_TICKET_LIFETIME)
    life = MAX_TICKET_LIFETIME;
  memset (&s, 0, sizeof s);
  s.cipher_suite = t->suite;
  memcpy (s.psk, t->master, GQ_TLS12_MASTER_LEN);
  s.psk_len = GQ_TLS12_MASTER_LEN;
  s.created_ms = g12_now_ms (t);
  s.lifetime = life;
  s.client_authenticated = t->client_verified;
  memcpy (s.server_name, t->sni, t->sni_len);
  s.server_name_len = t->sni_len;
  memcpy (s.alpn, t->info.alpn, t->info.alpn_len);
  s.alpn_len = t->info.alpn_len;
  r = gq_ticket_seal (t->scfg.ticket_keys, &s, ticket, sizeof ticket, &tl);
  gq_wipe (&s, sizeof s);
  if (r != GQ_OK)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, r);
  buf = malloc (tl + 16);
  if (buf == NULL)
    return g12_fail (t, GQ_ALERT_INTERNAL_ERROR, GQ_ERR_NOMEM);
  gq_wbuf_init (&w, buf, tl + 16);
  gq_tls12_build_nst (&w, life, (gq_slice) { ticket, tl });
  r = g12_send (t, &w);
  free (buf);
  return r;
}

static int
s_on_finished (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  TRY (g12_check_finished (t, msg, body));
  if (!t->resumed)
    {
      if (t->ticket_expected)
        TRY (s_send_ticket (t));
      TRY (g12_install_write (t));
      TRY (g12_send_finished (t));
    }
  return g12_complete (t);
}

int
g12_server_dispatch (gq_tls12 *t, gq_slice msg, gq_slice body)
{
  unsigned type = msg.data[0];

  switch (t->st)
    {
    case S12_S_WAIT_CH:
      if (type == GQ_HS_CLIENT_HELLO)
        return s_on_client_hello (t, msg, body);
      break;
    case S12_S_WAIT_CCERT:
      if (type == GQ_HS_CERTIFICATE)
        return s_on_certificate (t, msg, body);
      break;
    case S12_S_WAIT_CKE:
      if (type == GQ_HS12_CLIENT_KEY_EXCHANGE)
        return s_on_cke (t, msg, body);
      break;
    case S12_S_WAIT_CV:
      if (type == GQ_HS_CERTIFICATE_VERIFY)
        return s_on_certificate_verify (t, msg, body);
      break;
    case S12_S_WAIT_FIN:
      if (type == GQ_HS_FINISHED)
        return s_on_finished (t, msg, body);
      break;
    case S12_DONE:
      /* A ClientHello now would be a renegotiation attempt.  */
      return g12_fail (t, GQ_ALERT_NO_RENEGOTIATION, GQ_ERR_PROTOCOL);
    default:
      break;
    }
  return g12_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
}

int
g12_server_ccs (gq_tls12 *t)
{
  if (t->st != S12_S_WAIT_CCS)
    return g12_fail (t, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
  TRY (g12_install_read (t));
  t->st = S12_S_WAIT_FIN;
  return GQ_OK;
}
