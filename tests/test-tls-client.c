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
#include <gnuquic/tls.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;			/* Skipped: needs GnuTLS for certificates.  */
}

#else

#include "tst-x509.h"
#include "tst-tlspeer.h"

/* ------------------------------------------------------------------ */
/* Fixtures                                                           */
/* ------------------------------------------------------------------ */

static struct tst_cert ca, leaf, other_ca, other_leaf, expired_leaf, cli;
static gq_privkey *server_key, *other_key, *expired_key, *client_key;
static uint8_t leaf_der[2048], other_der[2048], expired_der[2048], cli_der[2048];
static size_t leaf_len, other_len, expired_len, cli_len;
static gq_trust *trust;

static size_t
der_of (const struct tst_cert *c, uint8_t *out, size_t cap)
{
  gnutls_datum_t d;
  size_t n;

  gnutls_x509_crt_export2 (c->crt, GNUTLS_X509_FMT_DER, &d);
  n = d.size;
  if (n <= cap)
    memcpy (out, d.data, n);
  gnutls_free (d.data);
  return n;
}

static gq_privkey *
key_of (const struct tst_cert *c)
{
  gnutls_datum_t pem;
  gq_privkey *k = NULL;

  gnutls_x509_privkey_export2_pkcs8 (c->key, GNUTLS_X509_FMT_PEM, NULL,
                                     GNUTLS_PKCS_PLAIN, &pem);
  CHECK_EQ (gq_privkey_from_pem (&k, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
  return k;
}

static void
setup_fixtures (void)
{
  gnutls_datum_t pem;

  CHECK_EQ (tst_make_cert (&ca, TST_ECDSA256, "Test CA", NULL, NULL, -3600,
                           86400, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&leaf, TST_ECDSA256, "example.test", "example.test",
                           &ca, -3600, 86400, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&other_ca, TST_ECDSA256, "Other CA", NULL, NULL,
                           -3600, 86400, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&other_leaf, TST_ECDSA256, "example.test",
                           "example.test", &other_ca, -3600, 86400,
                           GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&expired_leaf, TST_ECDSA256, "example.test",
                           "example.test", &ca, -7200, -3600,
                           GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&cli, TST_ED25519, "client", "client.test", &ca,
                           -3600, 86400, GNUTLS_DIG_UNKNOWN), 0);
  leaf_len = der_of (&leaf, leaf_der, sizeof leaf_der);
  other_len = der_of (&other_leaf, other_der, sizeof other_der);
  expired_len = der_of (&expired_leaf, expired_der, sizeof expired_der);
  cli_len = der_of (&cli, cli_der, sizeof cli_der);
  server_key = key_of (&leaf);
  other_key = key_of (&other_leaf);
  expired_key = key_of (&expired_leaf);
  client_key = key_of (&cli);

  CHECK_EQ (gq_trust_new (&trust), GQ_OK);
  gnutls_x509_crt_export2 (ca.crt, GNUTLS_X509_FMT_PEM, &pem);
  CHECK_EQ (gq_trust_add_pem (trust, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
}

/* ------------------------------------------------------------------ */
/* Sink that records everything                                       */
/* ------------------------------------------------------------------ */

struct sink_log
{
  uint8_t sent[4][8192];
  size_t sent_len[4];
  gq_tls_secret secrets[32];
  int n_secrets;
  int complete;
  gq_tls_info info;
  int alert;
  uint8_t peer_tp[512];
  size_t peer_tp_len;
  int n_tickets;
  uint8_t ticket[512];
  size_t ticket_len;
  uint8_t psk[48];
  size_t psk_len;
  uint32_t lifetime, age_add, max_early;
  int fail_send;		/* Make send return nonzero.  */
  int verify_result;		/* For verify_peer: 0 accept.  */
  int verify_calls;
};

static int
sk_send (void *u, enum gq_level level, const uint8_t *d, size_t n)
{
  struct sink_log *l = u;

  if (l->fail_send)
    return 1;
  memcpy (l->sent[level] + l->sent_len[level], d, n);
  l->sent_len[level] += n;
  return 0;
}

static int
sk_secret (void *u, const gq_tls_secret *s)
{
  struct sink_log *l = u;

  l->secrets[l->n_secrets++] = *s;
  return 0;
}

static int
sk_peer_params (void *u, const uint8_t *d, size_t n)
{
  struct sink_log *l = u;

  memcpy (l->peer_tp, d, n);
  l->peer_tp_len = n;
  return 0;
}

static int
sk_ticket (void *u, const gq_tls_ticket *t)
{
  struct sink_log *l = u;

  l->n_tickets++;
  memcpy (l->ticket, t->ticket.data, t->ticket.len);
  l->ticket_len = t->ticket.len;
  memcpy (l->psk, t->psk, t->psk_len);
  l->psk_len = t->psk_len;
  l->lifetime = t->lifetime;
  l->age_add = t->age_add;
  l->max_early = t->max_early_data;
  return 0;
}

static int
sk_complete (void *u, const gq_tls_info *i)
{
  struct sink_log *l = u;

  l->complete = 1;
  l->info = *i;
  return 0;
}

static int
sk_alert (void *u, unsigned code)
{
  struct sink_log *l = u;

  l->alert = (int) code;
  return 0;
}

static int
sk_verify (void *u, const gq_slice *chain, size_t n, const char *name)
{
  struct sink_log *l = u;

  (void) chain; (void) n; (void) name;
  l->verify_calls++;
  return l->verify_result;
}

/* ------------------------------------------------------------------ */
/* Test environment                                                   */
/* ------------------------------------------------------------------ */

struct env
{
  gq_tls *tls;
  struct sink_log lg;
  struct tst_peer peer;
  gq_tls_config cfg;
  gq_tls_sink sink;
  struct flight initial, hs;
  uint8_t ch[8192];
  size_t chlen;
  gq_slice alpn[2];
  uint8_t tp[8];
  gq_slice chain[1];
};

static struct env *
env_new (void)
{
  struct env *e = calloc (1, sizeof *e);

  e->lg.alert = -1;
  e->cfg.server_name = "example.test";
  e->cfg.trust = trust;
  e->sink.user = &e->lg;
  e->sink.send = sk_send;
  e->sink.secret = sk_secret;
  e->sink.peer_params = sk_peer_params;
  e->sink.ticket = sk_ticket;
  e->sink.complete = sk_complete;
  e->sink.alert = sk_alert;
  e->peer.key = server_key;
  e->peer.chain[0] = (gq_slice) { leaf_der, leaf_len };
  e->peer.n_chain = 1;
  return e;
}

static void
env_free (struct env *e)
{
  gq_tls_free (e->tls);
  if (e->peer.tr)
    gq_transcript_free (e->peer.tr);
  free (e);
}

static void
env_create (struct env *e)
{
  CHECK_EQ (gq_tls_client_new (&e->tls, &e->cfg, &e->sink), GQ_OK);
}

/* Take the client's bytes for LEVEL.  */
static size_t
take (struct env *e, enum gq_level level, uint8_t *out)
{
  size_t n = e->lg.sent_len[level];

  memcpy (out, e->lg.sent[level], n);
  e->lg.sent_len[level] = 0;
  return n;
}

static void
env_start (struct env *e)
{
  CHECK_EQ (gq_tls_start (e->tls), GQ_OK);
  e->chlen = take (e, GQ_LEVEL_INITIAL, e->ch);
  CHECK (e->chlen > 4);
}

static void
env_server (struct env *e)
{
  CHECK_EQ (peer_handle_ch (&e->peer, e->ch, e->chlen, &e->initial, &e->hs),
            GQ_OK);
}

static int
feed (struct env *e, enum gq_level level, const uint8_t *d, size_t n,
      size_t chunk)
{
  int r = GQ_OK;

  if (chunk == 0)
    chunk = n ? n : 1;
  while (n > 0 && r == GQ_OK)
    {
      size_t k = n < chunk ? n : chunk;
      const uint8_t *p = d;
      size_t l = k;

      r = gq_tls_feed (e->tls, level, &p, &l);
      d += k;
      n -= k;
    }
  return r;
}

static int
feed_flight (struct env *e, enum gq_level level, const struct flight *f,
             size_t chunk)
{
  int r = GQ_OK, i;

  for (i = 0; i < f->n && r == GQ_OK; i++)
    r = feed (e, level, f->data + f->off[i], f->len[i], chunk);
  return r;
}

/* Run a complete honest handshake, feeding the peer's bytes in CHUNK-byte
   pieces.  Leaves the client's final flight processed by the peer.  */
static void
run_handshake (struct env *e, size_t chunk)
{
  uint8_t out[16384];
  size_t n;

  env_start (e);
  env_server (e);
  CHECK_EQ (feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, chunk), GQ_OK);
  if (e->initial.n && e->lg.sent_len[GQ_LEVEL_INITIAL])
    {
      /* HelloRetryRequest: the client answered with a second ClientHello.  */
      e->chlen = take (e, GQ_LEVEL_INITIAL, e->ch);
      env_server (e);
      CHECK_EQ (feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, chunk), GQ_OK);
    }
  CHECK_EQ (feed_flight (e, GQ_LEVEL_HANDSHAKE, &e->hs, chunk), GQ_OK);
  n = take (e, GQ_LEVEL_HANDSHAKE, out);
  CHECK (n > 0);
  CHECK_EQ (peer_handle_client_flight (&e->peer, out, n), GQ_OK);
}

static int
secret_is (const gq_tls_secret *s, enum gq_level lv, enum gq_dir d,
           const uint8_t *want, size_t len)
{
  return s->level == lv && s->dir == d && s->len == len
    && memcmp (s->secret, want, len) == 0;
}

static void
check_keys_agree (struct env *e)
{
  struct sink_log *l = &e->lg;
  size_t hl = e->peer.hlen;

  CHECK_EQ (l->n_secrets, 4);
  if (l->n_secrets < 4)
    return;
  CHECK (secret_is (&l->secrets[0], GQ_LEVEL_HANDSHAKE, GQ_DIR_READ, e->peer.shs, hl));
  CHECK (secret_is (&l->secrets[1], GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE, e->peer.chs, hl));
  CHECK (secret_is (&l->secrets[2], GQ_LEVEL_APPLICATION, GQ_DIR_READ, e->peer.sas, hl));
  CHECK (secret_is (&l->secrets[3], GQ_LEVEL_APPLICATION, GQ_DIR_WRITE, e->peer.cas, hl));
  CHECK_EQ (l->secrets[0].aead, e->peer.aead);
  CHECK_EQ (l->secrets[0].hash, e->peer.hash);
  CHECK (l->complete && gq_tls_is_complete (e->tls));
  CHECK_EQ (l->info.cipher_suite, e->peer.suite);
  CHECK_EQ (l->info.group, e->peer.chosen_group);
}

/* ------------------------------------------------------------------ */
/* Happy paths                                                        */
/* ------------------------------------------------------------------ */

static void
test_basic (size_t chunk, unsigned suite, unsigned group)
{
  struct env *e = env_new ();
  uint8_t out[256];
  uint8_t want[64];

  e->peer.pick_suite = suite;
  e->peer.pick_group = group;
  env_create (e);
  run_handshake (e, chunk);
  check_keys_agree (e);
  if (suite)
    CHECK_EQ (e->peer.suite, suite);
  CHECK_EQ (e->lg.info.hello_retry, 0);
  CHECK_EQ (e->lg.info.alpn_len, 0);
  CHECK (e->peer.sid_len == 32);		/* Compatibility session ID.  */
  if (group)
    CHECK_EQ (e->lg.info.group, group);
  else
    CHECK_EQ (e->lg.info.group, GQ_GROUP_X25519_MLKEM768);

  /* Exporter agrees with an independent derivation.  */
  {
    uint8_t eh[48], ch[48], d[48], ctx[3] = { 1, 2, 3 };
    size_t hl = e->peer.hlen;

    gq_hash_compute (e->peer.hash, "", 0, eh, hl);
    gq_hash_compute (e->peer.hash, ctx, 3, ch, hl);
    gq_hkdf_expand_label (e->peer.hash, e->peer.exp, hl, "test label", eh, hl,
                          d, hl);
    gq_hkdf_expand_label (e->peer.hash, d, hl, "exporter", ch, hl, want, 20);
    CHECK_EQ (gq_tls_export (e->tls, "test label", ctx, 3, out, 20), GQ_OK);
    CHECK (memcmp (out, want, 20) == 0);
    CHECK_EQ (gq_tls_export (e->tls, "other", ctx, 3, want, 20), GQ_OK);
    CHECK (memcmp (out, want, 20) != 0);
  }
  env_free (e);
}

static void
test_hrr (int cookie, unsigned hrr_group)
{
  struct env *e = env_new ();

  e->peer.force_hrr = 1;
  e->peer.hrr_group = hrr_group;
  e->peer.hrr_cookie = cookie;
  env_create (e);
  run_handshake (e, 0);
  CHECK_EQ (e->lg.info.hello_retry, 1);
  CHECK_EQ (e->lg.info.group, hrr_group);
  check_keys_agree (e);
  env_free (e);
}

static void
test_quic (void)
{
  struct env *e = env_new ();
  static const uint8_t ptp[] = { 0x01, 0x02, 0x67, 0x10 };
  const uint8_t *ctp;
  size_t i;

  for (i = 0; i < sizeof e->tp; i++)
    e->tp[i] = (uint8_t) (0xa0 + i);
  e->alpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  e->alpn[1] = (gq_slice) { (const uint8_t *) "hq-interop", 10 };
  e->cfg.alpn = e->alpn;
  e->cfg.n_alpn = 2;
  e->cfg.transport_params = e->tp;
  e->cfg.transport_params_len = sizeof e->tp;
  e->cfg.quic = 1;
  e->peer.quic = 1;
  e->peer.tp = (gq_slice) { ptp, sizeof ptp };
  e->peer.alpn_pick = (gq_slice) { (const uint8_t *) "h3", 2 };
  env_create (e);
  run_handshake (e, 0);
  check_keys_agree (e);
  ctp = e->peer.client_tp_buf;
  CHECK_EQ (e->peer.client_tp_len, sizeof e->tp);
  CHECK (memcmp (ctp, e->tp, sizeof e->tp) == 0);
  CHECK_EQ (e->peer.sid_len, 0);		/* QUIC: empty session ID.  */
  CHECK_EQ (e->lg.peer_tp_len, sizeof ptp);
  CHECK (memcmp (e->lg.peer_tp, ptp, sizeof ptp) == 0);
  CHECK (e->lg.info.alpn_len == 2 && memcmp (e->lg.info.alpn, "h3", 2) == 0);
  /* No TLS KeyUpdate in QUIC.  */
  CHECK_EQ (gq_tls_key_update (e->tls, 0), GQ_ERR_INVAL);
  env_free (e);
}

static void
test_mtls (int with_key)
{
  struct env *e = env_new ();

  e->peer.request_cert = 1;
  if (with_key)
    {
      e->chain[0] = (gq_slice) { cli_der, cli_len };
      e->cfg.client_chain = e->chain;
      e->cfg.n_client_chain = 1;
      e->cfg.client_key = client_key;
    }
  env_create (e);
  run_handshake (e, 0);
  check_keys_agree (e);
  CHECK_EQ (e->lg.info.client_auth_requested, 1);
  CHECK_EQ (e->lg.info.client_auth_sent, with_key);
  CHECK_EQ (e->peer.client_sent_cert, with_key);
  env_free (e);
}

static void
test_tickets_and_key_update (void)
{
  struct env *e = env_new ();
  uint8_t buf[512], next[48], want[48];
  gq_wbuf w;
  size_t hl, n;
  const uint8_t *p;
  gq_ext ex;
  uint8_t max[4] = { 0, 0, 0x40, 0 };
  static const uint8_t nonce[2] = { 1, 2 }, ticket[] = { 't', 'i', 'c', 'k', 'e', 't', 'd', 'a', 't', 'a' };
  int before;

  env_create (e);
  run_handshake (e, 0);
  check_keys_agree (e);
  hl = e->peer.hlen;

  /* NewSessionTicket becomes a stored ticket with its derived PSK.  */
  ex.type = GQ_EXT_EARLY_DATA;
  ex.value = (gq_slice) { max, 4 };
  gq_wbuf_init (&w, buf, sizeof buf);
  gq_build_new_session_ticket (&w, 3600, 0xdeadbeef, (gq_slice) { nonce, 2 },
                               (gq_slice) { ticket, sizeof ticket }, &ex, 1);
  CHECK_EQ (feed (e, GQ_LEVEL_APPLICATION, buf, w.len, 0), GQ_OK);
  CHECK_EQ (e->lg.n_tickets, 1);
  CHECK (e->lg.ticket_len == sizeof ticket
         && memcmp (e->lg.ticket, ticket, sizeof ticket) == 0);
  CHECK_EQ (e->lg.lifetime, 3600);
  CHECK_EQ (e->lg.age_add, 0xdeadbeefU);
  CHECK_EQ (e->lg.max_early, 0x4000U);
  gq_resumption_psk (e->peer.hash, e->peer.resm, nonce, 2, want);
  CHECK (e->lg.psk_len == hl && memcmp (e->lg.psk, want, hl) == 0);

  /* Client-initiated KeyUpdate asking the peer to follow.  */
  before = e->lg.n_secrets;
  CHECK_EQ (gq_tls_key_update (e->tls, 1), GQ_OK);
  n = take (e, GQ_LEVEL_APPLICATION, buf);
  CHECK (n == 5 && buf[0] == GQ_HS_KEY_UPDATE && buf[4] == 1);
  gq_traffic_secret_update (e->peer.hash, e->peer.cas, next);
  CHECK_EQ (e->lg.n_secrets, before + 1);
  CHECK (secret_is (&e->lg.secrets[before], GQ_LEVEL_APPLICATION,
                    GQ_DIR_WRITE, next, hl));
  memcpy (e->peer.cas, next, hl);

  /* The peer answers with its own update (not requested): our read side.  */
  buf[0] = GQ_HS_KEY_UPDATE; buf[1] = 0; buf[2] = 0; buf[3] = 1; buf[4] = 0;
  gq_traffic_secret_update (e->peer.hash, e->peer.sas, next);
  CHECK_EQ (feed (e, GQ_LEVEL_APPLICATION, buf, 5, 0), GQ_OK);
  CHECK_EQ (e->lg.n_secrets, before + 2);
  CHECK (secret_is (&e->lg.secrets[before + 1], GQ_LEVEL_APPLICATION,
                    GQ_DIR_READ, next, hl));
  memcpy (e->peer.sas, next, hl);
  CHECK_EQ (e->lg.sent_len[GQ_LEVEL_APPLICATION], 0);

  /* Peer-initiated update requesting a reply: we answer and rekey.  */
  buf[4] = 1;
  gq_traffic_secret_update (e->peer.hash, e->peer.sas, next);
  CHECK_EQ (feed (e, GQ_LEVEL_APPLICATION, buf, 5, 0), GQ_OK);
  CHECK_EQ (e->lg.n_secrets, before + 4);
  CHECK (secret_is (&e->lg.secrets[before + 2], GQ_LEVEL_APPLICATION,
                    GQ_DIR_READ, next, hl));
  gq_traffic_secret_update (e->peer.hash, e->peer.cas, next);
  CHECK (secret_is (&e->lg.secrets[before + 3], GQ_LEVEL_APPLICATION,
                    GQ_DIR_WRITE, next, hl));
  p = e->lg.sent[GQ_LEVEL_APPLICATION];
  CHECK (e->lg.sent_len[GQ_LEVEL_APPLICATION] == 5 && p[0] == GQ_HS_KEY_UPDATE
         && p[4] == 0);
  env_free (e);
}

/* ------------------------------------------------------------------ */
/* Failures                                                           */
/* ------------------------------------------------------------------ */

#define expect_fail(e, s, r, a) expect_fail_ (e, s, r, a, __LINE__)

static void
expect_fail_ (struct env *e, int status, int r, unsigned alert, int line)
{
  if (r != status || e->lg.alert != (int) alert)
    fprintf (stderr, "  (expect_fail called from line %d)\n", line);
  CHECK_EQ (r, status);
  CHECK_EQ (e->lg.alert, (int) alert);
  CHECK_EQ (gq_tls_alert (e->tls), (int) alert);
  CHECK (gq_tls_is_failed (e->tls));
  CHECK (!e->lg.complete);
  /* A failed engine refuses more input.  */
  {
    const uint8_t b[4] = { 0 };
    const uint8_t *p = b;
    size_t l = 4;

    CHECK_EQ (gq_tls_feed (e->tls, GQ_LEVEL_HANDSHAKE, &p, &l), GQ_ERR_INVAL);
  }
}

/* Get to the point of feeding the server flight.  */
static struct env *
ready (void)
{
  struct env *e = env_new ();

  env_create (e);
  env_start (e);
  env_server (e);
  return e;
}

static void
test_certificate_failures (void)
{
  struct env *e;
  int r;

  /* Untrusted issuer.  */
  e = env_new ();
  e->peer.key = other_key;
  e->peer.chain[0] = (gq_slice) { other_der, other_len };
  env_create (e);
  env_start (e); env_server (e);
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  r = feed_flight (e, GQ_LEVEL_HANDSHAKE, &e->hs, 0);
  expect_fail (e, GQ_ERR_CERT, r, GQ_ALERT_UNKNOWN_CA);
  env_free (e);

  /* Expired certificate.  */
  e = env_new ();
  e->peer.key = expired_key;
  e->peer.chain[0] = (gq_slice) { expired_der, expired_len };
  env_create (e);
  env_start (e); env_server (e);
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  r = feed_flight (e, GQ_LEVEL_HANDSHAKE, &e->hs, 0);
  expect_fail (e, GQ_ERR_CERT, r, GQ_ALERT_CERTIFICATE_EXPIRED);
  env_free (e);

  /* Wrong host name.  */
  e = env_new ();
  e->cfg.server_name = "other.test";
  env_create (e);
  env_start (e); env_server (e);
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  r = feed_flight (e, GQ_LEVEL_HANDSHAKE, &e->hs, 0);
  expect_fail (e, GQ_ERR_CERT, r, GQ_ALERT_BAD_CERTIFICATE);
  env_free (e);

  /* A verify_peer callback replaces the trust store: it can accept an
     untrusted chain, and reject a trusted one.  */
  e = env_new ();
  e->peer.key = other_key;
  e->peer.chain[0] = (gq_slice) { other_der, other_len };
  e->cfg.trust = NULL;
  e->sink.verify_peer = sk_verify;
  env_create (e);
  run_handshake (e, 0);
  CHECK_EQ (e->lg.verify_calls, 1);
  check_keys_agree (e);
  env_free (e);

  e = env_new ();
  e->cfg.trust = NULL;
  e->sink.verify_peer = sk_verify;
  e->lg.verify_result = 1;
  env_create (e);
  env_start (e); env_server (e);
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  r = feed_flight (e, GQ_LEVEL_HANDSHAKE, &e->hs, 0);
  expect_fail (e, GQ_ERR_CERT, r, GQ_ALERT_BAD_CERTIFICATE);
  env_free (e);
}

/* Flip one byte inside the Nth message of the server flight.  */
static void
flip (struct env *e, int msg, size_t from_end)
{
  e->hs.data[e->hs.off[msg] + e->hs.len[msg] - 1 - from_end] ^= 0x01;
}

static void
test_signature_failures (void)
{
  struct env *e;
  int r, cv, fin;

  /* Layout of the honest flight: EE, Certificate, CV, Finished.  */
  cv = 2;
  fin = 3;

  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  CHECK_EQ (e->hs.n, 4);
  flip (e, fin, 0);
  r = feed_flight (e, GQ_LEVEL_HANDSHAKE, &e->hs, 0);
  expect_fail (e, GQ_ERR_CRYPTO, r, GQ_ALERT_DECRYPT_ERROR);
  env_free (e);

  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  flip (e, cv, 5);			/* Inside the signature.  */
  r = feed_flight (e, GQ_LEVEL_HANDSHAKE, &e->hs, 0);
  expect_fail (e, GQ_ERR_CRYPTO, r, GQ_ALERT_DECRYPT_ERROR);
  env_free (e);

  /* A signature scheme the client never offered.  */
  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  e->hs.data[e->hs.off[cv] + 4] = 0x02;		/* 0x0201: RSA SHA-1.  */
  e->hs.data[e->hs.off[cv] + 5] = 0x01;
  r = feed_flight (e, GQ_LEVEL_HANDSHAKE, &e->hs, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* Finished of the wrong length.  */
  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  {
    int i;
    uint8_t bad[8] = { GQ_HS_FINISHED, 0, 0, 4, 1, 2, 3, 4 };

    for (i = 0; i < fin; i++)
      CHECK_EQ (feed (e, GQ_LEVEL_HANDSHAKE, e->hs.data + e->hs.off[i],
                      e->hs.len[i], 0), GQ_OK);
    r = feed (e, GQ_LEVEL_HANDSHAKE, bad, sizeof bad, 0);
    expect_fail (e, GQ_ERR_ENCODING, r, GQ_ALERT_DECODE_ERROR);
  }
  env_free (e);
}

/* Build a ServerHello with the given extension block bytes.  */
static size_t
craft_sh (uint8_t *out, const struct env *e, unsigned suite, int echo_sid,
          const uint8_t *exts, size_t exts_len)
{
  gq_wbuf w;
  static const uint8_t rnd[32] = { 7 };

  gq_wbuf_init (&w, out, 1024);
  gq_wbuf_hs_open (&w, GQ_HS_SERVER_HELLO);
  gq_wbuf_u16 (&w, 0x0303);
  gq_wbuf_bytes (&w, rnd, 32);
  gq_wbuf_open (&w, 1);
  if (echo_sid)
    gq_wbuf_bytes (&w, e->peer.sid, e->peer.sid_len);
  gq_wbuf_close (&w);
  gq_wbuf_u16 (&w, suite);
  gq_wbuf_u8 (&w, 0);
  gq_wbuf_open (&w, 2);
  gq_wbuf_bytes (&w, exts, exts_len);
  gq_wbuf_close (&w);
  gq_wbuf_close (&w);
  CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
  return w.len;
}

static void
test_server_hello_failures (void)
{
  struct env *e;
  uint8_t sh[1024], exts[256];
  static const uint8_t sv13[] = { 0, 43, 0, 2, 3, 4 };
  static const uint8_t sv12[] = { 0, 43, 0, 2, 3, 3 };
  static const uint8_t unknown[] = { 0x0f, 0xff, 0, 0 };
  uint8_t ks_bad_group[4 + 2 + 2 + 32] = { 0, 51, 0, 36, 0, 0x18, 0, 32 };
  uint8_t ks_short[4 + 2 + 2 + 31] = { 0, 51, 0, 35, 0, 0x1d, 0, 31 };
  size_t n, el;
  int r;

  /* Session ID not echoed.  */
  e = ready ();
  n = craft_sh (sh, e, 0x1301, 0, sv13, sizeof sv13);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* Suite the client did not offer: restrict the offer to AES-256.  */
  e = env_new ();
  {
    static const uint16_t only[] = { GQ_TLS_AES_256_GCM_SHA384 };

    e->cfg.suites = only;
    e->cfg.n_suites = 1;
  }
  env_create (e); env_start (e); env_server (e);
  n = craft_sh (sh, e, 0x1301, 1, sv13, sizeof sv13);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* No supported_versions: an older protocol was chosen.  */
  e = ready ();
  n = craft_sh (sh, e, 0x1301, 1, ks_short, sizeof ks_short);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_PROTOCOL_VERSION);
  env_free (e);

  e = ready ();
  memcpy (exts, ks_bad_group, sizeof ks_bad_group);
  el = sizeof ks_bad_group;
  n = craft_sh (sh, e, 0x1301, 1, exts, el);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_PROTOCOL_VERSION);
  env_free (e);

  /* Unknown extension.  */
  e = ready ();
  memcpy (exts, sv13, sizeof sv13);
  memcpy (exts + sizeof sv13, unknown, sizeof unknown);
  n = craft_sh (sh, e, 0x1301, 1, exts, sizeof sv13 + sizeof unknown);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_UNSUPPORTED_EXTENSION);
  env_free (e);

  /* No key_share.  */
  e = ready ();
  n = craft_sh (sh, e, 0x1301, 1, sv13, sizeof sv13);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_MISSING_EXTENSION);
  env_free (e);

  /* Wrong version in supported_versions.  */
  e = ready ();
  n = craft_sh (sh, e, 0x1301, 1, sv12, sizeof sv12);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* Key share for a group the client did not send a share for.  */
  e = ready ();
  memcpy (exts, sv13, sizeof sv13);
  memcpy (exts + sizeof sv13, ks_bad_group, sizeof ks_bad_group);
  n = craft_sh (sh, e, 0x1301, 1, exts, sizeof sv13 + sizeof ks_bad_group);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* X25519 share of the wrong size.  */
  e = ready ();
  memcpy (exts, sv13, sizeof sv13);
  memcpy (exts + sizeof sv13, ks_short, sizeof ks_short);
  n = craft_sh (sh, e, 0x1301, 1, exts, sizeof sv13 + sizeof ks_short);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* Duplicate extension.  */
  e = ready ();
  memcpy (exts, sv13, sizeof sv13);
  memcpy (exts + sizeof sv13, sv13, sizeof sv13);
  n = craft_sh (sh, e, 0x1301, 1, exts, 2 * sizeof sv13);
  r = feed (e, GQ_LEVEL_INITIAL, sh, n, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* Truncated body.  */
  e = ready ();
  sh[0] = GQ_HS_SERVER_HELLO; sh[1] = 0; sh[2] = 0; sh[3] = 10;
  memset (sh + 4, 3, 10);
  r = feed (e, GQ_LEVEL_INITIAL, sh, 14, 0);
  expect_fail (e, GQ_ERR_ENCODING, r, GQ_ALERT_DECODE_ERROR);
  env_free (e);
}

static void
test_sequencing_failures (void)
{
  struct env *e;
  int r;

  /* Messages at the wrong level.  */
  e = ready ();
  r = feed_flight (e, GQ_LEVEL_HANDSHAKE, &e->initial, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_UNEXPECTED_MESSAGE);
  env_free (e);

  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  r = feed (e, GQ_LEVEL_INITIAL, e->hs.data + e->hs.off[0], e->hs.len[0], 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_UNEXPECTED_MESSAGE);
  env_free (e);

  /* Out of order: Certificate before EncryptedExtensions.  */
  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  r = feed (e, GQ_LEVEL_HANDSHAKE, e->hs.data + e->hs.off[1], e->hs.len[1], 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_UNEXPECTED_MESSAGE);
  env_free (e);

  /* Post-handshake messages before the handshake is done.  */
  e = ready ();
  {
    uint8_t ku[5] = { GQ_HS_KEY_UPDATE, 0, 0, 1, 0 };

    r = feed (e, GQ_LEVEL_APPLICATION, ku, 5, 0);
  }
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_UNEXPECTED_MESSAGE);
  env_free (e);

  /* A message split across a key change.  */
  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  r = feed (e, GQ_LEVEL_HANDSHAKE, e->hs.data + e->hs.off[0], 3, 0);
  CHECK_EQ (r, GQ_OK);
  r = feed (e, GQ_LEVEL_APPLICATION, e->hs.data + e->hs.off[0] + 3, 5, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_UNEXPECTED_MESSAGE);
  env_free (e);

  /* Absurd declared length is refused from the header.  */
  e = ready ();
  {
    uint8_t hdr[4] = { GQ_HS_SERVER_HELLO, 0x10, 0, 0 };

    r = feed (e, GQ_LEVEL_INITIAL, hdr, 4, 0);
  }
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* A failing sink aborts with an internal error.  */
  e = env_new ();
  e->lg.fail_send = 1;
  env_create (e);
  r = gq_tls_start (e->tls);
  CHECK_EQ (r, GQ_ERR_HANDLER);
  CHECK_EQ (e->lg.alert, GQ_ALERT_INTERNAL_ERROR);
  env_free (e);
}

static void
test_encrypted_extensions_failures (void)
{
  struct env *e;
  uint8_t ee[128];
  size_t n;
  int r, i;
  gq_wbuf w;
  static const uint8_t unknown[] = { 0x0f, 0xff, 0, 0 };
  static const uint8_t alpn_h2[] = { 0, 3, 2, 'h', '2' };

  /* Unknown extension in EncryptedExtensions.  */
  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  gq_wbuf_init (&w, ee, sizeof ee);
  {
    gq_ext x = { 0x0fff, { unknown + 4, 0 } };

    gq_build_encrypted_extensions (&w, &x, 1);
  }
  r = feed (e, GQ_LEVEL_HANDSHAKE, ee, w.len, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_UNSUPPORTED_EXTENSION);
  env_free (e);

  /* ALPN in the answer although the client offered none.  */
  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  gq_wbuf_init (&w, ee, sizeof ee);
  {
    gq_ext x = { GQ_EXT_ALPN, { alpn_h2, sizeof alpn_h2 } };

    gq_build_encrypted_extensions (&w, &x, 1);
  }
  r = feed (e, GQ_LEVEL_HANDSHAKE, ee, w.len, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_UNSUPPORTED_EXTENSION);
  env_free (e);

  /* ALPN the client did not offer.  */
  e = env_new ();
  e->alpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  e->cfg.alpn = e->alpn;
  e->cfg.n_alpn = 1;
  env_create (e); env_start (e); env_server (e);
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  gq_wbuf_init (&w, ee, sizeof ee);
  {
    gq_ext x = { GQ_EXT_ALPN, { alpn_h2, sizeof alpn_h2 } };

    gq_build_encrypted_extensions (&w, &x, 1);
  }
  r = feed (e, GQ_LEVEL_HANDSHAKE, ee, w.len, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* QUIC: EncryptedExtensions must carry transport parameters and ALPN.  */
  for (i = 0; i < 2; i++)
    {
      static const uint8_t alpn_h3[] = { 0, 3, 2, 'h', '3' };
      static const uint8_t tpv[] = { 1, 2, 3 };

      e = env_new ();
      e->alpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
      e->cfg.alpn = e->alpn;
      e->cfg.n_alpn = 1;
      e->cfg.transport_params = e->tp;
      e->cfg.transport_params_len = 4;
      env_create (e); env_start (e); env_server (e);
      feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
      gq_wbuf_init (&w, ee, sizeof ee);
      {
        gq_ext x = i == 0 ? (gq_ext) { GQ_EXT_ALPN, { alpn_h3, sizeof alpn_h3 } }
                          : (gq_ext) { GQ_EXT_QUIC_TRANSPORT_PARAMETERS,
                                       { tpv, sizeof tpv } };

        gq_build_encrypted_extensions (&w, &x, 1);
      }
      r = feed (e, GQ_LEVEL_HANDSHAKE, ee, w.len, 0);
      expect_fail (e, GQ_ERR_PROTOCOL, r,
                   i == 0 ? GQ_ALERT_MISSING_EXTENSION
                          : GQ_ALERT_NO_APPLICATION_PROTOCOL);
      env_free (e);
    }
  (void) n;
}

static void
test_certificate_message_failures (void)
{
  struct env *e;
  uint8_t m[128];
  gq_wbuf w;
  int r;

  /* Empty certificate list from a server.  */
  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  CHECK_EQ (feed (e, GQ_LEVEL_HANDSHAKE, e->hs.data + e->hs.off[0],
                  e->hs.len[0], 0), GQ_OK);
  gq_wbuf_init (&w, m, sizeof m);
  gq_build_certificate (&w, (gq_slice) { NULL, 0 }, NULL, 0);
  r = feed (e, GQ_LEVEL_HANDSHAKE, m, w.len, 0);
  expect_fail (e, GQ_ERR_ENCODING, r, GQ_ALERT_DECODE_ERROR);
  env_free (e);

  /* Non-empty request context in the server's Certificate.  */
  e = ready ();
  feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  CHECK_EQ (feed (e, GQ_LEVEL_HANDSHAKE, e->hs.data + e->hs.off[0],
                  e->hs.len[0], 0), GQ_OK);
  {
    static const uint8_t ctx[1] = { 9 };
    gq_slice c = { leaf_der, leaf_len };

    gq_wbuf_init (&w, m, sizeof m);
    gq_build_certificate (&w, (gq_slice) { ctx, 1 }, &c, 0);
  }
  r = feed (e, GQ_LEVEL_HANDSHAKE, m, w.len, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);
}

static void
test_hrr_failures (void)
{
  struct env *e;
  uint8_t out[8192], msg[256];
  size_t n;
  int r;

  /* A second HelloRetryRequest.  */
  e = env_new ();
  e->peer.force_hrr = 1;
  e->peer.hrr_group = GQ_GROUP_SECP256R1;
  env_create (e); env_start (e); env_server (e);
  CHECK_EQ (feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0), GQ_OK);
  n = take (e, GQ_LEVEL_INITIAL, out);
  CHECK (n > 4);
  memcpy (msg, e->initial.data, e->initial.len[0]);
  r = feed (e, GQ_LEVEL_INITIAL, msg, e->initial.len[0], 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_UNEXPECTED_MESSAGE);
  env_free (e);

  /* HelloRetryRequest asking for a group we already sent a share for.  */
  e = env_new ();
  e->peer.force_hrr = 1;
  e->peer.hrr_group = GQ_GROUP_X25519;
  env_create (e); env_start (e); env_server (e);
  r = feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);

  /* ...or for a group outside our list.  */
  e = env_new ();
  e->peer.force_hrr = 1;
  e->peer.hrr_group = 0x0019;
  env_create (e); env_start (e); env_server (e);
  r = feed_flight (e, GQ_LEVEL_INITIAL, &e->initial, 0);
  expect_fail (e, GQ_ERR_PROTOCOL, r, GQ_ALERT_ILLEGAL_PARAMETER);
  env_free (e);
}

static unsigned long long rng_state = 0x9e3779b97f4a7c15ULL;

static unsigned
rnd_below (unsigned n)
{
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return (unsigned) (rng_state % n);
}

/* Corrupt the honest server flight in random ways.  The engine must never
   crash, must fail with an alert whenever it does not finish, and, the
   security-critical part, whenever it does report success both ends must
   hold identical keys.  */
static void
test_mutations (int iterations)
{
  int it, completed = 0, failed = 0, stalled = 0;

  for (it = 0; it < iterations; it++)
    {
      struct env *e = env_new ();
      struct flight f;
      size_t total, chunk, pos, nmut, i;
      uint8_t all[16384];
      int r = GQ_OK;

      e->cfg.trust = trust;
      env_create (e);
      env_start (e);
      env_server (e);

      /* Flatten: initial flight then handshake flight, remembering the
         boundary so each part is fed at its own level.  */
      memset (&f, 0, sizeof f);
      memcpy (all, e->initial.data, e->initial.used);
      memcpy (all + e->initial.used, e->hs.data, e->hs.used);
      total = e->initial.used + e->hs.used;
      nmut = rnd_below (4);
      for (i = 0; i < nmut; i++)
        all[rnd_below ((unsigned) total)] ^= (uint8_t) (1u << rnd_below (8));
      if (rnd_below (6) == 0)
        total = rnd_below ((unsigned) total + 1);
      chunk = rnd_below (3) == 0 ? 1 + rnd_below (200) : 0;

      {
        size_t ilen = e->initial.used < total ? e->initial.used : total;

        r = feed (e, GQ_LEVEL_INITIAL, all, ilen, chunk);
        if (r == GQ_OK && total > ilen)
          r = feed (e, GQ_LEVEL_HANDSHAKE, all + ilen, total - ilen, chunk);
      }
      (void) pos;

      if (r != GQ_OK)
        {
          failed++;
          CHECK (e->lg.alert >= 0 && gq_tls_is_failed (e->tls));
        }
      else if (e->lg.complete)
        {
          uint8_t out[16384];
          size_t n = take (e, GQ_LEVEL_HANDSHAKE, out);

          completed++;
          CHECK_EQ (peer_handle_client_flight (&e->peer, out, n), GQ_OK);
          check_keys_agree (e);
        }
      else
        stalled++;
      env_free (e);
    }
  CHECK (completed > 0 && failed > 0);
  fprintf (stderr, "mutations: %d completed, %d failed, %d stalled\n",
           completed, failed, stalled);
}

static void
test_creation_rules (void)
{
  gq_tls *t;
  gq_tls_config cfg;
  gq_tls_sink sink;
  struct sink_log lg;

  memset (&cfg, 0, sizeof cfg);
  memset (&sink, 0, sizeof sink);
  memset (&lg, 0, sizeof lg);
  sink.user = &lg;
  sink.send = sk_send;
  sink.secret = sk_secret;

  /* No trust store and no verifier: refuse to run unauthenticated.  */
  CHECK_EQ (gq_tls_client_new (&t, &cfg, &sink), GQ_ERR_INVAL);
  cfg.trust = trust;
  CHECK_EQ (gq_tls_client_new (&t, &cfg, &sink), GQ_OK);
  gq_tls_free (t);
  /* QUIC needs transport parameters and ALPN.  */
  cfg.quic = 1;
  CHECK_EQ (gq_tls_client_new (&t, &cfg, &sink), GQ_ERR_INVAL);
  cfg.quic = 0;
  /* Only groups outside the policy leave nothing to offer.  */
  {
    static const uint16_t bad[] = { 0x0019, 0x0100 };

    cfg.groups = bad;
    cfg.n_groups = 2;
    CHECK_EQ (gq_tls_client_new (&t, &cfg, &sink), GQ_ERR_INVAL);
  }
  cfg.groups = NULL;
  /* A tls object cannot be started twice or fed before start.  */
  CHECK_EQ (gq_tls_client_new (&t, &cfg, &sink), GQ_OK);
  {
    const uint8_t b[4] = { 0 };
    const uint8_t *p = b;
    size_t l = 4;

    CHECK_EQ (gq_tls_feed (t, GQ_LEVEL_INITIAL, &p, &l), GQ_ERR_INVAL);
  }
  CHECK_EQ (gq_tls_start (t), GQ_OK);
  CHECK_EQ (gq_tls_start (t), GQ_ERR_INVAL);
  CHECK_EQ (gq_tls_key_update (t, 0), GQ_ERR_INVAL);
  gq_tls_free (t);
}

int
main (void)
{
  setup_fixtures ();

  test_basic (0, 0, 0);
  test_basic (1, 0, 0);
  test_basic (7, 0, 0);
  test_basic (0, GQ_TLS_AES_256_GCM_SHA384, 0);
  test_basic (0, GQ_TLS_CHACHA20_POLY1305_SHA256, GQ_GROUP_X25519);
  test_hrr (0, GQ_GROUP_SECP256R1);
  test_hrr (1, GQ_GROUP_SECP384R1);
  test_quic ();
  test_mtls (1);
  test_mtls (0);
  test_tickets_and_key_update ();

  test_certificate_failures ();
  test_signature_failures ();
  test_server_hello_failures ();
  test_sequencing_failures ();
  test_encrypted_extensions_failures ();
  test_certificate_message_failures ();
  test_hrr_failures ();
  test_creation_rules ();
  test_mutations (1500);

  TST_DONE ();
}

#endif
