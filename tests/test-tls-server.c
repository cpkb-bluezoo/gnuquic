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
#include <gnuquic/tlsmsg.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-x509.h"

/* ------------------------------------------------------------------ */
/* Fixtures                                                           */
/* ------------------------------------------------------------------ */

static struct tst_cert ca, ca2, ec, rsa, ed_srv, cli_ok, cli_bad_ca, cli_wrong_eku;
static gq_privkey *ec_key, *rsa_key, *ed_key, *cli_ok_key, *cli_bad_key,
  *cli_eku_key;
static uint8_t ec_der[2048], rsa_der[2048], ed_der[2048], cli_der[2048],
  clibad_der[2048], clieku_der[2048];
static gq_slice ec_chain[1], rsa_chain[1], ed_chain[1], cli_chain[1],
  clibad_chain[1], clieku_chain[1];
static gq_trust *client_trust;	/* Clients trust ca.  */
static gq_trust *server_trust;	/* Servers trust ca for client certs.  */
static gq_tls_credentials ec_creds, rsa_creds, ed_creds;

static size_t
der_of (const struct tst_cert *c, uint8_t *out)
{
  gnutls_datum_t d;
  size_t n;

  gnutls_x509_crt_export2 (c->crt, GNUTLS_X509_FMT_DER, &d);
  n = d.size;
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

static gq_trust *
trust_of (const struct tst_cert *anchor)
{
  gnutls_datum_t pem;
  gq_trust *t;

  CHECK_EQ (gq_trust_new (&t), GQ_OK);
  gnutls_x509_crt_export2 (anchor->crt, GNUTLS_X509_FMT_PEM, &pem);
  CHECK_EQ (gq_trust_add_pem (t, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
  return t;
}

static void
setup_fixtures (void)
{
  const long nb = -3600, na = 86400;

  CHECK_EQ (tst_make_cert (&ca, TST_ECDSA256, "CA", NULL, NULL, nb, na,
                           GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&ca2, TST_ECDSA256, "CA2", NULL, NULL, nb, na,
                           GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&ec, TST_ECDSA256, "ec", "example.test", &ca, nb,
                           na, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&rsa, TST_RSA2048, "rsa", "other.test", &ca, nb,
                           na, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&ed_srv, TST_ED25519, "ed", "ed.test", &ca, nb, na,
                           GNUTLS_DIG_UNKNOWN), 0);
  CHECK_EQ (tst_make_cert_eku (&cli_ok, TST_ED25519, "client", "client.test",
                               &ca, nb, na, GNUTLS_DIG_UNKNOWN,
                               GNUTLS_KP_TLS_WWW_CLIENT), 0);
  CHECK_EQ (tst_make_cert_eku (&cli_bad_ca, TST_ECDSA256, "client2",
                               "client.test", &ca2, nb, na,
                               GNUTLS_DIG_SHA256, GNUTLS_KP_TLS_WWW_CLIENT), 0);
  CHECK_EQ (tst_make_cert_eku (&cli_wrong_eku, TST_ECDSA256, "client3",
                               "client.test", &ca, nb, na, GNUTLS_DIG_SHA256,
                               GNUTLS_KP_TLS_WWW_SERVER), 0);
  ec_chain[0] = (gq_slice) { ec_der, der_of (&ec, ec_der) };
  rsa_chain[0] = (gq_slice) { rsa_der, der_of (&rsa, rsa_der) };
  ed_chain[0] = (gq_slice) { ed_der, der_of (&ed_srv, ed_der) };
  cli_chain[0] = (gq_slice) { cli_der, der_of (&cli_ok, cli_der) };
  clibad_chain[0] = (gq_slice) { clibad_der, der_of (&cli_bad_ca, clibad_der) };
  clieku_chain[0] = (gq_slice) { clieku_der, der_of (&cli_wrong_eku, clieku_der) };
  ec_key = key_of (&ec);
  rsa_key = key_of (&rsa);
  ed_key = key_of (&ed_srv);
  cli_ok_key = key_of (&cli_ok);
  cli_bad_key = key_of (&cli_bad_ca);
  cli_eku_key = key_of (&cli_wrong_eku);
  client_trust = trust_of (&ca);
  server_trust = trust_of (&ca);
  ec_creds = (gq_tls_credentials) { ec_chain, 1, ec_key };
  rsa_creds = (gq_tls_credentials) { rsa_chain, 1, rsa_key };
  ed_creds = (gq_tls_credentials) { ed_chain, 1, ed_key };
}

/* ------------------------------------------------------------------ */
/* One endpoint's recorded events                                     */
/* ------------------------------------------------------------------ */

struct end
{
  gq_tls *tls;
  uint8_t sent[4][16384];
  size_t sent_len[4];
  gq_tls_secret secrets[32];
  int n_secrets;
  int complete;
  gq_tls_info info;
  int alert;
  uint8_t peer_tp[64];
  size_t peer_tp_len;
  gq_tls_session session;		/* Last ticket received.  */
  int n_tickets;
  unsigned hs_seq[8];		/* Handshake-level message types sent.  */
  int n_hs;
};

static int
e_send (void *u, enum gq_level l, const uint8_t *d, size_t n)
{
  struct end *e = u;

  if (l == GQ_LEVEL_HANDSHAKE && n > 0 && e->n_hs < 8)
    e->hs_seq[e->n_hs++] = d[0];
  memcpy (e->sent[l] + e->sent_len[l], d, n);
  e->sent_len[l] += n;
  return 0;
}

static int
e_secret (void *u, const gq_tls_secret *s)
{
  struct end *e = u;

  e->secrets[e->n_secrets++] = *s;
  return 0;
}

static int
e_params (void *u, const uint8_t *d, size_t n)
{
  struct end *e = u;

  memcpy (e->peer_tp, d, n);
  e->peer_tp_len = n;
  return 0;
}

static int
e_complete (void *u, const gq_tls_info *i)
{
  struct end *e = u;

  e->complete = 1;
  e->info = *i;
  return 0;
}

static int
e_ticket (void *u, const gq_tls_ticket *t)
{
  struct end *e = u;

  e->n_tickets++;
  return gq_tls_session_store (&e->session, t) == GQ_OK ? 0 : 1;
}

static int
e_alert (void *u, unsigned code)
{
  ((struct end *) u)->alert = (int) code;
  return 0;
}

static gq_tls_sink
sink_for (struct end *e)
{
  gq_tls_sink s;

  memset (&s, 0, sizeof s);
  s.user = e;
  s.send = e_send;
  s.secret = e_secret;
  s.peer_params = e_params;
  s.complete = e_complete;
  s.ticket = e_ticket;
  s.alert = e_alert;
  return s;
}

/* A pair under test: config templates the tests adjust.  */
struct pair
{
  struct end c, s;
  gq_tls_config cc;
  gq_tls_server_config sc;
  gq_tls_sink csink, ssink;
  gq_slice calpn[2], salpn[2];
  uint8_t ctp[4], stp[4];
  gq_slice cchain[1];
  uint64_t cnow, snow;		/* Fake clocks, milliseconds.  */
};

static uint64_t
clock_of (void *u)
{
  return *(uint64_t *) u;
}

static struct pair *
pair_new (void)
{
  struct pair *p = calloc (1, sizeof *p);

  p->c.alert = p->s.alert = -1;
  p->cnow = p->snow = UINT64_C (1700000000000);
  p->cc.hooks.now_ms = clock_of;
  p->cc.hooks.user = &p->cnow;
  p->sc.hooks.now_ms = clock_of;
  p->sc.hooks.user = &p->snow;
  p->cc.server_name = "example.test";
  p->cc.trust = client_trust;
  p->sc.credentials = ec_creds;
  p->csink = sink_for (&p->c);
  p->ssink = sink_for (&p->s);
  memset (p->ctp, 0xc1, sizeof p->ctp);
  memset (p->stp, 0x5e, sizeof p->stp);
  return p;
}

static void
pair_create (struct pair *p)
{
  CHECK_EQ (gq_tls_client_new (&p->c.tls, &p->cc, &p->csink), GQ_OK);
  CHECK_EQ (gq_tls_server_new (&p->s.tls, &p->sc, &p->ssink), GQ_OK);
}

static void
pair_free (struct pair *p)
{
  gq_tls_free (p->c.tls);
  gq_tls_free (p->s.tls);
  free (p);
}

static int
feed_end (struct end *dst, enum gq_level level, const uint8_t *d, size_t n,
          size_t chunk)
{
  int r = GQ_OK;

  if (chunk == 0)
    chunk = n;
  while (n > 0 && r == GQ_OK)
    {
      size_t k = n < chunk ? n : chunk;
      const uint8_t *p = d;
      size_t l = k;

      r = gq_tls_feed (dst->tls, level, &p, &l);
      d += k;
      n -= k;
    }
  return r;
}

/* Move every pending byte between the two engines until quiet.  Stops at
   the first failure and returns its status (client feed first).  */
static int
pump (struct pair *p, size_t chunk)
{
  int moved = 1, r = GQ_OK, lv;

  while (moved && r == GQ_OK)
    {
      moved = 0;
      for (lv = 0; lv < 4 && r == GQ_OK; lv++)
        {
          size_t n = p->c.sent_len[lv];

          if (n)
            {
              uint8_t buf[16384];

              memcpy (buf, p->c.sent[lv], n);
              p->c.sent_len[lv] = 0;
              r = feed_end (&p->s, (enum gq_level) lv, buf, n, chunk);
              moved = 1;
            }
        }
      for (lv = 0; lv < 4 && r == GQ_OK; lv++)
        {
          size_t n = p->s.sent_len[lv];

          if (n)
            {
              uint8_t buf[16384];

              memcpy (buf, p->s.sent[lv], n);
              p->s.sent_len[lv] = 0;
              r = feed_end (&p->c, (enum gq_level) lv, buf, n, chunk);
              moved = 1;
            }
        }
    }
  return r;
}

static const gq_tls_secret *
find (const struct end *e, enum gq_level lv, enum gq_dir d)
{
  int i;

  for (i = e->n_secrets - 1; i >= 0; i--)
    if (e->secrets[i].level == lv && e->secrets[i].dir == d)
      return &e->secrets[i];
  return NULL;
}

static int
same_secret (const gq_tls_secret *a, const gq_tls_secret *b)
{
  return a && b && a->len == b->len && a->aead == b->aead
    && memcmp (a->secret, b->secret, a->len) == 0;
}

/* The two ends must hold mirror-image keys at every level.  */
static void
check_mirror (const struct pair *p)
{
  CHECK (same_secret (find (&p->c, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ),
                      find (&p->s, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE)));
  CHECK (same_secret (find (&p->c, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE),
                      find (&p->s, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ)));
  CHECK (same_secret (find (&p->c, GQ_LEVEL_APPLICATION, GQ_DIR_READ),
                      find (&p->s, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE)));
  CHECK (same_secret (find (&p->c, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE),
                      find (&p->s, GQ_LEVEL_APPLICATION, GQ_DIR_READ)));
}

static void
check_exporters (const struct pair *p)
{
  uint8_t a[32], b[32];

  CHECK_EQ (gq_tls_export (p->c.tls, "EXPORTER-test", (const uint8_t *) "ctx",
                           3, a, 32), GQ_OK);
  CHECK_EQ (gq_tls_export (p->s.tls, "EXPORTER-test", (const uint8_t *) "ctx",
                           3, b, 32), GQ_OK);
  CHECK (memcmp (a, b, 32) == 0);
}

static void
check_success (const struct pair *p)
{
  CHECK (p->c.complete && p->s.complete);
  CHECK (gq_tls_is_complete (p->c.tls) && gq_tls_is_complete (p->s.tls));
  check_mirror (p);
  check_exporters (p);
  CHECK_EQ (p->c.info.cipher_suite, p->s.info.cipher_suite);
  CHECK_EQ (p->c.info.group, p->s.info.group);
  CHECK_EQ (p->c.info.hello_retry, p->s.info.hello_retry);
  CHECK_EQ (p->c.info.alpn_len, p->s.info.alpn_len);
}

/* ------------------------------------------------------------------ */
/* Tests                                                              */
/* ------------------------------------------------------------------ */

static void
test_basic (size_t chunk)
{
  struct pair *p = pair_new ();

  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, chunk), GQ_OK);
  check_success (p);
  /* Server preference is the policy order; the hybrid group leads.  */
  CHECK_EQ (p->s.info.group, GQ_GROUP_X25519_MLKEM768);
  CHECK_EQ (p->s.info.cipher_suite, GQ_TLS_AES_256_GCM_SHA384);
  CHECK (p->s.info.server_name_len == 12
         && strcmp (p->s.info.server_name, "example.test") == 0);
  CHECK_EQ (p->c.info.client_auth_requested, 0);
  /* Servers do not start; clients cannot be fed before starting.  */
  CHECK_EQ (gq_tls_start (p->s.tls), GQ_ERR_INVAL);
  pair_free (p);
}

static void
test_hrr (int cookie)
{
  struct pair *p = pair_new ();
  static const uint16_t only_p384[] = { GQ_GROUP_SECP384R1 };

  p->sc.groups = only_p384;
  p->sc.n_groups = 1;
  p->sc.hello_retry_cookie = cookie;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.hello_retry, 1);
  CHECK_EQ (p->s.info.group, GQ_GROUP_SECP384R1);
  pair_free (p);
}

static void
test_preferences (void)
{
  struct pair *p = pair_new ();
  static const uint16_t suites[] = { GQ_TLS_CHACHA20_POLY1305_SHA256,
                                     GQ_TLS_AES_128_GCM_SHA256 };
  static const uint16_t groups[] = { GQ_GROUP_SECP256R1, GQ_GROUP_X25519 };

  /* Server order wins: ChaCha20, and P-256 although the client also sent
     an X25519 share (it sent hybrid and X25519 shares only, so the server
     falls back to a retry for its preferred group).  */
  p->sc.suites = suites;
  p->sc.n_suites = 2;
  p->sc.groups = groups;
  p->sc.n_groups = 2;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.cipher_suite, GQ_TLS_CHACHA20_POLY1305_SHA256);
  /* The client had shares for hybrid and X25519; the server, preferring
     P-256 but having an acceptable share (X25519), avoids the retry.  */
  CHECK_EQ (p->s.info.group, GQ_GROUP_X25519);
  CHECK_EQ (p->s.info.hello_retry, 0);
  pair_free (p);
}

static const gq_tls_credentials *
by_name (void *u, const char *name)
{
  int *calls = u;

  (*calls)++;
  if (name == NULL || strcmp (name, "example.test") == 0)
    return &ec_creds;
  if (strcmp (name, "other.test") == 0)
    return &rsa_creds;
  return NULL;
}

static void
test_sni_credentials (void)
{
  struct pair *p;
  int calls = 0;

  p = pair_new ();
  p->sc.select_credentials = by_name;
  p->sc.select_user = &calls;
  p->cc.server_name = "other.test";
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (calls, 1);
  CHECK (strcmp (p->s.info.server_name, "other.test") == 0);
  pair_free (p);

  /* An unknown name is refused with unrecognized_name.  */
  p = pair_new ();
  p->sc.select_credentials = by_name;
  p->sc.select_user = &calls;
  p->cc.server_name = "nowhere.test";
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, 112);
  pair_free (p);

  /* No SNI: the callback sees NULL and can pick a default.  */
  p = pair_new ();
  p->sc.select_credentials = by_name;
  p->sc.select_user = &calls;
  p->cc.server_name = NULL;
  p->cc.trust = NULL;
  p->csink.verify_peer = NULL;
  {
    /* Without a name the client cannot check host names; trust the CA.  */
    p->cc.trust = client_trust;
  }
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.server_name_len, 0);
  pair_free (p);

  /* The certificate type follows the client's signature algorithms: an
     Ed25519 server certificate needs a client that lists Ed25519.  */
  p = pair_new ();
  p->sc.credentials = ed_creds;
  p->cc.server_name = "ed.test";
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  pair_free (p);

  p = pair_new ();
  {
    static const uint16_t ecdsa_only[] = { GQ_SIG_ECDSA_SECP256R1_SHA256 };

    p->sc.credentials = ed_creds;
    p->cc.server_name = "ed.test";
    p->cc.sigschemes = ecdsa_only;
    p->cc.n_sigschemes = 1;
  }
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (p->s.alert, GQ_ALERT_HANDSHAKE_FAILURE);
  pair_free (p);
}

static void
test_alpn_and_quic (void)
{
  struct pair *p;

  /* Server preference decides.  */
  p = pair_new ();
  p->calpn[0] = (gq_slice) { (const uint8_t *) "http/1.1", 8 };
  p->calpn[1] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->salpn[1] = (gq_slice) { (const uint8_t *) "http/1.1", 8 };
  p->cc.alpn = p->calpn;
  p->cc.n_alpn = 2;
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 2;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK (p->s.info.alpn_len == 2 && memcmp (p->s.info.alpn, "h2", 2) == 0);
  CHECK (p->c.info.alpn_len == 2 && memcmp (p->c.info.alpn, "h2", 2) == 0);
  pair_free (p);

  /* No overlap: no_application_protocol.  */
  p = pair_new ();
  p->calpn[0] = (gq_slice) { (const uint8_t *) "foo", 3 };
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->cc.alpn = p->calpn;
  p->cc.n_alpn = 1;
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, GQ_ALERT_NO_APPLICATION_PROTOCOL);
  pair_free (p);

  /* A server with ALPN configured and a client that sends none: fine
     over TLS, selects nothing.  */
  p = pair_new ();
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.alpn_len, 0);
  pair_free (p);

  /* QUIC: transport parameters both ways, ALPN mandatory, no KeyUpdate.  */
  p = pair_new ();
  p->calpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  p->cc.alpn = p->calpn;
  p->cc.n_alpn = 1;
  p->cc.transport_params = p->ctp;
  p->cc.transport_params_len = sizeof p->ctp;
  p->cc.quic = 1;
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 1;
  p->sc.transport_params = p->stp;
  p->sc.transport_params_len = sizeof p->stp;
  p->sc.quic = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK (p->s.peer_tp_len == 4 && memcmp (p->s.peer_tp, p->ctp, 4) == 0);
  CHECK (p->c.peer_tp_len == 4 && memcmp (p->c.peer_tp, p->stp, 4) == 0);
  CHECK_EQ (gq_tls_key_update (p->s.tls, 0), GQ_ERR_INVAL);
  pair_free (p);

  /* A QUIC server needs the client's transport parameters.  */
  p = pair_new ();
  p->calpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  p->cc.alpn = p->calpn;
  p->cc.n_alpn = 1;
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 1;
  p->sc.transport_params = p->stp;
  p->sc.transport_params_len = sizeof p->stp;
  p->sc.quic = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, GQ_ALERT_MISSING_EXTENSION);
  pair_free (p);
}

static void
client_cert (struct pair *p, const gq_slice *chain, gq_privkey *key)
{
  p->cchain[0] = chain[0];
  p->cc.client_chain = p->cchain;
  p->cc.n_client_chain = 1;
  p->cc.client_key = key;
}

static void
test_client_auth (void)
{
  struct pair *p;

  /* Required, valid Ed25519 client certificate.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  client_cert (p, cli_chain, cli_ok_key);
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.client_auth_requested, 1);
  CHECK_EQ (p->c.info.client_auth_sent, 1);
  CHECK_EQ (p->s.info.client_auth_requested, 1);
  CHECK_EQ (p->s.info.client_auth_sent, 1);	/* Verified.  */
  pair_free (p);

  /* Optional and absent: the handshake completes unauthenticated.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_OPTIONAL;
  p->sc.client_trust = server_trust;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.client_auth_requested, 1);
  CHECK_EQ (p->s.info.client_auth_sent, 0);
  pair_free (p);

  /* Required and absent: certificate_required.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_CERT);
  CHECK_EQ (p->s.alert, 116);
  pair_free (p);

  /* Certificate from an untrusted CA: unknown_ca.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  client_cert (p, clibad_chain, cli_bad_key);
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_CERT);
  CHECK_EQ (p->s.alert, GQ_ALERT_UNKNOWN_CA);
  pair_free (p);

  /* A serverAuth-only certificate cannot authenticate a client.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  client_cert (p, clieku_chain, cli_eku_key);
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_CERT);
  CHECK_EQ (p->s.alert, GQ_ALERT_BAD_CERTIFICATE);
  pair_free (p);

  /* Asking for certificates with no way to verify them is refused when
     the engine is created.  */
  {
    gq_tls *t;
    gq_tls_server_config sc;
    struct end e;
    gq_tls_sink sk = sink_for (&e);

    memset (&sc, 0, sizeof sc);
    sc.credentials = ec_creds;
    sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
    CHECK_EQ (gq_tls_server_new (&t, &sc, &sk), GQ_ERR_INVAL);
    sc.client_auth = GQ_CLIENT_AUTH_NONE;
    sc.credentials.key = NULL;
    CHECK_EQ (gq_tls_server_new (&t, &sc, &sk), GQ_ERR_INVAL);
  }
}

static void
test_key_update (void)
{
  struct pair *p = pair_new ();
  int before_c, before_s;
  uint8_t next[48];
  const gq_tls_secret *cw, *sw;

  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);

  /* Client asks; the server rekeys its read side, answers and rekeys its
     write side; the client follows.  */
  before_c = p->c.n_secrets;
  before_s = p->s.n_secrets;
  CHECK_EQ (gq_tls_key_update (p->c.tls, 1), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  CHECK_EQ (p->c.n_secrets, before_c + 2);	/* Write, then read.  */
  CHECK_EQ (p->s.n_secrets, before_s + 2);	/* Read, then write.  */
  check_mirror (p);
  cw = find (&p->c, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE);
  sw = find (&p->s, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE);
  CHECK (cw != sw && memcmp (cw->secret, sw->secret, cw->len) != 0);
  (void) next;

  /* Server-initiated, not asking for a reply.  */
  before_c = p->c.n_secrets;
  CHECK_EQ (gq_tls_key_update (p->s.tls, 0), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  CHECK_EQ (p->c.n_secrets, before_c + 1);
  check_mirror (p);
  pair_free (p);
}

/* ---- ClientHello failures, by crafting or mutating ---- */

/* Client hello bytes produced by a fresh client.  */
static size_t
client_hello (struct pair *p, uint8_t *out)
{
  size_t n;

  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  n = p->c.sent_len[GQ_LEVEL_INITIAL];
  memcpy (out, p->c.sent[GQ_LEVEL_INITIAL], n);
  p->c.sent_len[GQ_LEVEL_INITIAL] = 0;
  return n;
}

/* Remove extension TYPE from a ClientHello by renaming it to an unknown
   type (keeps all lengths intact).  */
static int
rename_ext (uint8_t *ch, size_t n, unsigned type, unsigned to)
{
  gq_slice exts, v, rest;
  gq_client_hello c;
  unsigned t;

  if (gq_client_hello_parse ((gq_slice) { ch + 4, n - 4 }, &c) != GQ_OK)
    return 0;
  exts = c.extensions;
  rest = exts;
  while (gq_ext_next (&rest, &t, &v) == 1)
    if (t == type)
      {
        uint8_t *p = ch + (v.data - ch) - 4;

        p[0] = (uint8_t) (to >> 8);
        p[1] = (uint8_t) to;
        return 1;
      }
  return 0;
}

static void
expect_server_fail (struct pair *p, const uint8_t *ch, size_t n, int status,
                    int alert)
{
  int r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0);

  CHECK_EQ (r, status);
  CHECK_EQ (p->s.alert, alert);
  CHECK (gq_tls_is_failed (p->s.tls));
  /* A failed engine refuses more input.  */
  {
    const uint8_t b[4] = { 0 };
    const uint8_t *q = b;
    size_t l = 4;

    CHECK_EQ (gq_tls_feed (p->s.tls, GQ_LEVEL_INITIAL, &q, &l), GQ_ERR_INVAL);
  }
}

static void
test_client_hello_failures (void)
{
  struct pair *p;
  uint8_t ch[8192];
  size_t n;

  /* Missing mandatory extensions.  */
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK (rename_ext (ch, n, GQ_EXT_SIGNATURE_ALGORITHMS, 0x0fff));
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_MISSING_EXTENSION);
  pair_free (p);

  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK (rename_ext (ch, n, GQ_EXT_KEY_SHARE, 0x0fff));
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_MISSING_EXTENSION);
  pair_free (p);

  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK (rename_ext (ch, n, GQ_EXT_SUPPORTED_GROUPS, 0x0fff));
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_MISSING_EXTENSION);
  pair_free (p);

  /* No supported_versions: a TLS 1.2 client.  */
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK (rename_ext (ch, n, GQ_EXT_SUPPORTED_VERSIONS, 0x0fff));
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_PROTOCOL_VERSION);
  pair_free (p);

  /* Old legacy_version.  */
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  ch[4] = 3; ch[5] = 1;
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_PROTOCOL_VERSION);
  pair_free (p);

  /* No suite in common.  */
  p = pair_new ();
  {
    static const uint16_t s_only[] = { GQ_TLS_CHACHA20_POLY1305_SHA256 };
    static const uint16_t c_only[] = { GQ_TLS_AES_128_GCM_SHA256 };

    p->sc.suites = s_only;
    p->sc.n_suites = 1;
    p->cc.suites = c_only;
    p->cc.n_suites = 1;
  }
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (p->s.alert, GQ_ALERT_HANDSHAKE_FAILURE);
  pair_free (p);

  /* No group in common.  */
  p = pair_new ();
  {
    static const uint16_t s_only[] = { GQ_GROUP_SECP384R1 };
    static const uint16_t c_only[] = { GQ_GROUP_X25519 };

    p->sc.groups = s_only;
    p->sc.n_groups = 1;
    p->cc.groups = c_only;
    p->cc.n_groups = 1;
  }
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (p->s.alert, GQ_ALERT_HANDSHAKE_FAILURE);
  pair_free (p);

  /* Wrong first message: Finished where a ClientHello belongs; and a
     ClientHello at the wrong level.  */
  p = pair_new ();
  pair_create (p);
  {
    uint8_t fin[36] = { GQ_HS_FINISHED, 0, 0, 32 };

    expect_server_fail (p, fin, sizeof fin, GQ_ERR_PROTOCOL,
                        GQ_ALERT_UNEXPECTED_MESSAGE);
  }
  pair_free (p);
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_HANDSHAKE, ch, n, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, GQ_ALERT_UNEXPECTED_MESSAGE);
  pair_free (p);

  /* Absurd declared length.  */
  p = pair_new ();
  pair_create (p);
  {
    uint8_t hdr[4] = { GQ_HS_CLIENT_HELLO, 0x10, 0, 0 };

    expect_server_fail (p, hdr, 4, GQ_ERR_PROTOCOL, GQ_ALERT_ILLEGAL_PARAMETER);
  }
  pair_free (p);

  /* A second ClientHello after the handshake started, or after it ended.  */
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0), GQ_OK);
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, GQ_ALERT_UNEXPECTED_MESSAGE);
  pair_free (p);
}

static void
test_hrr_client_hello_failures (void)
{
  int variant;

  /* After a HelloRetryRequest, ClientHello2 must repeat ClientHello1.  */
  for (variant = 0; variant < 5; variant++)
    {
      struct pair *p = pair_new ();
      static const uint16_t only_p384[] = { GQ_GROUP_SECP384R1 };
      uint8_t ch1[8192], ch2[8192];
      size_t n1, n2;
      uint8_t *body;
      int r, want_alert;

      p->sc.groups = only_p384;
      p->sc.n_groups = 1;
      p->sc.hello_retry_cookie = (variant == 3 || variant == 4);
      pair_create (p);
      n1 = client_hello (p, ch1);
      CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch1, n1, 0), GQ_OK);
      /* The server answered with a HelloRetryRequest; the client replies.  */
      {
        uint8_t hrr[8192];
        size_t hn = p->s.sent_len[GQ_LEVEL_INITIAL];

        memcpy (hrr, p->s.sent[GQ_LEVEL_INITIAL], hn);
        p->s.sent_len[GQ_LEVEL_INITIAL] = 0;
        CHECK_EQ (feed_end (&p->c, GQ_LEVEL_INITIAL, hrr, hn, 0), GQ_OK);
      }
      n2 = p->c.sent_len[GQ_LEVEL_INITIAL];
      memcpy (ch2, p->c.sent[GQ_LEVEL_INITIAL], n2);
      p->c.sent_len[GQ_LEVEL_INITIAL] = 0;
      body = ch2 + 4;

      switch (variant)
        {
        case 0:			/* Different random.  */
          body[2] ^= 1;
          want_alert = GQ_ALERT_ILLEGAL_PARAMETER;
          break;
        case 1:			/* Different session ID.  */
          body[2 + 32 + 1] ^= 1;
          want_alert = GQ_ALERT_ILLEGAL_PARAMETER;
          break;
        case 2:			/* Cipher suites changed.  */
          body[2 + 32 + 1 + 32 + 2 + 1] ^= 0x04;
          want_alert = GQ_ALERT_ILLEGAL_PARAMETER;
          break;
        case 3:			/* Cookie not echoed.  */
          CHECK (rename_ext (ch2, n2, GQ_EXT_COOKIE, 0x0fff));
          want_alert = GQ_ALERT_MISSING_EXTENSION;
          break;
        default:		/* Wrong cookie.  */
          {
            gq_client_hello c;
            gq_slice v;

            CHECK_EQ (gq_client_hello_parse ((gq_slice) { ch2 + 4, n2 - 4 },
                                             &c), GQ_OK);
            CHECK (gq_ext_find (c.extensions, GQ_EXT_COOKIE, &v));
            ch2[(size_t) (v.data - ch2) + 5] ^= 1;
          }
          want_alert = GQ_ALERT_ILLEGAL_PARAMETER;
          break;
        }
      r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch2, n2, 0);
      CHECK_EQ (r, GQ_ERR_PROTOCOL);
      CHECK_EQ (p->s.alert, want_alert);
      pair_free (p);
    }
}

static void
test_finished_failures (void)
{
  struct pair *p = pair_new ();
  uint8_t out[16384];
  size_t n;
  int lv;

  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  /* Run until the client's Finished is pending, then corrupt it.  */
  for (lv = 0; lv < 4; lv++)
    {
      n = p->c.sent_len[lv];
      if (n)
        {
          memcpy (out, p->c.sent[lv], n);
          p->c.sent_len[lv] = 0;
          CHECK_EQ (feed_end (&p->s, (enum gq_level) lv, out, n, 0), GQ_OK);
        }
    }
  for (lv = 0; lv < 4; lv++)
    {
      n = p->s.sent_len[lv];
      if (n)
        {
          memcpy (out, p->s.sent[lv], n);
          p->s.sent_len[lv] = 0;
          CHECK_EQ (feed_end (&p->c, (enum gq_level) lv, out, n, 0), GQ_OK);
        }
    }
  n = p->c.sent_len[GQ_LEVEL_HANDSHAKE];
  CHECK_EQ (n, 4 + 48);		/* Finished under SHA-384.  */
  memcpy (out, p->c.sent[GQ_LEVEL_HANDSHAKE], n);
  out[n - 1] ^= 1;
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_HANDSHAKE, out, n, 0), GQ_ERR_CRYPTO);
  CHECK_EQ (p->s.alert, GQ_ALERT_DECRYPT_ERROR);
  CHECK (!p->s.complete);
  pair_free (p);
}

/* Corrupt the client's messages every way and check that the server never
   crashes and only completes with matching keys.  */
static unsigned long long rng = 0x2545f4914f6cdd1dULL;

static unsigned
rnd_below (unsigned n)
{
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return (unsigned) (rng % n);
}

static void
test_mutations (int iterations)
{
  int it, completed = 0, failed = 0;

  for (it = 0; it < iterations; it++)
    {
      struct pair *p = pair_new ();
      uint8_t ch[8192];
      size_t n, i, chunk;
      int r, nmut = (int) rnd_below (4);

      if (rnd_below (4) == 0)
        {
          static const uint16_t g[] = { GQ_GROUP_SECP256R1 };

          p->sc.groups = g;
          p->sc.n_groups = 1;
        }
      if (rnd_below (3) == 0)
        {
          p->sc.client_auth = GQ_CLIENT_AUTH_OPTIONAL;
          p->sc.client_trust = server_trust;
          client_cert (p, cli_chain, cli_ok_key);
        }
      pair_create (p);
      n = client_hello (p, ch);
      for (i = 0; i < (size_t) nmut; i++)
        ch[rnd_below ((unsigned) n)] ^= (uint8_t) (1u << rnd_below (8));
      if (rnd_below (8) == 0)
        n = rnd_below ((unsigned) n + 1);
      chunk = rnd_below (3) == 0 ? 1 + rnd_below (300) : 0;

      r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, chunk);
      if (r == GQ_OK)
        r = pump (p, chunk);
      if (r != GQ_OK)
        {
          failed++;
          CHECK (gq_tls_is_failed (p->s.tls) || gq_tls_is_failed (p->c.tls));
        }
      if (p->s.complete)
        {
          completed++;
          CHECK (p->c.complete);
          check_mirror (p);
        }
      pair_free (p);
    }
  CHECK (failed > 0);
  fprintf (stderr, "server mutations: %d completed, %d failed of %d\n",
           completed, failed, iterations);
}


/* ------------------------------------------------------------------ */
/* Resumption                                                         */
/* ------------------------------------------------------------------ */

/* Full handshake with tickets enabled; leaves the client's last session
   in SESSION.  */
static void
first_connection (gq_ticket_keys *keys, gq_tls_session *session,
                  const struct pair *tmpl_unused)
{
  struct pair *p = pair_new ();

  (void) tmpl_unused;
  p->sc.ticket_keys = keys;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 0);
  CHECK_EQ (p->c.n_tickets, 2);
  CHECK (p->s.n_hs == 4 && p->s.hs_seq[1] == GQ_HS_CERTIFICATE);
  *session = p->c.session;
  pair_free (p);
}

static void
test_resumption_basic (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess, restored;
  struct pair *p;
  uint8_t blob[GQ_TICKET_MAX + 128];
  size_t n;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);

  /* Resume, including from a session that went through storage.  */
  CHECK_EQ (gq_tls_session_serialize (&sess, blob, sizeof blob, &n), GQ_OK);
  CHECK_EQ (gq_tls_session_deserialize (&restored, blob, n), GQ_OK);
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.resume = &restored;
  p->cnow = p->snow += 5000;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 1);
  CHECK_EQ (p->s.info.resumed, 1);
  /* No certificate exchange: EncryptedExtensions and Finished only.  */
  CHECK (p->s.n_hs == 2 && p->s.hs_seq[0] == GQ_HS_ENCRYPTED_EXTENSIONS
         && p->s.hs_seq[1] == GQ_HS_FINISHED);
  /* The resumed session issues fresh tickets, usable in turn.  */
  CHECK_EQ (p->c.n_tickets, 2);
  CHECK (memcmp (p->c.session.ticket, sess.ticket, 16) == 0);	/* Same key.  */
  CHECK (memcmp (p->c.session.psk, sess.psk, sess.psk_len) != 0);
  sess = p->c.session;
  pair_free (p);

  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.resume = &sess;
  p->cnow = p->snow += 10000;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 1);
  pair_free (p);

  /* Chunked delivery and a different key derivation still agree.  */
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.resume = &restored;
  p->cnow = p->snow += 5000;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 1), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 1);
  pair_free (p);
  gq_ticket_keys_free (keys);
}

/* Whatever makes the server (or client) decline the ticket, the
   handshake still succeeds as a full one.  */
static void
fallback_case (const char *what, gq_ticket_keys *server_keys,
               const gq_tls_session *sess, uint64_t client_dt,
               uint64_t server_dt, int mutate_ticket)
{
  struct pair *p = pair_new ();
  static gq_tls_session s2;

  s2 = *sess;
  if (mutate_ticket)
    s2.ticket[40] ^= 1;
  p->sc.ticket_keys = server_keys;
  p->cc.resume = &s2;
  p->cnow += client_dt;
  p->snow += server_dt;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  if (pump (p, 0) != GQ_OK)
    fprintf (stderr, "fallback case failed: %s\n", what);
  CHECK (p->c.complete && p->s.complete);
  check_mirror (p);
  CHECK_EQ (p->c.info.resumed, 0);
  CHECK_EQ (p->s.info.resumed, 0);
  CHECK (p->s.n_hs >= 4 && p->s.hs_seq[1] == GQ_HS_CERTIFICATE);
  pair_free (p);
}

static void
test_resumption_fallbacks (void)
{
  gq_ticket_keys *keys, *other;
  static gq_tls_session sess;
  const uint64_t day = 86400000;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  CHECK_EQ (gq_ticket_keys_new (&other), GQ_OK);
  first_connection (keys, &sess, NULL);

  fallback_case ("server has other keys", other, &sess, 1000, 1000, 0);
  fallback_case ("ticket tampered", keys, &sess, 1000, 1000, 1);
  fallback_case ("server thinks it expired", keys, &sess, 1000, 2 * day, 0);
  fallback_case ("client knows it expired", keys, &sess, 2 * day, 2 * day, 0);
  /* Session says lifetime 0: never offered.  */
  {
    static gq_tls_session dead;

    dead = sess;
    dead.lifetime = 0;
    fallback_case ("zero lifetime", keys, &dead, 1000, 1000, 0);
  }
  /* A server with tickets switched off ignores the offer.  */
  fallback_case ("server has no ticket keys", NULL, &sess, 1000, 1000, 0);
  gq_ticket_keys_free (keys);
  gq_ticket_keys_free (other);
}

static void
test_resumption_policy (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  struct pair *p;
  int calls = 0;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);

  /* Bound to the server name: another name gets a full handshake, with
     the other certificate.  */
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->sc.select_credentials = by_name;
  p->sc.select_user = &calls;
  p->cc.resume = &sess;
  p->cc.server_name = "other.test";
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 0);
  pair_free (p);

  /* The suite of the ticket must still be allowed.  */
  {
    static const uint16_t chacha[] = { GQ_TLS_CHACHA20_POLY1305_SHA256 };

    p = pair_new ();
    p->sc.ticket_keys = keys;
    p->sc.suites = chacha;
    p->sc.n_suites = 1;
    p->cc.resume = &sess;
    pair_create (p);
    CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
    CHECK_EQ (pump (p, 0), GQ_OK);
    check_success (p);
    CHECK_EQ (p->c.info.resumed, 0);
    CHECK_EQ (p->s.info.cipher_suite, GQ_TLS_CHACHA20_POLY1305_SHA256);
    pair_free (p);
  }

  /* A client offering a suite it does not allow does not offer the PSK.  */
  {
    static const uint16_t chacha[] = { GQ_TLS_CHACHA20_POLY1305_SHA256 };

    p = pair_new ();
    p->sc.ticket_keys = keys;
    p->cc.suites = chacha;
    p->cc.n_suites = 1;
    p->cc.resume = &sess;
    pair_create (p);
    CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
    CHECK_EQ (pump (p, 0), GQ_OK);
    check_success (p);
    CHECK_EQ (p->c.info.resumed, 0);
    pair_free (p);
  }
  gq_ticket_keys_free (keys);
}

static void
test_resumption_client_auth (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session anon, authed;
  struct pair *p;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);

  /* A session from an unauthenticated connection cannot skip client
     authentication on a server that now requires it.  */
  first_connection (keys, &anon, NULL);
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  client_cert (p, cli_chain, cli_ok_key);
  p->cc.resume = &anon;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 0);
  CHECK_EQ (p->s.info.client_auth_sent, 1);	/* Verified this time.  */
  authed = p->c.session;
  pair_free (p);

  /* A session from an authenticated connection may resume, and the
     server remembers that the client was authenticated.  */
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  p->cc.resume = &authed;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 1);
  CHECK_EQ (p->s.info.client_auth_sent, 1);
  pair_free (p);
  gq_ticket_keys_free (keys);
}

static void
test_resumption_hrr (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  struct pair *p;
  static const uint16_t p384[] = { GQ_GROUP_SECP384R1 };
  int cookie;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);

  /* After a HelloRetryRequest the binder covers the message_hash
     transcript; with and without a cookie.  */
  for (cookie = 0; cookie < 2; cookie++)
    {
      p = pair_new ();
      p->sc.ticket_keys = keys;
      p->sc.groups = p384;
      p->sc.n_groups = 1;
      p->sc.hello_retry_cookie = cookie;
      p->cc.resume = &sess;
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      CHECK_EQ (pump (p, 0), GQ_OK);
      check_success (p);
      CHECK_EQ (p->c.info.resumed, 1);
      CHECK_EQ (p->c.info.hello_retry, 1);
      CHECK_EQ (p->s.info.group, GQ_GROUP_SECP384R1);
      pair_free (p);
    }
  gq_ticket_keys_free (keys);
}

static void
test_resumption_quic (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  int pass;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  for (pass = 0; pass < 2; pass++)
    {
      struct pair *p = pair_new ();

      p->calpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
      p->salpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
      p->cc.alpn = p->calpn;
      p->cc.n_alpn = 1;
      p->cc.transport_params = p->ctp;
      p->cc.transport_params_len = sizeof p->ctp;
      p->cc.quic = 1;
      p->sc.alpn = p->salpn;
      p->sc.n_alpn = 1;
      p->sc.transport_params = p->stp;
      p->sc.transport_params_len = sizeof p->stp;
      p->sc.quic = 1;
      p->sc.ticket_keys = keys;
      if (pass)
        p->cc.resume = &sess;
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      CHECK_EQ (pump (p, 0), GQ_OK);
      check_success (p);
      CHECK_EQ (p->c.info.resumed, pass);
      /* Transport parameters still travel in a resumed handshake.  */
      CHECK (p->s.peer_tp_len == 4 && p->c.peer_tp_len == 4);
      if (!pass)
        sess = p->c.session;
      pair_free (p);
    }
  gq_ticket_keys_free (keys);
}

/* A wrong binder is fatal, not a fallback.  */
static void
test_resumption_binder_failure (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  struct pair *p;
  uint8_t ch[8192];
  size_t n;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.resume = &sess;
  pair_create (p);
  n = client_hello (p, ch);
  ch[n - 1] ^= 1;
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0), GQ_ERR_CRYPTO);
  CHECK_EQ (p->s.alert, GQ_ALERT_DECRYPT_ERROR);
  pair_free (p);
  gq_ticket_keys_free (keys);
}

static void
test_resumption_mutations (int iterations)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  int it, completed = 0, resumed = 0;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);
  for (it = 0; it < iterations; it++)
    {
      struct pair *p = pair_new ();
      uint8_t ch[8192];
      size_t n, i;
      int r, nmut = (int) rnd_below (4);

      p->sc.ticket_keys = keys;
      p->cc.resume = &sess;
      if (rnd_below (3) == 0)
        {
          static const uint16_t g[] = { GQ_GROUP_SECP256R1 };

          p->sc.groups = g;
          p->sc.n_groups = 1;
        }
      pair_create (p);
      n = client_hello (p, ch);
      for (i = 0; i < (size_t) nmut; i++)
        ch[rnd_below ((unsigned) n)] ^= (uint8_t) (1u << rnd_below (8));
      if (rnd_below (8) == 0)
        n = rnd_below ((unsigned) n + 1);
      r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0);
      if (r == GQ_OK)
        r = pump (p, 0);
      if (p->s.complete)
        {
          completed++;
          resumed += p->s.info.resumed;
          CHECK (p->c.complete);
          check_mirror (p);
        }
      pair_free (p);
    }
  fprintf (stderr, "resumption mutations: %d completed (%d resumed) of %d\n",
           completed, resumed, iterations);
  gq_ticket_keys_free (keys);
}

int
main (void)
{
  setup_fixtures ();
  test_basic (0);
  test_basic (1);
  test_basic (17);
  test_hrr (0);
  test_hrr (1);
  test_preferences ();
  test_sni_credentials ();
  test_alpn_and_quic ();
  test_client_auth ();
  test_key_update ();
  test_client_hello_failures ();
  test_hrr_client_hello_failures ();
  test_finished_failures ();
  test_mutations (1200);
  test_resumption_basic ();
  test_resumption_fallbacks ();
  test_resumption_policy ();
  test_resumption_client_auth ();
  test_resumption_hrr ();
  test_resumption_quic ();
  test_resumption_binder_failure ();
  test_resumption_mutations (800);
  TST_DONE ();
}

#endif
