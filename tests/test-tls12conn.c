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

/* TLS 1.2 over a byte stream: a client and a server connection joined
   back to back, with real records.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/tls12conn.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"

struct bytes
{
  uint8_t *p;
  size_t n, cap;
};

static void
bytes_add (struct bytes *b, const uint8_t *d, size_t n)
{
  if (b->n + n > b->cap)
    {
      b->cap = (b->n + n) * 2 + 64;
      b->p = realloc (b->p, b->cap);
    }
  memcpy (b->p + b->n, d, n);
  b->n += n;
}

struct ev
{
  struct bytes wire;		/* What this side wrote.  */
  struct bytes app;		/* Application data it received.  */
  int connected, closed, close_error, close_alert, tickets;
  gq_tls_info info;
  gq_tls_session session;
  int have_session;
};

static int
ev_write (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct ev *) u)->wire, d, n);
  return 0;
}

static int
ev_data (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct ev *) u)->app, d, n);
  return 0;
}

static int
ev_connected (void *u, const gq_tls_info *i)
{
  struct ev *e = u;

  e->connected = 1;
  e->info = *i;
  return 0;
}

static int
ev_ticket (void *u, const gq_tls_ticket *t)
{
  struct ev *e = u;

  e->tickets++;
  CHECK_EQ (gq_tls_session_store (&e->session, t), GQ_OK);
  e->have_session = 1;
  return 0;
}

static void
ev_closed (void *u, int error, int alert)
{
  struct ev *e = u;

  e->closed++;
  e->close_error = error;
  e->close_alert = alert;
}

struct link
{
  gq_tls12conn *c, *s;
  struct ev ce, se;
  gq_tls_config cc;
  gq_tls_server_config sc;
  gq_tlsconn_events cev, sev;
};

static struct link *
link_new (struct ident *id, const uint16_t *csuites, gq_ticket_keys *keys,
          const gq_tls_session *resume, struct ident *cli,
          enum gq_client_auth auth)
{
  struct link *l = calloc (1, sizeof *l);

  l->cc.server_name = "example.test";
  l->cc.trust = fx_trust;
  l->cc.suites = csuites;
  l->cc.n_suites = csuites ? 1 : 0;
  l->cc.resume = resume;
  if (cli)
    {
      l->cc.client_chain = cli->chain;
      l->cc.n_client_chain = 1;
      l->cc.client_key = cli->key;
    }
  l->sc.credentials.chain = id->chain;
  l->sc.credentials.n_chain = 1;
  l->sc.credentials.key = id->key;
  l->sc.ticket_keys = keys;
  l->sc.client_auth = auth;
  l->sc.client_trust = fx_trust;
  l->cev.user = &l->ce;
  l->cev.write = ev_write;
  l->cev.data = ev_data;
  l->cev.connected = ev_connected;
  l->cev.ticket = ev_ticket;
  l->cev.closed = ev_closed;
  l->sev = l->cev;
  l->sev.user = &l->se;
  CHECK_EQ (gq_tls12conn_client_new (&l->c, &l->cc, &l->cev), GQ_OK);
  CHECK_EQ (gq_tls12conn_server_new (&l->s, &l->sc, &l->sev), GQ_OK);
  return l;
}

static void
link_free (struct link *l)
{
  gq_tls12conn_free (l->c);
  gq_tls12conn_free (l->s);
  free (l->ce.wire.p); free (l->ce.app.p);
  free (l->se.wire.p); free (l->se.app.p);
  free (l);
}

/* Move bytes both ways, CHUNK at a time (0: whole), until quiet.  */
static void
pump (struct link *l, size_t chunk)
{
  int guard;

  for (guard = 0; guard < 200; guard++)
    {
      size_t pos, n;
      int moved = 0;

      if (l->ce.wire.n)
        {
          uint8_t *copy = malloc (l->ce.wire.n);

          n = l->ce.wire.n;
          memcpy (copy, l->ce.wire.p, n);
          l->ce.wire.n = 0;
          for (pos = 0; pos < n; )
            {
              size_t k = chunk && n - pos > chunk ? chunk : n - pos;

              if (!gq_tls12conn_is_closed (l->s))
                gq_tls12conn_receive (l->s, copy + pos, k);
              pos += k;
            }
          free (copy);
          moved = 1;
        }
      if (l->se.wire.n)
        {
          uint8_t *copy = malloc (l->se.wire.n);

          n = l->se.wire.n;
          memcpy (copy, l->se.wire.p, n);
          l->se.wire.n = 0;
          for (pos = 0; pos < n; )
            {
              size_t k = chunk && n - pos > chunk ? chunk : n - pos;

              if (!gq_tls12conn_is_closed (l->c))
                gq_tls12conn_receive (l->c, copy + pos, k);
              pos += k;
            }
          free (copy);
          moved = 1;
        }
      if (!moved)
        break;
    }
}

static const uint16_t s_ecdsa128[] = { GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };
static const uint16_t s_ecdsachacha[] = { GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 };
static const uint16_t s_rsa256[] = { GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 };

static void
test_data (struct ident *id, const uint16_t *suite, size_t chunk)
{
  struct link *l = link_new (id, suite, NULL, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  static uint8_t big[200000], back[70000];
  size_t i;

  for (i = 0; i < sizeof big; i++)
    big[i] = (uint8_t) (i * 31 + i / 251);
  for (i = 0; i < sizeof back; i++)
    back[i] = (uint8_t) (i ^ 0x5a);

  CHECK_EQ (gq_tls12conn_start (l->c), GQ_OK);
  CHECK_EQ (gq_tls12conn_start (l->s), GQ_OK);	/* No-op for a server.  */
  pump (l, chunk);
  CHECK (l->ce.connected && l->se.connected);
  CHECK (gq_tls12conn_is_connected (l->c) && gq_tls12conn_is_connected (l->s));
  if (suite)
    CHECK_EQ (l->ce.info.cipher_suite, suite[0]);

  /* Data in both directions, across record boundaries.  */
  CHECK_EQ (gq_tls12conn_send (l->c, big, sizeof big), GQ_OK);
  CHECK_EQ (gq_tls12conn_send (l->s, back, sizeof back), GQ_OK);
  CHECK_EQ (gq_tls12conn_send (l->c, big, 0), GQ_OK);
  pump (l, chunk);
  CHECK (l->se.app.n == sizeof big && memcmp (l->se.app.p, big, sizeof big) == 0);
  CHECK (l->ce.app.n == sizeof back && memcmp (l->ce.app.p, back, sizeof back) == 0);
  CHECK_EQ (gq_tls12conn_write_seq (l->c), gq_tls12conn_read_seq (l->s));

  /* Exporter agrees.  */
  {
    uint8_t a[32], b[32];

    CHECK_EQ (gq_tls12conn_export (l->c, "EXPORTER-conn", NULL, 0, a, 32), GQ_OK);
    CHECK_EQ (gq_tls12conn_export (l->s, "EXPORTER-conn", NULL, 0, b, 32), GQ_OK);
    CHECK (memcmp (a, b, 32) == 0);
  }

  /* Orderly close from one side closes both.  */
  CHECK_EQ (gq_tls12conn_close (l->c), GQ_OK);
  pump (l, chunk);
  CHECK (l->se.closed == 1 && l->se.close_error == 0);
  CHECK (l->ce.closed == 1 && l->ce.close_error == 0);
  CHECK (gq_tls12conn_is_closed (l->c) && gq_tls12conn_is_closed (l->s));
  CHECK (gq_tls12conn_send (l->c, big, 1) < 0);
  link_free (l);
}

static void
test_resume_conn (void)
{
  gq_ticket_keys *keys;
  struct link *l;
  gq_tls_session sess;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  l = link_new (&fx_ec, NULL, keys, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  gq_tls12conn_start (l->c);
  pump (l, 0);
  CHECK (l->ce.connected && l->se.connected);
  CHECK_EQ (l->ce.tickets, 1);
  CHECK_EQ (l->ce.info.resumed, 0);
  sess = l->ce.session;
  link_free (l);

  l = link_new (&fx_ec, NULL, keys, &sess, NULL, GQ_CLIENT_AUTH_NONE);
  gq_tls12conn_start (l->c);
  pump (l, 7);
  CHECK (l->ce.connected && l->se.connected);
  CHECK_EQ (l->ce.info.resumed, 1);
  CHECK_EQ (l->se.info.resumed, 1);
  CHECK_EQ (gq_tls12conn_send (l->c, (const uint8_t *) "hi", 2), GQ_OK);
  pump (l, 0);
  CHECK (l->se.app.n == 2 && memcmp (l->se.app.p, "hi", 2) == 0);
  link_free (l);
  gq_ticket_keys_free (keys);
}

static void
test_client_auth_conn (void)
{
  struct link *l;

  l = link_new (&fx_rsa, NULL, NULL, NULL, &fx_cli_rsa, GQ_CLIENT_AUTH_REQUIRED);
  gq_tls12conn_start (l->c);
  pump (l, 0);
  CHECK (l->ce.connected && l->se.connected);
  CHECK_EQ (l->se.info.client_auth_sent, 1);
  link_free (l);

  /* Required and absent: the server sends an alert and both end.  */
  l = link_new (&fx_ec, NULL, NULL, NULL, NULL, GQ_CLIENT_AUTH_REQUIRED);
  gq_tls12conn_start (l->c);
  pump (l, 0);
  CHECK (!l->se.connected && l->se.closed == 1);
  CHECK (l->se.close_error < 0 && l->se.close_alert == GQ_ALERT_HANDSHAKE_FAILURE);
  CHECK (l->ce.closed == 1 && l->ce.close_alert == GQ_ALERT_HANDSHAKE_FAILURE);
  link_free (l);
}

/* Garbage and misuse on the wire.  */
static void
test_wire_errors (void)
{
  struct link *l;
  static const uint8_t junk[] = { 'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P' };
  static const uint8_t ssl3[] = { 22, 3, 0, 0, 5, 1, 0, 0, 1, 0 };
  static const uint8_t app[] = { 23, 3, 3, 0, 1, 0 };
  static const uint8_t alert[] = { 21, 3, 3, 0, 2, 2, 40 };
  static const uint8_t ccs[] = { 20, 3, 3, 0, 1, 1 };

  /* Plain HTTP at a TLS server.  */
  l = link_new (&fx_ec, NULL, NULL, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  CHECK (gq_tls12conn_receive (l->s, junk, sizeof junk) < 0);
  CHECK (l->se.closed == 1);
  CHECK (gq_tls12conn_receive (l->s, junk, 1) < 0);	/* Terminal.  */
  link_free (l);

  /* SSL 3.0.  */
  l = link_new (&fx_ec, NULL, NULL, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  CHECK (gq_tls12conn_receive (l->s, ssl3, sizeof ssl3) < 0);
  CHECK_EQ (l->se.close_alert, GQ_ALERT_PROTOCOL_VERSION);
  /* An alert record was sent back.  */
  CHECK (l->se.wire.n == 7 && l->se.wire.p[0] == 21 && l->se.wire.p[6] == 70);
  link_free (l);

  /* Application data before the handshake completes.  */
  l = link_new (&fx_ec, NULL, NULL, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  CHECK (gq_tls12conn_receive (l->s, app, sizeof app) < 0);
  link_free (l);

  /* Peer alerts end the connection with its code.  */
  l = link_new (&fx_ec, NULL, NULL, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  gq_tls12conn_start (l->c);
  pump (l, 0);
  CHECK (l->ce.connected);
  CHECK (gq_tls12conn_receive (l->c, alert, sizeof alert) < 0
         || l->ce.closed);
  link_free (l);

  /* A stray ChangeCipherSpec at the start of a connection.  */
  l = link_new (&fx_ec, NULL, NULL, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  CHECK (gq_tls12conn_receive (l->s, ccs, sizeof ccs) < 0);
  link_free (l);

  /* Send before connected is refused.  */
  l = link_new (&fx_ec, NULL, NULL, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  CHECK_EQ (gq_tls12conn_send (l->c, (const uint8_t *) "x", 1), GQ_ERR_INVAL);
  link_free (l);

  /* Bit flips in protected application data are fatal (bad_record_mac).  */
  l = link_new (&fx_ec, s_ecdsa128, NULL, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  gq_tls12conn_start (l->c);
  pump (l, 0);
  CHECK_EQ (gq_tls12conn_send (l->c, (const uint8_t *) "secret", 6), GQ_OK);
  l->ce.wire.p[l->ce.wire.n - 3] ^= 1;
  pump (l, 0);
  CHECK (l->se.closed == 1 && l->se.close_alert == GQ_ALERT_BAD_RECORD_MAC);
  CHECK (l->se.app.n == 0);
  link_free (l);
}

/* AES-GCM cannot be used past its record limit and there is no rekeying:
   the connection says close_notify and closes.  The limit is lowered
   through rekey_records to keep the test short.  */
static void
test_record_limit (void)
{
  struct link *l = link_new (&fx_ec, s_ecdsa128, NULL, NULL, NULL,
                             GQ_CLIENT_AUTH_NONE);
  uint8_t b[100] = { 0 };
  int i, r = GQ_OK;

  l->cev.rekey_records = 20;
  gq_tls12conn_free (l->c);
  CHECK_EQ (gq_tls12conn_client_new (&l->c, &l->cc, &l->cev), GQ_OK);
  gq_tls12conn_start (l->c);
  pump (l, 0);
  CHECK (l->ce.connected && l->se.connected);
  for (i = 0; i < 100 && r == GQ_OK; i++)
    r = gq_tls12conn_send (l->c, b, sizeof b);
  CHECK_EQ (r, GQ_ERR_RANGE);
  CHECK (i > 10 && i < 30);
  CHECK (l->ce.closed == 1 && l->ce.close_error == GQ_ERR_RANGE);
  CHECK (gq_tls12conn_is_closed (l->c));
  /* The peer received everything sent, then an orderly close.  */
  pump (l, 0);
  CHECK_EQ (l->se.app.n, (size_t) (i - 1) * sizeof b);
  CHECK (l->se.closed == 1 && l->se.close_error == 0);
  link_free (l);

  /* ChaCha20-Poly1305 is not limited that way.  */
  l = link_new (&fx_ec, s_ecdsachacha, NULL, NULL, NULL, GQ_CLIENT_AUTH_NONE);
  l->cev.rekey_records = 20;
  gq_tls12conn_free (l->c);
  CHECK_EQ (gq_tls12conn_client_new (&l->c, &l->cc, &l->cev), GQ_OK);
  gq_tls12conn_start (l->c);
  pump (l, 0);
  r = GQ_OK;
  for (i = 0; i < 100 && r == GQ_OK; i++)
    r = gq_tls12conn_send (l->c, b, sizeof b);
  CHECK_EQ (r, GQ_OK);
  link_free (l);
}

int
main (void)
{
  gq_crypto_init ();
  fx_setup ();
  test_data (&fx_ec, s_ecdsa128, 0);
  test_data (&fx_ec, s_ecdsa128, 1);
  test_data (&fx_ec, s_ecdsachacha, 13);
  test_data (&fx_rsa, s_rsa256, 0);
  test_data (&fx_ec, NULL, 5000);
  test_resume_conn ();
  test_client_auth_conn ();
  test_wire_errors ();
  test_record_limit ();
  TST_DONE ();
}

#endif
