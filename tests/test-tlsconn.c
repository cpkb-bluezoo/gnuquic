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
#include <gnuquic/record.h>
#include <gnuquic/tlsconn.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-x509.h"
#include "tst-tlspeer.h"

/* ---- Fixtures (one CA and server certificate) ---- */

static struct tst_cert ca, leaf;
static gq_privkey *server_key;
static uint8_t leaf_der[2048];
static size_t leaf_len;
static gq_trust *trust;

static void
setup_fixtures (void)
{
  gnutls_datum_t pem, d;

  CHECK_EQ (tst_make_cert (&ca, TST_ECDSA256, "Test CA", NULL, NULL, -3600,
                           86400, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&leaf, TST_ECDSA256, "example.test", "example.test",
                           &ca, -3600, 86400, GNUTLS_DIG_SHA256), 0);
  gnutls_x509_crt_export2 (leaf.crt, GNUTLS_X509_FMT_DER, &d);
  leaf_len = d.size;
  memcpy (leaf_der, d.data, d.size);
  gnutls_free (d.data);
  gnutls_x509_privkey_export2_pkcs8 (leaf.key, GNUTLS_X509_FMT_PEM, NULL,
                                     GNUTLS_PKCS_PLAIN, &pem);
  CHECK_EQ (gq_privkey_from_pem (&server_key, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
  CHECK_EQ (gq_trust_new (&trust), GQ_OK);
  gnutls_x509_crt_export2 (ca.crt, GNUTLS_X509_FMT_PEM, &pem);
  CHECK_EQ (gq_trust_add_pem (trust, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
}

/* ---- A growable byte string ---- */

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

/* ---- Events from the connection under test ---- */

struct ev
{
  struct bytes wire;		/* What the client wrote.  */
  struct bytes app;		/* Application data it delivered.  */
  int connected;
  int closed, close_error, close_alert;
  int tickets;
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
  (void) i;
  ((struct ev *) u)->connected = 1;
  return 0;
}

static int
ev_ticket (void *u, const gq_tls_ticket *t)
{
  (void) t;
  ((struct ev *) u)->tickets++;
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

/* ---- The peer side: a record layer plus the scripted server ---- */

struct side
{
  gq_tlsconn *conn;
  struct ev ev;
  gq_tls_config cfg;
  gq_tlsconn_events events;
  struct tst_peer peer;
  gq_record rin, rout;		/* Peer's read and write protection.  */
  struct bytes to_client;	/* Bytes the peer is sending.  */
  /* What the peer decoded from the client.  */
  struct bytes app_in;
  struct bytes hs_in;
  int alerts_in[8][2];
  int n_alerts;
  int rekeys_seen;
};

static int
peer_on_record (void *u, unsigned type, const uint8_t *d, size_t n)
{
  struct side *s = u;

  if (type == GQ_CT_APPLICATION_DATA)
    bytes_add (&s->app_in, d, n);
  else if (type == GQ_CT_ALERT && n == 2 && s->n_alerts < 8)
    {
      s->alerts_in[s->n_alerts][0] = d[0];
      s->alerts_in[s->n_alerts][1] = d[1];
      s->n_alerts++;
    }
  else if (type == GQ_CT_HANDSHAKE)
    {
      /* KeyUpdate: ratchet the client's sending secret, and follow it.  */
      if (n == 5 && d[0] == GQ_HS_KEY_UPDATE)
        {
          uint8_t next[48];

          gq_traffic_secret_update (s->peer.hash, s->peer.cas, next);
          memcpy (s->peer.cas, next, s->peer.hlen);
          CHECK_EQ (gq_record_set_keys (&s->rin, GQ_DIR_READ, s->peer.aead,
                                        s->peer.cas, s->peer.hlen), GQ_OK);
          s->rekeys_seen++;
        }
      else
        bytes_add (&s->hs_in, d, n);
    }
  return 0;
}

/* Take everything the client wrote and decode it with the peer's reader.  */
static int
peer_read_client (struct side *s)
{
  uint8_t *copy;
  uint8_t *p;
  size_t l = s->ev.wire.n;
  int r;

  if (l == 0)
    return GQ_OK;
  copy = malloc (l);
  memcpy (copy, s->ev.wire.p, l);
  s->ev.wire.n = 0;
  p = copy;
  r = gq_record_receive (&s->rin, &p, &l, peer_on_record, s);
  CHECK (l == 0 || r == GQ_NEED_MORE);
  free (copy);
  return r;
}

static void
peer_write (struct side *s, unsigned type, const uint8_t *d, size_t n)
{
  uint8_t out[GQ_REC_MAX_RECORD];
  size_t k;

  while (n > 0 || type == GQ_CT_APPLICATION_DATA)
    {
      size_t c = n < GQ_REC_MAX_PLAINTEXT ? n : GQ_REC_MAX_PLAINTEXT;

      CHECK_EQ (gq_record_protect (&s->rout, type, d, c, 0, out, sizeof out,
                                   &k), GQ_OK);
      bytes_add (&s->to_client, out, k);
      d += c;
      n -= c;
      if (n == 0)
        break;
    }
}

/* Deliver the peer's pending bytes to the client in CHUNK-byte pieces.  */
static int
deliver (struct side *s, size_t chunk)
{
  size_t pos = 0;
  int r = GQ_OK;

  while (pos < s->to_client.n && r == GQ_OK)
    {
      size_t k = s->to_client.n - pos;

      if (chunk && k > chunk)
        k = chunk;
      r = gq_tlsconn_receive (s->conn, s->to_client.p + pos, k);
      pos += k;
    }
  s->to_client.n = 0;
  return r;
}

static struct side *
side_new (void)
{
  struct side *s = calloc (1, sizeof *s);

  s->cfg.server_name = "example.test";
  s->cfg.trust = trust;
  s->events.user = &s->ev;
  s->events.write = ev_write;
  s->events.data = ev_data;
  s->events.connected = ev_connected;
  s->events.ticket = ev_ticket;
  s->events.closed = ev_closed;
  s->peer.key = server_key;
  s->peer.chain[0] = (gq_slice) { leaf_der, leaf_len };
  s->peer.n_chain = 1;
  gq_record_init (&s->rin);
  gq_record_init (&s->rout);
  gq_record_allow_ccs (&s->rin, 1);
  s->ev.close_alert = -2;
  return s;
}

static void
side_free (struct side *s)
{
  gq_tlsconn_free (s->conn);
  if (s->peer.tr)
    gq_transcript_free (s->peer.tr);
  free (s->ev.wire.p);
  free (s->ev.app.p);
  free (s->to_client.p);
  free (s->app_in.p);
  free (s->hs_in.p);
  free (s);
}

/* Run the handshake.  RECORD_STYLE selects how the server flight is cut
   into records (0: one record for the whole flight, 1: one per message,
   2: at most 50 bytes per record).  */
static void
handshake (struct side *s, size_t chunk, int record_style)
{
  struct flight init, hs;
  static const uint8_t ccs = 1;
  int i;

  CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
  CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK (s->hs_in.n > 4);
  CHECK_EQ (peer_handle_ch (&s->peer, s->hs_in.p, s->hs_in.n, &init, &hs),
            GQ_OK);
  s->hs_in.n = 0;

  /* ServerHello in the clear, compatibility CCS, then protected data.  */
  peer_write (s, GQ_CT_HANDSHAKE, init.data, init.used);
  peer_write (s, GQ_CT_CHANGE_CIPHER_SPEC, &ccs, 1);
  CHECK_EQ (gq_record_set_keys (&s->rout, GQ_DIR_WRITE, s->peer.aead,
                                s->peer.shs, s->peer.hlen), GQ_OK);
  CHECK_EQ (gq_record_set_keys (&s->rin, GQ_DIR_READ, s->peer.aead,
                                s->peer.chs, s->peer.hlen), GQ_OK);
  if (record_style == 0)
    peer_write (s, GQ_CT_HANDSHAKE, hs.data, hs.used);
  else if (record_style == 1)
    for (i = 0; i < hs.n; i++)
      peer_write (s, GQ_CT_HANDSHAKE, hs.data + hs.off[i], hs.len[i]);
  else
    {
      size_t pos;

      for (pos = 0; pos < hs.used; pos += 50)
        peer_write (s, GQ_CT_HANDSHAKE, hs.data + pos,
                    hs.used - pos < 50 ? hs.used - pos : 50);
    }
  CHECK_EQ (deliver (s, chunk), GQ_OK);
  CHECK (gq_tlsconn_is_connected (s->conn));
  CHECK (s->ev.connected);

  /* The client's Finished arrives after a CCS, encrypted; the peer checks
     it and switches to application keys.  */
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK_EQ (s->hs_in.n, 36);
  CHECK_EQ (peer_handle_client_flight (&s->peer, s->hs_in.p, s->hs_in.n),
            GQ_OK);
  s->hs_in.n = 0;
  CHECK_EQ (gq_record_set_keys (&s->rout, GQ_DIR_WRITE, s->peer.aead,
                                s->peer.sas, s->peer.hlen), GQ_OK);
  CHECK_EQ (gq_record_set_keys (&s->rin, GQ_DIR_READ, s->peer.aead,
                                s->peer.cas, s->peer.hlen), GQ_OK);
  gq_record_allow_ccs (&s->rin, 0);
}

static void
fill (uint8_t *b, size_t n, unsigned seed)
{
  size_t i;

  for (i = 0; i < n; i++)
    b[i] = (uint8_t) (seed + i * 31 + (i >> 8));
}

static void
test_handshake_and_data (size_t chunk, int style)
{
  struct side *s = side_new ();
  uint8_t msg[300000], back[300000];
  size_t n = 250000;

  handshake (s, chunk, style);

  /* Client to peer: small then large (many records).  */
  CHECK_EQ (gq_tlsconn_send (s->conn, (const uint8_t *) "hello", 5), GQ_OK);
  fill (msg, n, 1);
  CHECK_EQ (gq_tlsconn_send (s->conn, msg, n), GQ_OK);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK_EQ (s->app_in.n, 5 + n);
  CHECK (memcmp (s->app_in.p, "hello", 5) == 0);
  CHECK (memcmp (s->app_in.p + 5, msg, n) == 0);

  /* Peer to client.  */
  fill (back, n, 9);
  peer_write (s, GQ_CT_APPLICATION_DATA, back, n);
  CHECK_EQ (deliver (s, chunk), GQ_OK);
  CHECK_EQ (s->ev.app.n, n);
  CHECK (memcmp (s->ev.app.p, back, n) == 0);
  CHECK (gq_tlsconn_read_seq (s->conn) > 10);

  /* A session ticket after the handshake.  */
  {
    static const uint8_t nonce[1] = { 1 }, ticket[4] = { 9, 8, 7, 6 };
    uint8_t buf[64];
    gq_wbuf w;

    gq_wbuf_init (&w, buf, sizeof buf);
    gq_build_new_session_ticket (&w, 100, 5, (gq_slice) { nonce, 1 },
                                 (gq_slice) { ticket, 4 }, NULL, 0);
    peer_write (s, GQ_CT_HANDSHAKE, buf, w.len);
    /* The peer's resumption secret is derived from the client Finished.  */
  }
  CHECK_EQ (deliver (s, chunk), GQ_OK);
  CHECK_EQ (s->ev.tickets, 1);

  /* Orderly shutdown: we send close_notify, peer answers, we are closed.  */
  CHECK_EQ (gq_tlsconn_close (s->conn), GQ_OK);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK (s->n_alerts == 1 && s->alerts_in[0][0] == 1 && s->alerts_in[0][1] == 0);
  CHECK_EQ (s->ev.closed, 0);
  {
    static const uint8_t cn[2] = { 1, 0 };

    peer_write (s, GQ_CT_ALERT, cn, 2);
  }
  CHECK_EQ (deliver (s, chunk), GQ_OK);
  CHECK_EQ (s->ev.closed, 1);
  CHECK_EQ (s->ev.close_error, 0);
  CHECK (gq_tlsconn_is_closed (s->conn));
  CHECK_EQ (gq_tlsconn_send (s->conn, msg, 1), GQ_ERR_INVAL);
  side_free (s);
}

static void
test_rekey_by_count (void)
{
  struct side *s = side_new ();
  uint8_t chunk[100];
  int i;
  size_t total = 0;

  s->events.rekey_records = 4;
  handshake (s, 0, 1);
  for (i = 0; i < 30; i++)
    {
      fill (chunk, sizeof chunk, (unsigned) i);
      CHECK_EQ (gq_tlsconn_send (s->conn, chunk, sizeof chunk), GQ_OK);
      total += sizeof chunk;
      CHECK_EQ (peer_read_client (s), GQ_OK);
      CHECK_EQ (s->app_in.n, total);
      CHECK (memcmp (s->app_in.p + total - sizeof chunk, chunk,
                     sizeof chunk) == 0);
    }
  /* Every four records the connection updated its keys, and the peer,
     following the ratchet, kept decrypting.  */
  CHECK (s->rekeys_seen >= 5);
  CHECK (gq_tlsconn_write_seq (s->conn) < 8);

  /* Explicit update asking the peer to follow: it is the peer that
     rekeys its own sending keys in response.  */
  CHECK_EQ (gq_tlsconn_key_update (s->conn, 1), GQ_OK);
  side_free (s);
}

static void
test_failures (void)
{
  struct side *s;
  uint8_t junk[64];
  int r;

  /* Tampered record after the handshake: bad_record_mac alert sent, and
     the connection closes with an error.  */
  s = side_new ();
  handshake (s, 0, 1);
  peer_write (s, GQ_CT_APPLICATION_DATA, (const uint8_t *) "data", 4);
  s->to_client.p[s->to_client.n - 3] ^= 1;
  r = deliver (s, 0);
  CHECK_EQ (r, GQ_ERR_CRYPTO);
  CHECK (s->ev.closed == 1 && s->ev.close_alert == 20);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK (s->n_alerts == 1 && s->alerts_in[0][0] == 2
         && s->alerts_in[0][1] == 20);
  side_free (s);

  /* A fatal alert from the peer.  */
  s = side_new ();
  handshake (s, 0, 1);
  {
    static const uint8_t al[2] = { 2, 40 };

    peer_write (s, GQ_CT_ALERT, al, 2);
  }
  deliver (s, 0);
  CHECK (s->ev.closed == 1 && s->ev.close_error == GQ_ERR_PROTOCOL
         && s->ev.close_alert == 40);
  side_free (s);

  /* The peer closes first: we answer close_notify.  */
  s = side_new ();
  handshake (s, 1, 1);
  {
    static const uint8_t cn[2] = { 1, 0 };

    peer_write (s, GQ_CT_ALERT, cn, 2);
  }
  CHECK_EQ (deliver (s, 1), GQ_OK);
  CHECK (s->ev.closed == 1 && s->ev.close_error == 0);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK (s->n_alerts == 1 && s->alerts_in[0][1] == 0);
  side_free (s);

  /* Garbage instead of TLS: unexpected_message.  */
  s = side_new ();
  CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
  CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
  memcpy (junk, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
  r = gq_tlsconn_receive (s->conn, junk, 28);
  CHECK_EQ (r, GQ_ERR_PROTOCOL);
  CHECK (s->ev.closed == 1 && s->ev.close_alert == 10);
  side_free (s);

  /* Application data before the handshake is finished.  */
  s = side_new ();
  CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
  CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
  {
    static const uint8_t bad[6] = { 23, 3, 3, 0, 1, 9 };

    r = gq_tlsconn_receive (s->conn, bad, 6);
    CHECK (r != GQ_OK);
  }
  side_free (s);

  /* A bad server Finished: the engine's alert goes out under the
     handshake keys.  */
  s = side_new ();
  {
    struct flight init, hs;
    static const uint8_t ccs = 1;

    CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
    CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
    CHECK_EQ (peer_read_client (s), GQ_OK);
    CHECK_EQ (peer_handle_ch (&s->peer, s->hs_in.p, s->hs_in.n, &init, &hs),
              GQ_OK);
    s->hs_in.n = 0;
    hs.data[hs.off[3] + hs.len[3] - 1] ^= 1;	/* Corrupt Finished.  */
    peer_write (s, GQ_CT_HANDSHAKE, init.data, init.used);
    peer_write (s, GQ_CT_CHANGE_CIPHER_SPEC, &ccs, 1);
    gq_record_set_keys (&s->rout, GQ_DIR_WRITE, s->peer.aead, s->peer.shs,
                        s->peer.hlen);
    gq_record_set_keys (&s->rin, GQ_DIR_READ, s->peer.aead, s->peer.chs,
                        s->peer.hlen);
    peer_write (s, GQ_CT_HANDSHAKE, hs.data, hs.used);
    r = deliver (s, 0);
    CHECK_EQ (r, GQ_ERR_CRYPTO);
    CHECK (s->ev.closed == 1 && s->ev.close_alert == 51);
    CHECK_EQ (peer_read_client (s), GQ_OK);
    CHECK (s->n_alerts == 1 && s->alerts_in[0][1] == 51);
  }
  side_free (s);

  /* QUIC configuration is not for stream use.  */
  {
    gq_tlsconn *c;
    gq_tls_config cfg;
    struct ev e;
    gq_tlsconn_events ev;

    memset (&cfg, 0, sizeof cfg);
    memset (&e, 0, sizeof e);
    memset (&ev, 0, sizeof ev);
    cfg.trust = trust;
    cfg.quic = 1;
    ev.user = &e;
    ev.write = ev_write;
    ev.data = ev_data;
    CHECK_EQ (gq_tlsconn_client_new (&c, &cfg, &ev), GQ_ERR_INVAL);
  }
}

int
main (void)
{
  setup_fixtures ();
  test_handshake_and_data (0, 0);
  test_handshake_and_data (1, 1);
  test_handshake_and_data (13, 2);
  test_rekey_by_count ();
  test_failures ();
  TST_DONE ();
}

#endif
