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
#include <gnuquic/crypto.h>
#include <gnuquic/tickets.h>

#include "tst-util.h"

static void
fill_state (gq_session_state *s)
{
  memset (s, 0, sizeof *s);
  s->cipher_suite = 0x1302;
  memset (s->psk, 0x42, 48);
  s->psk_len = 48;
  s->created_ms = UINT64_C (1700000000123);
  s->age_add = 0x01020304;
  s->lifetime = 86400;
  s->max_early_data = 16384;
  s->client_authenticated = 1;
  memcpy (s->server_name, "example.test", 12);
  s->server_name_len = 12;
  memcpy (s->alpn, "h3", 2);
  s->alpn_len = 2;
}

static void
test_roundtrip_and_tamper (void)
{
  gq_ticket_keys *k;
  gq_session_state in, out;
  uint8_t t[GQ_TICKET_MAX], copy[GQ_TICKET_MAX], t2[GQ_TICKET_MAX];
  size_t n, n2, i;
  int active = 0;

  CHECK_EQ (gq_ticket_keys_new (&k), GQ_OK);
  fill_state (&in);
  CHECK_EQ (gq_ticket_seal (k, &in, t, sizeof t, &n), GQ_OK);
  CHECK (n < GQ_TICKET_MAX);
  CHECK_EQ (gq_ticket_open (k, t, n, &out, &active), GQ_OK);
  CHECK (active);
  CHECK (memcmp (&in, &out, sizeof in) == 0 || (
         out.cipher_suite == in.cipher_suite && out.psk_len == 48
         && memcmp (out.psk, in.psk, 48) == 0
         && out.created_ms == in.created_ms && out.age_add == in.age_add
         && out.lifetime == in.lifetime && out.max_early_data == in.max_early_data
         && out.client_authenticated && out.server_name_len == 12
         && strcmp (out.server_name, "example.test") == 0 && out.alpn_len == 2
         && memcmp (out.alpn, "h3", 2) == 0));

  /* Two tickets for the same state differ (random nonce).  */
  CHECK_EQ (gq_ticket_seal (k, &in, t2, sizeof t2, &n2), GQ_OK);
  CHECK (n2 == n && memcmp (t, t2, n) != 0);

  /* No byte of a ticket can be changed, and no prefix accepted.  */
  for (i = 0; i < n; i++)
    {
      memcpy (copy, t, n);
      copy[i] ^= 0x01;
      CHECK_EQ (gq_ticket_open (k, copy, n, &out, NULL), GQ_ERR_CRYPTO);
    }
  for (i = 0; i < n; i++)
    CHECK_EQ (gq_ticket_open (k, t, i, &out, NULL), GQ_ERR_CRYPTO);
  CHECK_EQ (gq_ticket_seal (k, &in, t2, 10, &n2), GQ_ERR_BUFSIZE);

  /* A different key ring cannot read it.  */
  {
    gq_ticket_keys *other;

    CHECK_EQ (gq_ticket_keys_new (&other), GQ_OK);
    CHECK_EQ (gq_ticket_open (other, t, n, &out, NULL), GQ_ERR_CRYPTO);
    gq_ticket_keys_free (other);
  }
  gq_ticket_keys_free (k);
}

static void
test_rotation (void)
{
  gq_ticket_keys *k;
  gq_session_state in, out;
  uint8_t t0[GQ_TICKET_MAX], t1[GQ_TICKET_MAX];
  size_t n0, n1;
  int active, i;

  CHECK_EQ (gq_ticket_keys_new (&k), GQ_OK);
  fill_state (&in);
  CHECK_EQ (gq_ticket_seal (k, &in, t0, sizeof t0, &n0), GQ_OK);

  /* After rotation old tickets still open, but no longer under the
     active key; new tickets use the new key.  */
  CHECK_EQ (gq_ticket_keys_rotate (k), GQ_OK);
  CHECK_EQ (gq_ticket_open (k, t0, n0, &out, &active), GQ_OK);
  CHECK (!active);
  CHECK_EQ (gq_ticket_seal (k, &in, t1, sizeof t1, &n1), GQ_OK);
  CHECK_EQ (gq_ticket_open (k, t1, n1, &out, &active), GQ_OK);
  CHECK (active);
  CHECK (memcmp (t0, t1, 16) != 0);		/* Different key names.  */

  /* The ring holds GQ_TICKET_KEYS_MAX keys: the original is pushed out
     after enough rotations, but the newest never is.  */
  for (i = 0; i < GQ_TICKET_KEYS_MAX; i++)
    CHECK_EQ (gq_ticket_keys_rotate (k), GQ_OK);
  CHECK_EQ (gq_ticket_open (k, t0, n0, &out, NULL), GQ_ERR_CRYPTO);
  CHECK_EQ (gq_ticket_seal (k, &in, t1, sizeof t1, &n1), GQ_OK);
  CHECK_EQ (gq_ticket_open (k, t1, n1, &out, &active), GQ_OK);
  CHECK (active);
  gq_ticket_keys_free (k);
}

/* Servers sharing a key read each other's tickets.  */
static void
test_shared_keys (void)
{
  static const uint8_t shared[GQ_TICKET_KEY_LEN] = { 9, 8, 7 };
  gq_ticket_keys *a, *b;
  gq_session_state in, out;
  uint8_t t[GQ_TICKET_MAX];
  size_t n;

  CHECK_EQ (gq_ticket_keys_new (&a), GQ_OK);
  CHECK_EQ (gq_ticket_keys_new (&b), GQ_OK);
  CHECK_EQ (gq_ticket_keys_add (a, shared, 1), GQ_OK);
  CHECK_EQ (gq_ticket_keys_add (b, shared, 0), GQ_OK);	/* Decrypt only.  */
  fill_state (&in);
  CHECK_EQ (gq_ticket_seal (a, &in, t, sizeof t, &n), GQ_OK);
  CHECK_EQ (gq_ticket_open (b, t, n, &out, NULL), GQ_OK);
  /* b still encrypts under its own key, which a cannot read.  */
  CHECK_EQ (gq_ticket_seal (b, &in, t, sizeof t, &n), GQ_OK);
  CHECK_EQ (gq_ticket_open (a, t, n, &out, NULL), GQ_ERR_CRYPTO);
  /* Adding the same key twice is harmless.  */
  CHECK_EQ (gq_ticket_keys_add (a, shared, 1), GQ_OK);
  gq_ticket_keys_free (a);
  gq_ticket_keys_free (b);
}

/* An authentic ticket with a malformed payload is an encoding error, not
   a crash: craft one under a known key.  */
static void
test_malformed_payload (void)
{
  static const uint8_t key[GQ_TICKET_KEY_LEN] = { 1, 2, 3 };
  gq_ticket_keys *k;
  gq_session_state out;
  uint8_t t[16 + 12 + 40 + 16], name[16];
  static const uint8_t bad[5] = { 1, 0x13, 0x01, 0xff, 0 };	/* psk_len 255 */
  uint8_t in[16 + 32];
  uint8_t h[32];

  CHECK_EQ (gq_ticket_keys_new (&k), GQ_OK);
  CHECK_EQ (gq_ticket_keys_add (k, key, 1), GQ_OK);

  /* Recompute the key name the way the ring does.  */
  memcpy (in, "gnuquic ticket:", 16);
  memcpy (in + 16, key, 32);
  CHECK_EQ (gq_hash_compute (GQ_HASH_SHA256, in, sizeof in, h, 32), GQ_OK);
  memcpy (name, h, 16);
  memcpy (t, name, 16);
  memset (t + 16, 7, 12);
  CHECK_EQ (gq_aead_seal (GQ_AEAD_AES_256_GCM, key, 32, t + 16, name, 16, bad,
                          sizeof bad, t + 28, sizeof bad + 16), GQ_OK);
  CHECK_EQ (gq_ticket_open (k, t, 28 + sizeof bad + 16, &out, NULL),
            GQ_ERR_ENCODING);
  gq_ticket_keys_free (k);
}

int
main (void)
{
  CHECK_EQ (gq_crypto_init (), GQ_OK);
  test_roundtrip_and_tamper ();
  test_rotation ();
  test_shared_keys ();
  test_malformed_payload ();
  TST_DONE ();
}
