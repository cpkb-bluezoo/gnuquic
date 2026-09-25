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
#include <gnuquic/kx.h>
#include <gnuquic/transcript.h>
#include <gnuquic/keysched.h>

#include "tst-util.h"
#include "vectors-tls.h"

static size_t
hexbuf (const char *hex, uint8_t *out, size_t cap)
{
  return tst_unhex (hex, out, cap);
}

/* Feed the given messages into a fresh SHA-256 transcript and hash them.  */
static void
th (uint8_t out[32], size_t n, const char *const *msgs)
{
  gq_transcript *t;
  uint8_t buf[1024];
  size_t i, l;

  CHECK_EQ (gq_transcript_new (&t, GQ_HASH_SHA256), GQ_OK);
  for (i = 0; i < n; i++)
    {
      l = hexbuf (msgs[i], buf, sizeof buf);
      CHECK_EQ (gq_transcript_update (t, buf, l), GQ_OK);
    }
  CHECK_EQ (gq_transcript_hash (t, out, 32), GQ_OK);
  gq_transcript_free (t);
}

static void
test_rfc8448_flow (void)
{
  uint8_t shared[GQ_KX_SHARED_MAX], cpriv[32], spub[32];
  size_t sl;
  static gq_kx_key ck;
  gq_ks ks;
  uint8_t h_sh[32], h_cv[32], h_sfin[32], h_cfin[32];
  uint8_t chs[32], shs[32], cap[32], sap[32], exp[32], res[32], out[32];
  uint8_t key[16], iv[12], want[32];
  const char *ch_sh[] = { T8448_CLIENT_HELLO, T8448_SERVER_HELLO };
  const char *to_cv[] = { T8448_CLIENT_HELLO, T8448_SERVER_HELLO,
                          T8448_ENCRYPTED_EXTENSIONS, T8448_CERTIFICATE,
                          T8448_CERTIFICATE_VERIFY };
  const char *to_sfin[] = { T8448_CLIENT_HELLO, T8448_SERVER_HELLO,
                            T8448_ENCRYPTED_EXTENSIONS, T8448_CERTIFICATE,
                            T8448_CERTIFICATE_VERIFY, T8448_SERVER_FINISHED };
  const char *to_cfin[] = { T8448_CLIENT_HELLO, T8448_SERVER_HELLO,
                            T8448_ENCRYPTED_EXTENSIONS, T8448_CERTIFICATE,
                            T8448_CERTIFICATE_VERIFY, T8448_SERVER_FINISHED,
                            T8448_CLIENT_FINISHED };

  /* The X25519 exchange of the trace gives the trace's shared secret.  */
  memset (&ck, 0, sizeof ck);
  ck.group = GQ_GROUP_X25519;
  hexbuf (T8448_CLIENT_X25519_PRIV, cpriv, 32);
  memcpy (ck.secret, cpriv, 32);
  hexbuf (T8448_SERVER_X25519_PUB, spub, 32);
  CHECK_EQ (gq_kx_complete (&ck, spub, 32, shared, sizeof shared, &sl), GQ_OK);
  CHECK (tst_eq_hex (shared, sl, T8448_SHARED_SECRET));

  /* Transcript hashes computed from the messages match the trace.  */
  th (h_sh, 2, ch_sh);
  CHECK (tst_eq_hex (h_sh, 32, T8448_HASH_CH_SH));
  th (h_cv, 5, to_cv);
  th (h_sfin, 6, to_sfin);
  CHECK (tst_eq_hex (h_sfin, 32, T8448_HASH_CH_SFIN));
  th (h_cfin, 7, to_cfin);
  CHECK (tst_eq_hex (h_cfin, 32, T8448_HASH_CH_CFIN));

  CHECK_EQ (gq_ks_early (&ks, GQ_HASH_SHA256, NULL, 0), GQ_OK);
  CHECK (tst_eq_hex (ks.secret, 32, T8448_EARLY_SECRET));

  CHECK_EQ (gq_ks_handshake (&ks, shared, sl), GQ_OK);
  CHECK (tst_eq_hex (ks.secret, 32, T8448_HANDSHAKE_SECRET));
  CHECK_EQ (gq_ks_handshake_traffic (&ks, h_sh, chs, shs), GQ_OK);
  CHECK (tst_eq_hex (chs, 32, T8448_CLIENT_HS_TRAFFIC));
  CHECK (tst_eq_hex (shs, 32, T8448_SERVER_HS_TRAFFIC));

  CHECK_EQ (gq_traffic_keys (GQ_AEAD_AES_128_GCM, shs, key, iv), GQ_OK);
  CHECK (tst_eq_hex (key, 16, T8448_SERVER_HS_KEY));
  CHECK (tst_eq_hex (iv, 12, T8448_SERVER_HS_IV));
  CHECK_EQ (gq_traffic_keys (GQ_AEAD_AES_128_GCM, chs, key, iv), GQ_OK);
  CHECK (tst_eq_hex (key, 16, T8448_CLIENT_HS_KEY));
  CHECK (tst_eq_hex (iv, 12, T8448_CLIENT_HS_IV));

  /* Finished messages.  */
  CHECK_EQ (gq_finished_key (GQ_HASH_SHA256, shs, out), GQ_OK);
  CHECK (tst_eq_hex (out, 32, T8448_SERVER_FINISHED_KEY));
  CHECK_EQ (gq_finished_verify_data (GQ_HASH_SHA256, shs, h_cv, out), GQ_OK);
  CHECK (tst_eq_hex (out, 32, T8448_SERVER_FINISHED_VERIFY));
  CHECK_EQ (gq_finished_key (GQ_HASH_SHA256, chs, out), GQ_OK);
  CHECK (tst_eq_hex (out, 32, T8448_CLIENT_FINISHED_KEY));
  CHECK_EQ (gq_finished_verify_data (GQ_HASH_SHA256, chs, h_sfin, out), GQ_OK);
  CHECK (tst_eq_hex (out, 32, T8448_CLIENT_FINISHED_VERIFY));

  CHECK_EQ (gq_ks_master (&ks), GQ_OK);
  CHECK (tst_eq_hex (ks.secret, 32, T8448_MASTER_SECRET));
  CHECK_EQ (gq_ks_app_traffic (&ks, h_sfin, cap, sap), GQ_OK);
  CHECK (tst_eq_hex (cap, 32, T8448_CLIENT_AP_TRAFFIC));
  CHECK (tst_eq_hex (sap, 32, T8448_SERVER_AP_TRAFFIC));
  CHECK_EQ (gq_ks_exporter_master (&ks, h_sfin, exp), GQ_OK);
  CHECK (tst_eq_hex (exp, 32, T8448_EXPORTER_MASTER));
  CHECK_EQ (gq_traffic_keys (GQ_AEAD_AES_128_GCM, sap, key, iv), GQ_OK);
  CHECK (tst_eq_hex (key, 16, T8448_SERVER_AP_KEY));
  CHECK (tst_eq_hex (iv, 12, T8448_SERVER_AP_IV));
  CHECK_EQ (gq_traffic_keys (GQ_AEAD_AES_128_GCM, cap, key, iv), GQ_OK);
  CHECK (tst_eq_hex (key, 16, T8448_CLIENT_AP_KEY));
  CHECK (tst_eq_hex (iv, 12, T8448_CLIENT_AP_IV));

  CHECK_EQ (gq_ks_resumption_master (&ks, h_cfin, res), GQ_OK);
  CHECK (tst_eq_hex (res, 32, T8448_RESUMPTION_MASTER));
  hexbuf (T8448_TICKET_NONCE, want, 2);
  CHECK_EQ (gq_resumption_psk (GQ_HASH_SHA256, res, want, 2, out), GQ_OK);
  CHECK (tst_eq_hex (out, 32, T8448_RESUMPTION_PSK));

  /* KeyUpdate ratchet: deterministic, and different each step.  */
  {
    uint8_t n1[32], n2[32];

    CHECK_EQ (gq_traffic_secret_update (GQ_HASH_SHA256, cap, n1), GQ_OK);
    CHECK_EQ (gq_traffic_secret_update (GQ_HASH_SHA256, n1, n2), GQ_OK);
    CHECK (memcmp (n1, cap, 32) != 0 && memcmp (n1, n2, 32) != 0);
  }
  gq_ks_wipe (&ks);
  CHECK (ks.secret[0] == 0 && ks.stage == 0);
}

static void
test_stage_discipline (void)
{
  gq_ks ks;
  uint8_t out[48], h[48] = { 0 };

  CHECK_EQ (gq_ks_early (&ks, GQ_HASH_SHA256, NULL, 1), GQ_ERR_INVAL);
  CHECK_EQ (gq_ks_early (&ks, GQ_HASH_SHA256, h, 16), GQ_ERR_INVAL);
  CHECK_EQ (gq_ks_early (&ks, (enum gq_hash) 9, NULL, 0), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (gq_ks_early (&ks, GQ_HASH_SHA256, NULL, 0), GQ_OK);

  /* Stages only go forward.  */
  CHECK_EQ (gq_ks_master (&ks), GQ_ERR_INVAL);
  CHECK_EQ (gq_ks_handshake_traffic (&ks, h, out, NULL), GQ_ERR_INVAL);
  CHECK_EQ (gq_ks_app_traffic (&ks, h, out, NULL), GQ_ERR_INVAL);
  CHECK_EQ (gq_ks_binder_key (&ks, 1, out), GQ_OK);
  CHECK_EQ (gq_ks_client_early_traffic (&ks, h, out), GQ_OK);
  CHECK_EQ (gq_ks_handshake (&ks, NULL, 0), GQ_OK);	/* PSK-only.  */
  CHECK_EQ (gq_ks_binder_key (&ks, 1, out), GQ_ERR_INVAL);
  CHECK_EQ (gq_ks_handshake (&ks, NULL, 0), GQ_ERR_INVAL);
}

/* Binder keys differ by kind, and a PSK changes the whole schedule.  */
static void
test_psk_and_384 (void)
{
  gq_ks a, b;
  uint8_t psk[32], r1[48], r2[48];
  size_t hl;
  int i;

  memset (psk, 0x42, sizeof psk);
  CHECK_EQ (gq_ks_early (&a, GQ_HASH_SHA256, psk, 32), GQ_OK);
  CHECK_EQ (gq_ks_early (&b, GQ_HASH_SHA256, NULL, 0), GQ_OK);
  CHECK (memcmp (a.secret, b.secret, 32) != 0);
  CHECK_EQ (gq_ks_binder_key (&a, 1, r1), GQ_OK);
  CHECK_EQ (gq_ks_binder_key (&a, 0, r2), GQ_OK);
  CHECK (memcmp (r1, r2, 32) != 0);

  /* SHA-384 (TLS_AES_256_GCM_SHA384): 48-byte secrets throughout.  */
  for (i = 0; i < 2; i++)
    {
      gq_ks k;
      uint8_t c[48], s[48], fin[48], hh[48], sh[48], p48[48];

      hl = 48;
      memset (hh, 0x11, hl);
      memset (p48, 0x33, hl);
      CHECK_EQ (gq_ks_early (&k, GQ_HASH_SHA384, i ? p48 : NULL, i ? hl : 0),
                GQ_OK);
      CHECK_EQ (k.hlen, 48);
      CHECK_EQ (gq_ks_handshake (&k, hh, 32), GQ_OK);
      CHECK_EQ (gq_ks_handshake_traffic (&k, hh, c, s), GQ_OK);
      CHECK (memcmp (c, s, hl) != 0);
      CHECK_EQ (gq_finished_verify_data (GQ_HASH_SHA384, s, hh, fin), GQ_OK);
      CHECK_EQ (gq_ks_master (&k), GQ_OK);
      CHECK_EQ (gq_ks_app_traffic (&k, hh, c, sh), GQ_OK);
      CHECK (memcmp (c, sh, hl) != 0);
      {
        uint8_t key[32], iv[12];

        CHECK_EQ (gq_traffic_keys (GQ_AEAD_AES_256_GCM, c, key, iv), GQ_OK);
        CHECK (memcmp (key, c, 32) != 0);
      }
    }
}

static void
test_transcript (void)
{
  gq_transcript *t, *c, *whole;
  uint8_t data[300], h1[32], h2[32], h3[32], ch1[32], want[32], msg[36];
  size_t i;

  for (i = 0; i < sizeof data; i++)
    data[i] = (uint8_t) (i * 7);

  /* Chunking does not change the hash; reading does not disturb it.  */
  CHECK_EQ (gq_transcript_new (&whole, GQ_HASH_SHA256), GQ_OK);
  CHECK_EQ (gq_transcript_update (whole, data, sizeof data), GQ_OK);
  CHECK_EQ (gq_transcript_hash (whole, h1, 32), GQ_OK);
  CHECK_EQ (gq_transcript_new (&t, GQ_HASH_SHA256), GQ_OK);
  for (i = 0; i < sizeof data; i += 13)
    {
      size_t n = sizeof data - i < 13 ? sizeof data - i : 13;

      CHECK_EQ (gq_transcript_update (t, data + i, n), GQ_OK);
      CHECK_EQ (gq_transcript_hash (t, h3, 32), GQ_OK);	/* Peek.  */
    }
  CHECK_EQ (gq_transcript_hash (t, h2, 32), GQ_OK);
  CHECK (memcmp (h1, h2, 32) == 0);

  /* A copy diverges independently.  */
  CHECK_EQ (gq_transcript_copy (t, &c), GQ_OK);
  CHECK_EQ (gq_transcript_update (c, "x", 1), GQ_OK);
  CHECK_EQ (gq_transcript_hash (c, h3, 32), GQ_OK);
  CHECK (memcmp (h3, h1, 32) != 0);
  CHECK_EQ (gq_transcript_hash (t, h2, 32), GQ_OK);
  CHECK (memcmp (h1, h2, 32) == 0);

  /* HelloRetryRequest: message_hash || 00 00 20 || Hash (CH1).  */
  CHECK_EQ (gq_transcript_hello_retry (t), GQ_OK);
  CHECK_EQ (gq_hash_compute (GQ_HASH_SHA256, data, sizeof data, ch1, 32),
            GQ_OK);
  msg[0] = 254; msg[1] = 0; msg[2] = 0; msg[3] = 32;
  memcpy (msg + 4, ch1, 32);
  CHECK_EQ (gq_hash_compute (GQ_HASH_SHA256, msg, 36, want, 32), GQ_OK);
  CHECK_EQ (gq_transcript_hash (t, h2, 32), GQ_OK);
  CHECK (memcmp (h2, want, 32) == 0);

  CHECK_EQ (gq_transcript_hash (t, h2, 31), GQ_ERR_INVAL);
  gq_transcript_free (c);
  CHECK_EQ (gq_transcript_new (&c, (enum gq_hash) 7), GQ_ERR_UNSUPPORTED);
  gq_transcript_free (t);
  gq_transcript_free (whole);
  gq_transcript_free (NULL);
}

int
main (void)
{
  CHECK_EQ (gq_crypto_init (), GQ_OK);
  test_rfc8448_flow ();
  test_stage_discipline ();
  test_psk_and_384 ();
  test_transcript ();
  TST_DONE ();
}
