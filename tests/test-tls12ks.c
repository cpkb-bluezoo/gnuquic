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

/* TLS 1.2 key schedule: the PRF against the widely used SHA-256 and
   SHA-384 test vectors, and the derived structures against the PRF.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/tls12ks.h>

#include "tst-util.h"

static void
test_prf (void)
{
  uint8_t s[32], seed[32], out[148];
  size_t sl, dl;

  sl = tst_unhex ("9bbe436ba940f017b17652849a71db35", s, sizeof s);
  dl = tst_unhex ("a0ba9f936cda311827a6f796ffd5198c", seed, sizeof seed);
  CHECK_EQ (gq_tls12_prf (GQ_HASH_SHA256, s, sl, "test label", seed, dl, out,
                          100), GQ_OK);
  CHECK (tst_eq_hex (out, 100,
    "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a"
    "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab"
    "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701"
    "87347b66"));

  sl = tst_unhex ("b80b733d6ceefcdc71566ea48e5567df", s, sizeof s);
  dl = tst_unhex ("cd665cf6a8447dd6ff8b27555edb7465", seed, sizeof seed);
  CHECK_EQ (gq_tls12_prf (GQ_HASH_SHA384, s, sl, "test label", seed, dl, out,
                          148), GQ_OK);
  CHECK (tst_eq_hex (out, 148,
    "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd"
    "e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd"
    "8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425"
    "9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6"
    "91c8f3a26854308d5eaa3be85e0990703d73e56f"));

  /* Output length is a prefix property.  */
  {
    uint8_t a[13], b[100];

    sl = tst_unhex ("9bbe436ba940f017b17652849a71db35", s, sizeof s);
    dl = tst_unhex ("a0ba9f936cda311827a6f796ffd5198c", seed, sizeof seed);
    CHECK_EQ (gq_tls12_prf (GQ_HASH_SHA256, s, sl, "test label", seed, dl, a,
                            sizeof a), GQ_OK);
    CHECK_EQ (gq_tls12_prf (GQ_HASH_SHA256, s, sl, "test label", seed, dl, b,
                            sizeof b), GQ_OK);
    CHECK (memcmp (a, b, sizeof a) == 0);
  }
  CHECK_EQ (gq_tls12_prf (GQ_HASH_SHA256, s, sl, "x", seed, dl, out, 1),
            GQ_OK);
  CHECK_EQ (gq_tls12_prf ((enum gq_hash) 99, s, sl, "x", seed, dl, out, 1),
            GQ_ERR_INVAL);
}

static void
test_suites (void)
{
  enum gq_aead a;
  enum gq_hash h;
  size_t n, i;
  const uint16_t *l = gq_policy_default_suites (GQ_TLS_1_2, &n);

  /* Every policy suite has parameters, and only they do.  */
  for (i = 0; i < n; i++)
    CHECK (gq_tls12_suite_params (l[i], &a, &h));
  CHECK (!gq_tls12_suite_params (0xc013, &a, &h));
  CHECK (!gq_tls12_suite_params (GQ_TLS_AES_128_GCM_SHA256, &a, &h));
  CHECK (gq_tls12_suite_params (GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, &a, &h)
         && a == GQ_AEAD_AES_256_GCM && h == GQ_HASH_SHA384);
  CHECK (gq_tls12_suite_params (GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, &a, &h)
         && a == GQ_AEAD_CHACHA20_POLY1305 && h == GQ_HASH_SHA256);
  CHECK (gq_tls12_suite_is_rsa (GQ_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305));
  CHECK (!gq_tls12_suite_is_rsa (GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
}

static void
test_derivation (void)
{
  uint8_t pms[32], sh[32], master[48], m2[48], sr[32], cr[32], v[12], v2[12];
  uint8_t seed[64], block[88], e1[16], e2[16], e3[16];
  gq_tls12_keys k;
  size_t i;

  for (i = 0; i < 32; i++)
    {
      pms[i] = (uint8_t) i;
      sh[i] = (uint8_t) (0x40 + i);
      sr[i] = (uint8_t) (0x80 + i);
      cr[i] = (uint8_t) (0xc0 + i);
    }
  CHECK_EQ (gq_tls12_master_secret (GQ_HASH_SHA256, pms, 32, sh, master), GQ_OK);
  /* It is the PRF under the RFC 7627 label, and depends on the hash.  */
  CHECK_EQ (gq_tls12_prf (GQ_HASH_SHA256, pms, 32, "extended master secret",
                          sh, 32, m2, 48), GQ_OK);
  CHECK (memcmp (master, m2, 48) == 0);
  sh[5] ^= 1;
  CHECK_EQ (gq_tls12_master_secret (GQ_HASH_SHA256, pms, 32, sh, m2), GQ_OK);
  CHECK (memcmp (master, m2, 48) != 0);

  /* Key block: server random first (RFC 5246 section 6.3).  */
  memcpy (seed, sr, 32);
  memcpy (seed + 32, cr, 32);
  CHECK_EQ (gq_tls12_key_block (GQ_HASH_SHA256, GQ_AEAD_AES_128_GCM, master,
                                sr, cr, &k), GQ_OK);
  CHECK_EQ (gq_tls12_prf (GQ_HASH_SHA256, master, 48, "key expansion", seed,
                          64, block, 40), GQ_OK);
  CHECK (k.key_len == 16 && k.iv_len == 4);
  CHECK (memcmp (k.client_key, block, 16) == 0);
  CHECK (memcmp (k.server_key, block + 16, 16) == 0);
  CHECK (memcmp (k.client_iv, block + 32, 4) == 0);
  CHECK (memcmp (k.server_iv, block + 36, 4) == 0);
  CHECK_EQ (gq_tls12_key_block (GQ_HASH_SHA384, GQ_AEAD_AES_256_GCM, master,
                                sr, cr, &k), GQ_OK);
  CHECK (k.key_len == 32 && k.iv_len == 4);
  CHECK_EQ (gq_tls12_key_block (GQ_HASH_SHA256, GQ_AEAD_CHACHA20_POLY1305,
                                master, sr, cr, &k), GQ_OK);
  CHECK (k.key_len == 32 && k.iv_len == 12);
  CHECK_EQ (gq_tls12_prf (GQ_HASH_SHA256, master, 48, "key expansion", seed,
                          64, block, 88), GQ_OK);
  CHECK (memcmp (k.client_iv, block + 64, 12) == 0);
  CHECK (memcmp (k.server_iv, block + 76, 12) == 0);
  CHECK_EQ (gq_tls12_key_block (GQ_HASH_SHA256, (enum gq_aead) 9, master, sr,
                                cr, &k), GQ_ERR_UNSUPPORTED);

  /* Finished differs by role.  */
  CHECK_EQ (gq_tls12_verify_data (GQ_HASH_SHA256, master, 1, sh, v), GQ_OK);
  CHECK_EQ (gq_tls12_verify_data (GQ_HASH_SHA256, master, 0, sh, v2), GQ_OK);
  CHECK (memcmp (v, v2, 12) != 0);

  /* Exporter: context and no context differ, handshake labels refused.  */
  CHECK_EQ (gq_tls12_exporter (GQ_HASH_SHA256, master, cr, sr, "EXPORTER-test",
                             NULL, 0, e1, 16), GQ_OK);
  CHECK_EQ (gq_tls12_exporter (GQ_HASH_SHA256, master, cr, sr, "EXPORTER-test",
                             (const uint8_t *) "", 0, e2, 16), GQ_OK);
  CHECK_EQ (gq_tls12_exporter (GQ_HASH_SHA256, master, cr, sr, "EXPORTER-test",
                             (const uint8_t *) "x", 1, e3, 16), GQ_OK);
  CHECK (memcmp (e1, e2, 16) != 0 && memcmp (e2, e3, 16) != 0);
  CHECK_EQ (gq_tls12_exporter (GQ_HASH_SHA256, master, cr, sr, "key expansion",
                             NULL, 0, e1, 16), GQ_ERR_INVAL);
}

int
main (void)
{
  test_prf ();
  test_suites ();
  test_derivation ();
  TST_DONE ();
}
