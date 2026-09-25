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

#include "tst-util.h"

/* RFC 5869 appendix A.1.  */
static void
test_hkdf_rfc5869 (void)
{
  uint8_t ikm[22], salt[13], info[10], prk[32], okm[42];
  size_t nikm = tst_unhex ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm, sizeof ikm);
  size_t nsalt = tst_unhex ("000102030405060708090a0b0c", salt, sizeof salt);
  size_t ninfo = tst_unhex ("f0f1f2f3f4f5f6f7f8f9", info, sizeof info);

  CHECK_EQ (gq_hkdf_extract (GQ_HASH_SHA256, salt, nsalt, ikm, nikm,
                             prk, sizeof prk), GQ_OK);
  CHECK (tst_eq_hex (prk, sizeof prk,
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
  CHECK_EQ (gq_hkdf_expand (GQ_HASH_SHA256, prk, sizeof prk, info, ninfo,
                            okm, sizeof okm), GQ_OK);
  CHECK (tst_eq_hex (okm, sizeof okm,
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"));

  /* Bounds.  */
  CHECK_EQ (gq_hkdf_expand (GQ_HASH_SHA256, prk, sizeof prk, info, ninfo,
                            okm, 255 * 32 + 1),
            GQ_ERR_INVAL);
}

/* RFC 9001 appendix A.2 and A.5: header protection masks.  */
static void
test_hp_masks (void)
{
  uint8_t hp[32], sample[16], mask[5];

  tst_unhex ("9f50449e04a0e810283a1e9933adedd2", hp, sizeof hp);
  tst_unhex ("d1b1c98dd7689fb8ec11d242b123dc9b", sample, sizeof sample);
  CHECK_EQ (gq_hp_mask (GQ_AEAD_AES_128_GCM, hp, 16, sample, mask), GQ_OK);
  CHECK (tst_eq_hex (mask, 5, "437b9aec36"));

  tst_unhex ("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
             hp, sizeof hp);
  tst_unhex ("5e5cd55c41f69080575d7999c25a5bfb", sample, sizeof sample);
  CHECK_EQ (gq_hp_mask (GQ_AEAD_CHACHA20_POLY1305, hp, 32, sample, mask),
            GQ_OK);
  CHECK (tst_eq_hex (mask, 5, "aefefe7d03"));
}

static void
test_aead (enum gq_aead alg)
{
  uint8_t key[32], nonce[12], aad[13], pt[100], ct[100 + 16], back[100];
  size_t kl = gq_aead_key_size (alg);
  size_t i;

  CHECK (kl == 16 || kl == 32);
  for (i = 0; i < sizeof key; i++)
    key[i] = (uint8_t) i;
  for (i = 0; i < sizeof nonce; i++)
    nonce[i] = (uint8_t) (0xa0 + i);
  for (i = 0; i < sizeof aad; i++)
    aad[i] = (uint8_t) (0x40 + i);
  for (i = 0; i < sizeof pt; i++)
    pt[i] = (uint8_t) (i * 7);

  CHECK_EQ (gq_aead_seal (alg, key, kl, nonce, aad, sizeof aad, pt,
                          sizeof pt, ct, sizeof ct), GQ_OK);
  CHECK (memcmp (ct, pt, sizeof pt) != 0);
  CHECK_EQ (gq_aead_open (alg, key, kl, nonce, aad, sizeof aad, ct,
                          sizeof ct, back, sizeof back), GQ_OK);
  CHECK (memcmp (back, pt, sizeof pt) == 0);

  /* In place.  */
  memcpy (back, pt, sizeof pt);
  CHECK_EQ (gq_aead_seal (alg, key, kl, nonce, aad, sizeof aad, back,
                          sizeof pt, ct, sizeof ct), GQ_OK);

  /* Any single-bit flip in ciphertext, tag or AAD must be rejected and
     must not leak plaintext.  */
  ct[3] ^= 1;
  memset (back, 0x55, sizeof back);
  CHECK_EQ (gq_aead_open (alg, key, kl, nonce, aad, sizeof aad, ct,
                          sizeof ct, back, sizeof back), GQ_ERR_CRYPTO);
  for (i = 0; i < sizeof back; i++)
    CHECK (back[i] == 0);
  ct[3] ^= 1;
  ct[sizeof ct - 1] ^= 0x80;
  CHECK_EQ (gq_aead_open (alg, key, kl, nonce, aad, sizeof aad, ct,
                          sizeof ct, back, sizeof back), GQ_ERR_CRYPTO);
  ct[sizeof ct - 1] ^= 0x80;
  aad[0] ^= 1;
  CHECK_EQ (gq_aead_open (alg, key, kl, nonce, aad, sizeof aad, ct,
                          sizeof ct, back, sizeof back), GQ_ERR_CRYPTO);
  aad[0] ^= 1;

  /* Empty plaintext, no AAD: tag only.  */
  CHECK_EQ (gq_aead_seal (alg, key, kl, nonce, NULL, 0, NULL, 0, ct, 16),
            GQ_OK);
  CHECK_EQ (gq_aead_open (alg, key, kl, nonce, NULL, 0, ct, 16, back, 0),
            GQ_OK);

  /* Wrong key size and short input.  */
  CHECK_EQ (gq_aead_seal (alg, key, kl - 1, nonce, NULL, 0, pt, 1, ct, 17),
            GQ_ERR_INVAL);
  CHECK_EQ (gq_aead_open (alg, key, kl, nonce, NULL, 0, ct, 15, back, 0),
            GQ_ERR_CRYPTO);
}

/* RFC 4231 test case 1: the SHA-384 key schedule has no RFC 8448 trace,
   so pin down its HMAC here.  */
static void
test_hmac_rfc4231 (void)
{
  uint8_t key[20], out[48];

  memset (key, 0x0b, sizeof key);
  CHECK_EQ (gq_hmac (GQ_HASH_SHA256, key, sizeof key, "Hi There", 8, out, 32),
            GQ_OK);
  CHECK (tst_eq_hex (out, 32,
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
  CHECK_EQ (gq_hmac (GQ_HASH_SHA384, key, sizeof key, "Hi There", 8, out, 48),
            GQ_OK);
  CHECK (tst_eq_hex (out, 48,
    "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
    "faea9ea9076ede7f4af152e8b2fa9cb6"));
}

static void
test_misc (void)
{
  uint8_t a[16], b[16], h[32];

  CHECK_EQ (gq_random (a, sizeof a), GQ_OK);
  CHECK_EQ (gq_random (b, sizeof b), GQ_OK);
  CHECK (memcmp (a, b, sizeof a) != 0);
  CHECK (gq_ct_equal (a, a, sizeof a));
  CHECK (!gq_ct_equal (a, b, sizeof a));

  /* SHA-256 of "abc" (FIPS 180-4).  */
  CHECK_EQ (gq_hash_compute (GQ_HASH_SHA256, "abc", 3, h, 32), GQ_OK);
  CHECK (tst_eq_hex (h, 32,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CHECK_EQ (gq_hash_compute (GQ_HASH_SHA256, "abc", 3, h, 31), GQ_ERR_INVAL);
  CHECK_EQ (gq_hash_compute ((enum gq_hash) 99, "abc", 3, h, 32),
            GQ_ERR_UNSUPPORTED);
  CHECK_EQ (gq_aead_seal ((enum gq_aead) 99, a, 16, a, NULL, 0, NULL, 0,
                          b, 16), GQ_ERR_UNSUPPORTED);
}

int
main (void)
{
  CHECK_EQ (gq_crypto_init (), GQ_OK);
  test_hkdf_rfc5869 ();
  test_hp_masks ();
  test_hmac_rfc4231 ();
  test_aead (GQ_AEAD_AES_128_GCM);
  test_aead (GQ_AEAD_AES_256_GCM);
  test_aead (GQ_AEAD_CHACHA20_POLY1305);
  test_misc ();
  TST_DONE ();
}
