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

/* QUIC-LB connection IDs (quiclb.h), checked against the load balancer
   test vectors of draft-ietf-quic-load-balancers-21 appendix B, plus the
   boundary behaviours callers depend on.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/quiclb.h>

#include "tst-util.h"

static const uint8_t KEY[GQ_QUICLB_KEY_LEN] =
{
  0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
  0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f
};

static size_t
hex (const char *s, uint8_t *out)
{
  size_t n = 0;
  unsigned v;

  while (sscanf (s + 2 * n, "%2x", &v) == 1)
    {
      out[n++] = (uint8_t) v;
      if (s[2 * n] == 0)
        break;
    }
  return n;
}

/* One row of appendix B: config id, server id, nonce, key (NULL for
   plaintext) and the expected connection ID, all as hex.  Every row uses
   first-octet-encodes-length.  */
static void
vector (unsigned config_id, const char *sid, const char *nonce,
       const uint8_t *key, const char *want)
{
  uint8_t sidb[32], nonceb[32], wantb[32], cid[32], got[32];
  size_t sn = hex (sid, sidb), nn = hex (nonce, nonceb);
  size_t wn = hex (want, wantb), gl = sizeof got;
  gq_quiclb_config cfg;

  CHECK_EQ (gq_quiclb_config_init (&cfg, config_id, sidb, sn, nn, key, 1),
           GQ_OK);
  CHECK_EQ (gq_quiclb_cid_len (&cfg), wn);
  CHECK_EQ (gq_quiclb_encode (&cfg, nonceb, cid, wn), GQ_OK);
  CHECK (memcmp (cid, wantb, wn) == 0);
  CHECK_EQ (gq_quiclb_decode_server_id (&cfg, wantb, wn, got, &gl), GQ_OK);
  CHECK_EQ (gl, sn);
  CHECK (memcmp (got, sidb, sn) == 0);
  CHECK (gq_quiclb_is_own (&cfg, wantb, wn));
}

static void
test_vectors (void)
{
  vector (0, "c4605e", "4504cc4f", NULL, "07c4605e4504cc4f");
  vector (0, "ed793a", "ee080dbf", KEY, "0720b1d07b359d3c");
  vector (1, "ed793a51d49b8f5fab65", "ee080dbf48", KEY,
         "2fcc381bc74cb4fbad2823a3d1f8fed2");
  vector (2, "ed793a51d49b8f5f", "ee080dbf48c0d1e5", KEY,
         "504dd2d05a7b0de9b2b9907afb5ecf8cc3");
  vector (0, "ed793a51d49b8f5fab", "ee080dbf48c0d1e55d", KEY,
         "125779c9cc86beb3a3a4a3ca96fce4bfe0cdbc");
}

static void
test_wrong_config_does_not_decode (void)
{
  gq_quiclb_config cfg;
  uint8_t sid[3] = { 0xed, 0x79, 0x3a };
  uint8_t cid[8], got[8];
  size_t gl = sizeof got;

  CHECK_EQ (gq_quiclb_config_init (&cfg, 0, sid, 3, 4, KEY, 1), GQ_OK);
  memcpy (cid, "\x27\x20\xb1\xd0\x7b\x35\x9d\x3c", 8);	/* Config id 1.  */
  CHECK_EQ (gq_quiclb_decode_server_id (&cfg, cid, 8, got, &gl),
           GQ_ERR_ENCODING);
  memcpy (cid, "\x07\x20\xb1\xd0\x7b\x35\x9d", 7);		/* Short.  */
  gl = sizeof got;
  CHECK_EQ (gq_quiclb_decode_server_id (&cfg, cid, 7, got, &gl),
           GQ_ERR_ENCODING);
  CHECK (!gq_quiclb_is_own (&cfg, cid, 7));
}

static void
test_other_server_id_is_not_own (void)
{
  gq_quiclb_config mine, other;
  uint8_t a[1] = { 0x01 }, b[1] = { 0x02 }, cid[6];

  CHECK_EQ (gq_quiclb_config_init (&mine, 0, a, 1, 4, KEY, 0), GQ_OK);
  CHECK_EQ (gq_quiclb_config_init (&other, 0, b, 1, 4, KEY, 0), GQ_OK);
  CHECK_EQ (gq_quiclb_cid_gen (&other, cid, sizeof cid), GQ_OK);
  CHECK (!gq_quiclb_is_own (&mine, cid, sizeof cid));
  CHECK (gq_quiclb_is_own (&other, cid, sizeof cid));
}

static void
test_generated_ids_self_describe_and_are_unique (void)
{
  gq_quiclb_config cfg;
  uint8_t sid[2] = { 1, 2 };
  uint8_t seen[64][8];
  int n = 0, i, j;
  size_t len;

  CHECK_EQ (gq_quiclb_config_init (&cfg, 3, sid, 2, 6, KEY, 1), GQ_OK);
  len = gq_quiclb_cid_len (&cfg);
  CHECK_EQ (len, (size_t) 9);
  for (i = 0; i < 64; i++)
    {
      uint8_t cid[9], got[8];
      size_t gl = sizeof got;

      CHECK_EQ (gq_quiclb_cid_gen (&cfg, cid, len), GQ_OK);
      CHECK_EQ ((unsigned) (cid[0] >> 5), 3u);
      CHECK_EQ ((size_t) (cid[0] & 0x1f) + 1, len);
      CHECK_EQ (gq_quiclb_decode_server_id (&cfg, cid, len, got, &gl),
               GQ_OK);
      CHECK (memcmp (got, sid, 2) == 0);
      memcpy (seen[n++], cid, len < 8 ? len : 8);
      for (j = 0; j < n - 1; j++)
        CHECK (memcmp (seen[j], seen[n - 1], len < 8 ? len : 8) != 0);
    }
}

static void
test_unkeyed_low_bits_are_random (void)
{
  gq_quiclb_config cfg;
  uint8_t sid[1] = { 0xaa };
  uint8_t a[6], b[6];

  CHECK_EQ (gq_quiclb_config_init (&cfg, 0, sid, 1, 4, NULL, 0), GQ_OK);
  CHECK_EQ (gq_quiclb_cid_len (&cfg), sizeof a);
  CHECK_EQ (gq_quiclb_cid_gen (&cfg, a, sizeof a), GQ_OK);
  CHECK_EQ (gq_quiclb_cid_gen (&cfg, b, sizeof b), GQ_OK);
  CHECK (memcmp (a, b, sizeof a) != 0);
}

static void
test_rejects_bad_parameters (void)
{
  gq_quiclb_config cfg;
  uint8_t sid[1] = { 0xaa };

  CHECK_EQ (gq_quiclb_config_init (&cfg, GQ_QUICLB_MAX_CONFIG_ID + 1, sid, 1,
                                   4, NULL, 0), GQ_ERR_INVAL);
  CHECK_EQ (gq_quiclb_config_init (&cfg, 0, sid, 1, GQ_QUICLB_MIN_NONCE_LEN - 1,
                                   NULL, 0), GQ_ERR_INVAL);
  {
    uint8_t sid3[3] = { 1, 2, 3 };

    CHECK_EQ (gq_quiclb_config_init (&cfg, 0, sid3, 3, 17, NULL, 0),
             GQ_ERR_INVAL);	/* 3 + 17 > 19.  */
  }
  CHECK_EQ (gq_quiclb_config_init (&cfg, 0, NULL, 0, 4, NULL, 0),
           GQ_ERR_INVAL);
}

static void
test_plaintext_length_boundary (void)
{
  /* Section 5.3: server id plus nonce may reach 19 octets exactly, but
     not exceed it.  */
  gq_quiclb_config cfg;
  uint8_t sid[1] = { 1 };

  CHECK_EQ (gq_quiclb_config_init (&cfg, 0, sid, 1, 18, NULL, 1), GQ_OK);
  CHECK_EQ (gq_quiclb_cid_len (&cfg), (size_t) 20);
  CHECK_EQ (gq_quiclb_config_init (&cfg, 0, sid, 1, 19, NULL, 1),
           GQ_ERR_INVAL);
}

int
main (void)
{
  test_vectors ();
  test_wrong_config_does_not_decode ();
  test_other_server_id_is_not_own ();
  test_generated_ids_self_describe_and_are_unique ();
  test_unkeyed_low_bits_are_random ();
  test_rejects_bad_parameters ();
  test_plaintext_length_boundary ();
  TST_DONE ();
}
