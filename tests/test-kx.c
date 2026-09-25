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
#include <gnuquic/policy.h>
#include <gnuquic/kx.h>

#include "tst-util.h"

static const unsigned all_groups[] = {
  GQ_GROUP_X25519, GQ_GROUP_SECP256R1, GQ_GROUP_SECP384R1,
  GQ_GROUP_X25519_MLKEM768, GQ_GROUP_SECP256R1_MLKEM768,
  GQ_GROUP_SECP384R1_MLKEM1024
};

/* Expected: client share, server share, shared secret sizes.  */
static const size_t sizes[][3] = {
  { 32, 32, 32 }, { 65, 65, 32 }, { 97, 97, 48 },
  { 1184 + 32, 1088 + 32, 64 }, { 65 + 1184, 65 + 1088, 64 },
  { 97 + 1568, 97 + 1568, 48 + 32 }
};

static void
test_roundtrip (void)
{
  size_t i;

  for (i = 0; i < sizeof all_groups / sizeof all_groups[0]; i++)
    {
      unsigned g = all_groups[i];
      static gq_kx_key key, key2;
      uint8_t server[GQ_KX_SHARE_MAX], ss[GQ_KX_SHARED_MAX], cs[GQ_KX_SHARED_MAX];
      size_t slen, sslen, cslen;

      CHECK_EQ (gq_kx_client_share_len (g), sizes[i][0]);
      CHECK_EQ (gq_kx_server_share_len (g), sizes[i][1]);
      CHECK_EQ (gq_kx_shared_len (g), sizes[i][2]);

      CHECK_EQ (gq_kx_generate (g, &key), GQ_OK);
      CHECK_EQ (key.share_len, sizes[i][0]);
      CHECK_EQ (gq_kx_respond (g, key.share, key.share_len, server,
                               sizeof server, &slen, ss, sizeof ss, &sslen),
                GQ_OK);
      CHECK_EQ (slen, sizes[i][1]);
      CHECK_EQ (sslen, sizes[i][2]);
      CHECK_EQ (gq_kx_complete (&key, server, slen, cs, sizeof cs, &cslen),
                GQ_OK);
      CHECK_EQ (cslen, sslen);
      CHECK (memcmp (cs, ss, sslen) == 0);

      /* Fresh keys and fresh responses differ.  */
      CHECK_EQ (gq_kx_generate (g, &key2), GQ_OK);
      CHECK (memcmp (key.share, key2.share, key.share_len) != 0);

      /* A response to someone else's share yields a different secret.  */
      {
        uint8_t other[GQ_KX_SHARE_MAX], os[GQ_KX_SHARED_MAX];
        size_t olen, osl, cl2;

        CHECK_EQ (gq_kx_respond (g, key2.share, key2.share_len, other,
                                 sizeof other, &olen, os, sizeof os, &osl),
                  GQ_OK);
        if (gq_kx_complete (&key, other, olen, cs, sizeof cs, &cl2) == GQ_OK)
          CHECK (memcmp (cs, os, osl) != 0 && memcmp (cs, ss, sslen) != 0);
      }
      gq_kx_key_wipe (&key);
      CHECK (key.share_len == 0 && key.secret[0] == 0);
    }
}

/* RFC 7748 section 6.1 test vectors, fed through the client path.  */
static void
test_x25519_kat (void)
{
  static gq_kx_key key;
  uint8_t peer[32], out[GQ_KX_SHARED_MAX];
  size_t n;

  memset (&key, 0, sizeof key);
  key.group = GQ_GROUP_X25519;
  tst_unhex ("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
             key.secret, 32);
  tst_unhex ("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
             peer, 32);
  CHECK_EQ (gq_kx_complete (&key, peer, 32, out, sizeof out, &n), GQ_OK);
  CHECK (tst_eq_hex (out, n,
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));

  tst_unhex ("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
             key.secret, 32);
  tst_unhex ("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
             peer, 32);
  CHECK_EQ (gq_kx_complete (&key, peer, 32, out, sizeof out, &n), GQ_OK);
  CHECK (tst_eq_hex (out, n,
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
}

/* Verify the RFC 10024 ordering of the hybrid halves by recomputing the
   classical half with the plain curve group.  */
static void
check_hybrid_order (unsigned hybrid, unsigned classical, size_t ec_pub,
                    size_t ec_ss, size_t pq_ct, int pq_first)
{
  static gq_kx_key key, plain;
  uint8_t server[GQ_KX_SHARE_MAX], ss[GQ_KX_SHARED_MAX], want[GQ_KX_SHARED_MAX];
  size_t slen, sslen, wlen;
  const uint8_t *ec_share = pq_first ? server + pq_ct : server;
  const uint8_t *ec_part = pq_first ? ss + 32 : ss;

  CHECK_EQ (gq_kx_generate (hybrid, &key), GQ_OK);
  CHECK_EQ (gq_kx_respond (hybrid, key.share, key.share_len, server,
                           sizeof server, &slen, ss, sizeof ss, &sslen),
            GQ_OK);

  /* The classical scalar sits first in the secret buffer.  */
  memset (&plain, 0, sizeof plain);
  plain.group = (uint16_t) classical;
  memcpy (plain.secret, key.secret, 48);
  CHECK_EQ (gq_kx_complete (&plain, ec_share, ec_pub, want, sizeof want,
                            &wlen), GQ_OK);
  CHECK_EQ (wlen, ec_ss);
  CHECK (memcmp (ec_part, want, ec_ss) == 0);

  /* And the classical public value is at the documented end of the share.  */
  CHECK_EQ (slen, ec_pub + pq_ct);
}

static void
test_hybrid_order (void)
{
  check_hybrid_order (GQ_GROUP_X25519_MLKEM768, GQ_GROUP_X25519, 32, 32,
                      1088, 1);
  check_hybrid_order (GQ_GROUP_SECP256R1_MLKEM768, GQ_GROUP_SECP256R1, 65,
                      32, 1088, 0);
  check_hybrid_order (GQ_GROUP_SECP384R1_MLKEM1024, GQ_GROUP_SECP384R1, 97,
                      48, 1568, 0);
}

static void
test_errors (void)
{
  static gq_kx_key key;
  uint8_t share[GQ_KX_SHARE_MAX], server[GQ_KX_SHARE_MAX], ss[GQ_KX_SHARED_MAX];
  size_t n, m;

  /* Groups outside the policy list.  */
  CHECK_EQ (gq_kx_generate (0x0019, &key), GQ_ERR_UNSUPPORTED);	/* secp521r1 */
  CHECK_EQ (gq_kx_generate (0x0100, &key), GQ_ERR_UNSUPPORTED);	/* ffdhe2048 */
  CHECK_EQ (gq_kx_client_share_len (0x0100), 0);

  /* Wrong share sizes.  */
  memset (share, 1, sizeof share);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_X25519, share, 31, server, sizeof server,
                           &n, ss, sizeof ss, &m), GQ_ERR_ENCODING);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_X25519_MLKEM768, share, 32, server,
                           sizeof server, &n, ss, sizeof ss, &m),
            GQ_ERR_ENCODING);

  /* Low-order X25519 points produce an all-zero secret: refused.  */
  memset (share, 0, 32);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_X25519, share, 32, server, sizeof server,
                           &n, ss, sizeof ss, &m), GQ_ERR_CRYPTO);

  /* Off-curve NIST points are refused.  */
  memset (share, 0, 65);
  share[0] = 4;
  CHECK_EQ (gq_kx_respond (GQ_GROUP_SECP256R1, share, 65, server,
                           sizeof server, &n, ss, sizeof ss, &m),
            GQ_ERR_CRYPTO);
  memset (share, 0, 97);
  share[0] = 4;
  CHECK_EQ (gq_kx_respond (GQ_GROUP_SECP384R1, share, 97, server,
                           sizeof server, &n, ss, sizeof ss, &m),
            GQ_ERR_CRYPTO);

  /* Client side: same checks on the server share, and buffer sizes.  */
  CHECK_EQ (gq_kx_generate (GQ_GROUP_SECP256R1, &key), GQ_OK);
  CHECK_EQ (gq_kx_complete (&key, share, 64, ss, sizeof ss, &m),
            GQ_ERR_ENCODING);
  memset (share, 0, 65);
  share[0] = 4;
  CHECK_EQ (gq_kx_complete (&key, share, 65, ss, sizeof ss, &m),
            GQ_ERR_CRYPTO);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_SECP256R1, key.share, 65, server, 64,
                           &n, ss, sizeof ss, &m), GQ_ERR_BUFSIZE);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_SECP256R1, key.share, 65, server,
                           sizeof server, &n, ss, 31, &m), GQ_ERR_BUFSIZE);
}

int
main (void)
{
  test_roundtrip ();
  test_x25519_kat ();
  test_hybrid_order ();
  test_errors ();
  TST_DONE ();
}
