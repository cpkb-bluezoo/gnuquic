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
#include <gnuquic/packet.h>
#include <gnuquic/protect.h>

#include "tst-util.h"
#include "vectors.h"

static const char *DCID_HEX = "8394c8f03e515708";

static void
check_keys (const gq_packet_keys *k, const char *key, const char *iv,
            const char *hp)
{
  size_t kl = gq_aead_key_size (k->aead);

  CHECK (tst_eq_hex (k->key, kl, key));
  CHECK (tst_eq_hex (k->iv, GQ_AEAD_NONCE_LEN, iv));
  CHECK (tst_eq_hex (k->hp, kl, hp));
}

/* RFC 9001 appendix A.1 and RFC 9369 appendix A.1.  */
static void
test_initial_keys (void)
{
  uint8_t dcid[8], cs[32], ss[32];
  gq_packet_keys c, s;

  tst_unhex (DCID_HEX, dcid, sizeof dcid);

  CHECK_EQ (gq_initial_secrets (GQ_VERSION_1, dcid, 8, cs, ss), GQ_OK);
  CHECK (tst_eq_hex (cs, 32,
    "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"));
  CHECK (tst_eq_hex (ss, 32,
    "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"));
  CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_1, dcid, 8, &c, &s), GQ_OK);
  check_keys (&c, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c",
              "9f50449e04a0e810283a1e9933adedd2");
  check_keys (&s, "cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e",
              "c206b8d9b9f0f37644430b490eeaa314");

  CHECK_EQ (gq_initial_secrets (GQ_VERSION_2, dcid, 8, cs, ss), GQ_OK);
  CHECK (tst_eq_hex (cs, 32,
    "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"));
  CHECK (tst_eq_hex (ss, 32,
    "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1"));
  CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_2, dcid, 8, &c, &s), GQ_OK);
  check_keys (&c, "8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f",
              "45b95e15235d6f45a6b19cbcb0294ba9");
  check_keys (&s, "82db637861d55e1d011f19ea71d5d2a7", "dd13c276499c0249d3310652",
              "edf6d05c83121201b436e16877593c3a");

  CHECK_EQ (gq_packet_keys_initial (0x1a2a3a4a, dcid, 8, &c, &s),
            GQ_ERR_UNSUPPORTED);
}

/* RFC 9001 appendix A.2: the protected client Initial, byte for byte,
   including the header we build ourselves.  */
static void
test_client_initial (void)
{
  uint8_t dcid[8], hdr_expect[64], want[1300], pkt[1300], plain[1162];
  uint8_t crypto[300];
  size_t hdr, hdr_expect_len, cn, want_len, out, off, plen;
  uint64_t pn;
  gq_packet_keys c;

  tst_unhex (DCID_HEX, dcid, sizeof dcid);
  CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_1, dcid, 8, &c, NULL), GQ_OK);

  cn = tst_unhex (V_CLIENT_CRYPTO_FRAME, crypto, sizeof crypto);
  memset (plain, 0, sizeof plain);
  memcpy (plain, crypto, cn);		/* Remainder is PADDING.  */
  hdr_expect_len = tst_unhex (V_CLIENT_UNPROTECTED_HEADER, hdr_expect,
                              sizeof hdr_expect);
  want_len = tst_unhex (V_CLIENT_PROTECTED_PACKET, want, sizeof want);
  CHECK_EQ (want_len, 1200);

  CHECK_EQ (gq_long_header_build (GQ_PKT_INITIAL, GQ_VERSION_1, dcid, 8, NULL,
                                  0, NULL, 0, 2, 4, sizeof plain, pkt,
                                  sizeof pkt, &hdr), GQ_OK);
  CHECK_EQ (hdr, hdr_expect_len);
  CHECK (memcmp (pkt, hdr_expect, hdr) == 0);

  memcpy (pkt + hdr, plain, sizeof plain);
  CHECK_EQ (gq_packet_seal (&c, 2, pkt, hdr - 4, 4, sizeof plain,
                            sizeof pkt, &out), GQ_OK);
  CHECK_EQ (out, want_len);
  CHECK (memcmp (pkt, want, want_len) == 0);

  /* Receive it back.  */
  memcpy (pkt, want, want_len);
  CHECK_EQ (gq_packet_open (&c, 0, 0, pkt, want_len, hdr - 4, &pn, &off,
                            &plen), GQ_OK);
  CHECK (pn == 2);
  CHECK_EQ (off, hdr);
  CHECK_EQ (plen, sizeof plain);
  CHECK (memcmp (pkt + off, plain, plen) == 0);
  CHECK (memcmp (pkt, hdr_expect, hdr) == 0);	/* Header unmasked.  */

  /* Tampering: any changed byte fails authentication.  */
  memcpy (pkt, want, want_len);
  pkt[700] ^= 1;
  CHECK_EQ (gq_packet_open (&c, 0, 0, pkt, want_len, hdr - 4, &pn, &off,
                            &plen), GQ_ERR_CRYPTO);
  memcpy (pkt, want, want_len);
  pkt[10] ^= 1;			/* Inside the DCID: covered by the AAD.  */
  CHECK_EQ (gq_packet_open (&c, 0, 0, pkt, want_len, hdr - 4, &pn, &off,
                            &plen), GQ_ERR_CRYPTO);
  memcpy (pkt, want, want_len);
  CHECK_EQ (gq_packet_open (&c, 0, 0, pkt, want_len - 1, hdr - 4, &pn, &off,
                            &plen), GQ_ERR_CRYPTO);

  /* Wrong key.  */
  {
    gq_packet_keys s;

    CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_1, dcid, 8, NULL, &s), GQ_OK);
    memcpy (pkt, want, want_len);
    CHECK_EQ (gq_packet_open (&s, 0, 0, pkt, want_len, hdr - 4, &pn, &off,
                              &plen), GQ_ERR_CRYPTO);
  }
}

/* RFC 9001 appendix A.3: the server Initial.  */
static void
test_server_initial (void)
{
  uint8_t dcid[8], scid[8], want[256], pkt[256], plain[256], hdr_expect[64];
  size_t hdr, want_len, pn = 0, out, off, plen, pl, hl;
  uint64_t got_pn;
  gq_packet_keys s;

  tst_unhex (DCID_HEX, dcid, sizeof dcid);
  tst_unhex ("f067a5502a4262b5", scid, sizeof scid);
  CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_1, dcid, 8, NULL, &s), GQ_OK);

  pl = tst_unhex (V_SERVER_PAYLOAD_PLAINTEXT, plain, sizeof plain);
  hl = tst_unhex (V_SERVER_UNPROTECTED_HEADER, hdr_expect, sizeof hdr_expect);
  want_len = tst_unhex (V_SERVER_PROTECTED_PACKET, want, sizeof want);

  CHECK_EQ (gq_long_header_build (GQ_PKT_INITIAL, GQ_VERSION_1, NULL, 0, scid,
                                  8, NULL, 0, 1, 2, pl, pkt, sizeof pkt,
                                  &hdr), GQ_OK);
  CHECK_EQ (hdr, hl);
  CHECK (memcmp (pkt, hdr_expect, hdr) == 0);
  memcpy (pkt + hdr, plain, pl);
  pn = hdr - 2;
  CHECK_EQ (gq_packet_seal (&s, 1, pkt, pn, 2, pl, sizeof pkt, &out), GQ_OK);
  CHECK_EQ (out, want_len);
  CHECK (memcmp (pkt, want, want_len) == 0);

  memcpy (pkt, want, want_len);
  CHECK_EQ (gq_packet_open (&s, 0, 0, pkt, want_len, pn, &got_pn, &off, &plen),
            GQ_OK);
  CHECK (got_pn == 1);
  CHECK_EQ (plen, pl);
  CHECK (memcmp (pkt + off, plain, pl) == 0);
}

/* RFC 9001 appendix A.5: ChaCha20-Poly1305 short header packet.  */
static void
test_chacha_short (void)
{
  uint8_t secret[32], pkt[64], want[64], hdr_want[8];
  size_t hdr, out, want_len, off, plen;
  uint64_t pn;
  gq_packet_keys k;
  const uint64_t full = 654360564;

  tst_unhex ("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
             secret, sizeof secret);
  CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, GQ_AEAD_CHACHA20_POLY1305,
                                   secret, 32, &k), GQ_OK);
  want_len = tst_unhex ("4cfe4189655e5cd55c41f69080575d7999c25a5bfb", want,
                        sizeof want);
  tst_unhex ("4200bff4", hdr_want, sizeof hdr_want);

  CHECK_EQ (gq_short_header_build (NULL, 0, 0, 0, full, 3, pkt, sizeof pkt,
                                   &hdr), GQ_OK);
  CHECK_EQ (hdr, 4);
  CHECK (memcmp (pkt, hdr_want, 4) == 0);
  pkt[hdr] = 0x01;		/* A single PING frame.  */
  CHECK_EQ (gq_packet_seal (&k, full, pkt, 1, 3, 1, sizeof pkt, &out), GQ_OK);
  CHECK_EQ (out, want_len);
  CHECK (memcmp (pkt, want, want_len) == 0);

  memcpy (pkt, want, want_len);
  CHECK_EQ (gq_packet_open (&k, 1, full - 1, pkt, want_len, 1, &pn, &off,
                            &plen), GQ_OK);
  CHECK (pn == full);
  CHECK_EQ (plen, 1);
  CHECK_EQ (pkt[off], 0x01);
}

static void
test_seal_errors_and_reserved (void)
{
  static const uint8_t secret[32] = { 1 };
  uint8_t pkt[100];
  size_t hdr, out, off, plen;
  uint64_t pn;
  gq_packet_keys k;

  CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, GQ_AEAD_AES_128_GCM, secret,
                                   32, &k), GQ_OK);
  CHECK_EQ (gq_short_header_build (NULL, 0, 0, 0, 7, 1, pkt, sizeof pkt,
                                   &hdr), GQ_OK);
  /* One-byte packet number needs at least 3 payload bytes to sample.  */
  CHECK_EQ (gq_packet_seal (&k, 7, pkt, 1, 1, 2, sizeof pkt, &out),
            GQ_ERR_RANGE);
  CHECK_EQ (gq_packet_seal (&k, 7, pkt, 1, 1, 3, 1 + 1 + 3 + 15, &out),
            GQ_ERR_BUFSIZE);
  CHECK_EQ (gq_packet_seal (&k, 7, pkt, 1, 1, 3, 1 + 1 + 3 + 16, &out),
            GQ_OK);
  CHECK_EQ (out, 21);

  /* Too short to sample on receipt.  */
  CHECK_EQ (gq_packet_open (&k, 0, 0, pkt, 20, 1, &pn, &off, &plen),
            GQ_ERR_ENCODING);

  /* Reserved bits set in the plaintext header: authentic, but illegal.  */
  gq_short_header_build (NULL, 0, 0, 0, 7, 1, pkt, sizeof pkt, &hdr);
  pkt[0] |= 0x08;
  memset (pkt + hdr, 0, 3);
  CHECK_EQ (gq_packet_seal (&k, 7, pkt, 1, 1, 3, sizeof pkt, &out), GQ_OK);
  CHECK_EQ (gq_packet_open (&k, 0, 0, pkt, out, 1, &pn, &off, &plen),
            GQ_ERR_ENCODING);
}

static void
test_key_update (void)
{
  static const uint8_t secret[32] = { 7 };
  uint8_t next[32], next2[32], pkt[64], copy[64];
  size_t out, off, plen;
  uint64_t pn;
  gq_packet_keys k0, k1, k1v2, k2;

  CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, GQ_AEAD_AES_128_GCM, secret,
                                   32, &k0), GQ_OK);
  CHECK_EQ (gq_packet_keys_update (GQ_VERSION_1, &k0, secret, 32, next, &k1),
            GQ_OK);
  CHECK_EQ (gq_packet_keys_update (GQ_VERSION_2, &k0, secret, 32, next2, &k1v2),
            GQ_OK);
  CHECK (memcmp (k0.key, k1.key, 16) != 0);
  CHECK (memcmp (k0.iv, k1.iv, 12) != 0);
  CHECK (memcmp (k0.hp, k1.hp, 16) == 0);	/* HP key survives updates.  */
  CHECK (memcmp (k1.key, k1v2.key, 16) != 0);	/* Version-specific label.  */
  CHECK (memcmp (next, next2, 32) != 0);
  CHECK_EQ (gq_packet_keys_update (GQ_VERSION_1, &k1, next, 32, next2, &k2),
            GQ_OK);
  CHECK (memcmp (k1.key, k2.key, 16) != 0);

  /* A packet sealed after the update opens only with the new keys.  */
  memset (pkt, 0, sizeof pkt);
  pkt[0] = 0x40 | 0x04;		/* Key phase 1, one-byte packet number.  */
  pkt[1] = 9;
  CHECK_EQ (gq_packet_seal (&k1, 9, pkt, 1, 1, 10, sizeof pkt, &out), GQ_OK);
  memcpy (copy, pkt, out);
  CHECK_EQ (gq_packet_open (&k1, 0, 0, pkt, out, 1, &pn, &off, &plen), GQ_OK);
  memcpy (pkt, copy, out);
  CHECK_EQ (gq_packet_open (&k0, 0, 0, pkt, out, 1, &pn, &off, &plen),
            GQ_ERR_CRYPTO);

  gq_packet_keys_wipe (&k0);
  CHECK (tst_eq_hex (k0.key, 4, "00000000"));
}

int
main (void)
{
  test_initial_keys ();
  test_client_initial ();
  test_server_initial ();
  test_chacha_short ();
  test_seal_errors_and_reserved ();
  test_key_update ();
  TST_DONE ();
}
