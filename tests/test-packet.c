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

#include "tst-util.h"
#include "vectors.h"

static void
test_pn (void)
{
  /* RFC 9000 appendix A.3.  */
  CHECK (gq_pn_decode (1, 0xa82f30eaU, 0x9b32, 2) == UINT64_C (0xa82f9b32));
  /* Appendix A.2.  */
  CHECK_EQ (gq_pn_encoded_len (0xac5c02, 1, 0xabe8b3), 2);
  CHECK_EQ (gq_pn_encoded_len (0xace8fe, 1, 0xabe8b3), 3);
  CHECK_EQ (gq_pn_encoded_len (0, 0, 0), 1);
  CHECK_EQ (gq_pn_encoded_len (UINT64_C (1) << 40, 1, 0), 4);

  /* No packet received yet.  */
  CHECK (gq_pn_decode (0, 0, 5, 1) == 5);
  /* Wrap-around candidates in both directions.  */
  CHECK (gq_pn_decode (1, 0x1ff, 0x00, 1) == 0x200);
  CHECK (gq_pn_decode (1, 0x200, 0xff, 1) == 0x1ff);

  /* Round trip: every encoding length recovers the full number.  */
  {
    uint64_t largest = 1000000, full;
    uint8_t buf[4];
    size_t n, i;

    for (full = largest + 1; full < largest + 300000; full += 4999)
      {
        uint64_t t = 0;

        n = gq_pn_encoded_len (full, 1, largest);
        gq_pn_encode (full, n, buf);
        for (i = 0; i < n; i++)
          t = (t << 8) | buf[i];
        CHECK (gq_pn_decode (1, largest, t, n) == full);
      }
  }
}

static void
test_long_roundtrip (uint32_t version, enum gq_packet_type type,
                     unsigned expect_bits)
{
  static const uint8_t dcid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  static const uint8_t scid[3] = { 9, 10, 11 };
  static const uint8_t token[5] = { 't', 'o', 'k', 'e', 'n' };
  uint8_t pkt[200];
  size_t hdr, i;
  gq_long_header h;
  size_t payload = 30;
  int is_initial = (type == GQ_PKT_INITIAL);

  memset (pkt, 0xaa, sizeof pkt);
  CHECK_EQ (gq_long_header_build (type, version, dcid, sizeof dcid, scid,
                                  sizeof scid, token, is_initial ? 5 : 0,
                                  0x1234, 2, payload, pkt, sizeof pkt, &hdr),
            GQ_OK);
  CHECK_EQ ((pkt[0] >> 4) & 3, expect_bits);
  CHECK_EQ (pkt[0] & 3, 1);		/* pn_len - 1.  */
  CHECK_EQ (pkt[0] & 0xc0, 0xc0);

  /* Datagram: header + payload + 16-byte tag, then a second packet.  */
  memset (pkt + hdr, 0, payload + 16);
  CHECK_EQ (gq_long_header_parse (pkt, hdr + payload + 16, &h), GQ_OK);
  CHECK_EQ (h.version, version);
  CHECK_EQ (h.type, type);
  CHECK (h.dcid.len == 8 && memcmp (h.dcid.data, dcid, 8) == 0);
  CHECK (h.scid.len == 3 && memcmp (h.scid.data, scid, 3) == 0);
  CHECK_EQ (h.token.len, is_initial ? 5 : 0);
  CHECK_EQ (h.length, 2 + payload + 16);
  CHECK_EQ (h.pn_offset, hdr - 2);
  CHECK_EQ (h.packet_len, hdr + payload + 16);
  CHECK_EQ (pkt[h.pn_offset], 0x12);
  CHECK_EQ (pkt[h.pn_offset + 1], 0x34);

  /* Coalescing: a datagram longer than the packet parses the same and
     reports where the next packet starts.  */
  CHECK_EQ (gq_long_header_parse (pkt, sizeof pkt, &h), GQ_OK);
  CHECK_EQ (h.packet_len, hdr + payload + 16);

  /* Truncated inside the header: NEED_MORE for every prefix.  */
  for (i = 0; i < hdr - 2; i++)
    CHECK_EQ (gq_long_header_parse (pkt, i, &h), GQ_NEED_MORE);
  /* Header intact but the declared length runs past the datagram.  */
  CHECK_EQ (gq_long_header_parse (pkt, hdr + payload, &h), GQ_ERR_ENCODING);
}

static void
test_long_errors (void)
{
  uint8_t pkt[64];
  gq_long_header h;
  size_t hdr;
  static const uint8_t d[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

  CHECK_EQ (gq_long_header_build (GQ_PKT_HANDSHAKE, GQ_VERSION_1, d, 8, d, 0,
                                  NULL, 0, 1, 1, 20, pkt, sizeof pkt, &hdr),
            GQ_OK);
  memset (pkt + hdr, 0, 40);

  /* Fixed bit clear.  */
  pkt[0] &= (uint8_t) ~0x40;
  CHECK_EQ (gq_long_header_parse (pkt, hdr + 20, &h), GQ_ERR_ENCODING);
  pkt[0] |= 0x40;
  /* Short header form is not a long header.  */
  pkt[0] &= 0x7f;
  CHECK_EQ (gq_long_header_parse (pkt, hdr + 20, &h), GQ_ERR_ENCODING);
  pkt[0] |= 0x80;
  /* Connection ID longer than 20 in a known version.  */
  pkt[5] = 21;
  CHECK_EQ (gq_long_header_parse (pkt, sizeof pkt, &h), GQ_ERR_ENCODING);
  pkt[5] = 8;
  /* Unknown version: invariants still available for Version Negotiation.  */
  pkt[1] = 0xde; pkt[2] = 0xad; pkt[3] = 0xbe; pkt[4] = 0xef;
  CHECK_EQ (gq_long_header_parse (pkt, hdr + 20, &h), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (h.version, 0xdeadbeefU);
  CHECK (h.dcid.len == 8 && h.dcid.data[0] == 1);
  CHECK_EQ (gq_long_header_parse (pkt, 0, &h), GQ_NEED_MORE);
}

static void
test_rfc_client_initial_header (void)
{
  uint8_t pkt[1300];
  gq_long_header h;
  size_t n = tst_unhex (V_CLIENT_PROTECTED_PACKET, pkt, sizeof pkt);

  CHECK_EQ (n, 1200);
  CHECK_EQ (gq_long_header_parse (pkt, n, &h), GQ_OK);
  CHECK_EQ (h.type, GQ_PKT_INITIAL);
  CHECK_EQ (h.version, GQ_VERSION_1);
  CHECK (tst_eq_hex (h.dcid.data, h.dcid.len, "8394c8f03e515708"));
  CHECK_EQ (h.scid.len, 0);
  CHECK_EQ (h.token.len, 0);
  CHECK_EQ (h.length, 1182);
  CHECK_EQ (h.pn_offset, 18);
  CHECK_EQ (h.packet_len, 1200);
}

static void
test_short (void)
{
  static const uint8_t d[4] = { 0xa, 0xb, 0xc, 0xd };
  uint8_t pkt[64];
  size_t hdr;
  gq_short_header h;

  CHECK_EQ (gq_short_header_build (d, 4, 1, 1, 0x0102, 2, pkt, sizeof pkt,
                                   &hdr), GQ_OK);
  CHECK_EQ (hdr, 1 + 4 + 2);
  CHECK_EQ (pkt[0], 0x40 | 0x20 | 0x04 | 0x01);
  CHECK_EQ (gq_short_header_parse (pkt, hdr, 4, &h), GQ_OK);
  CHECK (h.dcid.len == 4 && memcmp (h.dcid.data, d, 4) == 0);
  CHECK_EQ (h.pn_offset, 5);
  CHECK_EQ (gq_short_header_parse (pkt, 3, 4, &h), GQ_NEED_MORE);
  pkt[0] &= (uint8_t) ~0x40;
  CHECK_EQ (gq_short_header_parse (pkt, hdr, 4, &h), GQ_ERR_ENCODING);
  pkt[0] = 0xc0;
  CHECK_EQ (gq_short_header_parse (pkt, hdr, 4, &h), GQ_ERR_ENCODING);
  CHECK_EQ (gq_short_header_build (d, 4, 0, 0, 1, 5, pkt, sizeof pkt, &hdr),
            GQ_ERR_INVAL);
}

static void
test_version_negotiation (void)
{
  static const uint8_t d[4] = { 1, 2, 3, 4 };
  static const uint8_t s[2] = { 9, 9 };
  static const uint32_t vs[3] = { GQ_VERSION_1, GQ_VERSION_2, 0x0a0a0a0a };
  uint8_t pkt[64];
  size_t n;
  gq_long_header h;

  CHECK_EQ (gq_vn_build (d, 4, s, 2, vs, 3, 0x2a, pkt, sizeof pkt, &n),
            GQ_OK);
  CHECK_EQ (n, 1 + 4 + 1 + 4 + 1 + 2 + 12);
  CHECK_EQ (pkt[0], 0x80 | 0x2a);
  CHECK_EQ (gq_long_header_parse (pkt, n, &h), GQ_OK);
  CHECK_EQ (h.type, GQ_PKT_VERSION_NEGOTIATION);
  CHECK_EQ (gq_vn_count (&h), 3);
  CHECK_EQ (gq_vn_get (&h, 0), GQ_VERSION_1);
  CHECK_EQ (gq_vn_get (&h, 1), GQ_VERSION_2);
  CHECK_EQ (gq_vn_get (&h, 2), 0x0a0a0a0aU);

  /* Empty or ragged version lists are malformed.  */
  CHECK_EQ (gq_long_header_parse (pkt, n - 12, &h), GQ_ERR_ENCODING);
  CHECK_EQ (gq_long_header_parse (pkt, n - 1, &h), GQ_ERR_ENCODING);
  CHECK_EQ (gq_vn_build (d, 4, s, 2, vs, 0, 0, pkt, sizeof pkt, &n),
            GQ_ERR_INVAL);
  CHECK_EQ (gq_vn_build (d, 4, s, 2, vs, 3, 0, pkt, 10, &n), GQ_ERR_BUFSIZE);
}

static void
retry_case (uint32_t version, const char *expect_hex)
{
  static const uint8_t odcid[8] = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
  static const uint8_t scid[8] = { 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };
  uint8_t pkt[128], expect[128];
  size_t n, en;
  gq_long_header h;

  en = tst_unhex (expect_hex, expect, sizeof expect);
  CHECK_EQ (gq_retry_build (version, NULL, 0, scid, 8, (const uint8_t *) "token",
                            5, odcid, 8, 0x0f, pkt, sizeof pkt, &n), GQ_OK);
  CHECK_EQ (n, en);
  CHECK (memcmp (pkt, expect, en) == 0);

  CHECK_EQ (gq_long_header_parse (expect, en, &h), GQ_OK);
  CHECK_EQ (h.type, GQ_PKT_RETRY);
  CHECK_EQ (h.token.len, 5);
  CHECK (memcmp (h.token.data, "token", 5) == 0);
  CHECK_EQ (h.retry_tag.len, 16);
  CHECK_EQ (gq_retry_verify (&h, expect, en, odcid, 8), GQ_OK);

  /* Wrong original DCID, tampered token, tampered tag.  */
  CHECK_EQ (gq_retry_verify (&h, expect, en, scid, 8), GQ_ERR_CRYPTO);
  memcpy (pkt, expect, en);
  pkt[en - 20] ^= 1;
  CHECK_EQ (gq_retry_verify (&h, pkt, en, odcid, 8), GQ_ERR_CRYPTO);
  pkt[en - 20] ^= 1;
  pkt[en - 1] ^= 1;
  CHECK_EQ (gq_retry_verify (&h, pkt, en, odcid, 8), GQ_ERR_CRYPTO);

  /* A Retry with an empty token (only the tag) is malformed.  */
  CHECK_EQ (gq_long_header_parse (expect, en - 5, &h), GQ_ERR_ENCODING);
}

static void
test_retry (void)
{
  /* RFC 9001 appendix A.4 and RFC 9369 appendix A.4.  */
  retry_case (GQ_VERSION_1,
              "ff000000010008f067a5502a4262b5746f6b656e"
              "04a265ba2eff4d829058fb3f0f2496ba");
  retry_case (GQ_VERSION_2,
              "cf6b3343cf0008f067a5502a4262b5746f6b656e"
              "c8646ce8bfe33952d955543665dcc7b6");
}

static void
test_stateless_reset (void)
{
  uint8_t token[16], pkt[128];
  size_t n;

  memset (token, 0x5a, sizeof token);
  CHECK_EQ (gq_stateless_reset_size (21), 0);
  CHECK_EQ (gq_stateless_reset_size (22), 21);
  CHECK_EQ (gq_stateless_reset_size (30), 29);
  CHECK_EQ (gq_stateless_reset_size (1200), 43);

  CHECK_EQ (gq_stateless_reset_build (1200, token, pkt, sizeof pkt, &n), GQ_OK);
  CHECK_EQ (n, 43);
  CHECK_EQ (pkt[0] & 0xc0, 0x40);	/* Looks like a short header.  */
  CHECK (gq_stateless_reset_match (pkt, n, token));
  token[3] ^= 1;
  CHECK (!gq_stateless_reset_match (pkt, n, token));
  CHECK (!gq_stateless_reset_match (pkt, 20, token));
  CHECK_EQ (gq_stateless_reset_build (20, token, pkt, sizeof pkt, &n),
            GQ_ERR_RANGE);
  CHECK_EQ (gq_stateless_reset_build (1200, token, pkt, 30, &n),
            GQ_ERR_BUFSIZE);
}

int
main (void)
{
  test_pn ();
  test_long_roundtrip (GQ_VERSION_1, GQ_PKT_INITIAL, 0);
  test_long_roundtrip (GQ_VERSION_1, GQ_PKT_ZERO_RTT, 1);
  test_long_roundtrip (GQ_VERSION_1, GQ_PKT_HANDSHAKE, 2);
  test_long_roundtrip (GQ_VERSION_2, GQ_PKT_INITIAL, 1);
  test_long_roundtrip (GQ_VERSION_2, GQ_PKT_ZERO_RTT, 2);
  test_long_roundtrip (GQ_VERSION_2, GQ_PKT_HANDSHAKE, 3);
  test_long_errors ();
  test_rfc_client_initial_header ();
  test_short ();
  test_version_negotiation ();
  test_retry ();
  test_stateless_reset ();
  TST_DONE ();
}
