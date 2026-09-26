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
#include <gnuquic/tparams.h>
#include <gnuquic/packet.h>

#include "tst-util.h"

/* The parameters a client sent in the RFC 9001 appendix A.2 ClientHello.  */
#define RFC_CLIENT_TP \
  "0408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f08" \
  "8394c8f03e51570806048000ffff"

static void
test_rfc_vector (void)
{
  uint8_t buf[128], out[128];
  size_t n = tst_unhex (RFC_CLIENT_TP, buf, sizeof buf), w;
  gq_transport_params tp;

  CHECK_EQ (n, 50);
  CHECK_EQ (gq_tp_decode (buf, n, GQ_ROLE_CLIENT, &tp), GQ_OK);
  CHECK (tp.initial_max_data == UINT64_C (0x3fffffffffffffff));
  CHECK_EQ (tp.initial_max_stream_data_bidi_local, 65535);
  CHECK_EQ (tp.initial_max_stream_data_bidi_remote, 65535);
  CHECK_EQ (tp.initial_max_stream_data_uni, 65535);
  CHECK_EQ (tp.initial_max_streams_bidi, 16);
  CHECK_EQ (tp.initial_max_streams_uni, 16);
  CHECK_EQ (tp.max_idle_timeout, 30000);
  CHECK (tst_eq_hex (tp.initial_source_connection_id.data,
                     tp.initial_source_connection_id.len, "8394c8f03e515708"));
  /* Absent parameters take RFC defaults.  */
  CHECK_EQ (tp.max_udp_payload_size, 65527);
  CHECK_EQ (tp.ack_delay_exponent, 3);
  CHECK_EQ (tp.max_ack_delay, 25);
  CHECK_EQ (tp.active_connection_id_limit, 2);
  CHECK (!gq_tp_has (&tp, GQ_TP_ACK_DELAY_EXPONENT));
  CHECK (gq_tp_has (&tp, GQ_TP_MAX_IDLE_TIMEOUT));

  /* Re-encoding gives the same parameters (ascending id order).  */
  CHECK_EQ (gq_tp_encode (&tp, GQ_ROLE_CLIENT, out, sizeof out, &w), GQ_OK);
  {
    gq_transport_params again;

    CHECK_EQ (gq_tp_decode (out, w, GQ_ROLE_CLIENT, &again), GQ_OK);
    CHECK (memcmp (&again, &tp, sizeof tp) == 0);
  }
  CHECK_EQ (out[0], 0x01);	/* max_idle_timeout is the lowest id.  */
}

static void
test_server_roundtrip (void)
{
  uint8_t buf[256];
  size_t w;
  gq_transport_params tp, back;

  gq_tp_defaults (&tp);
  tp.original_destination_connection_id.len = 8;
  memset (tp.original_destination_connection_id.data, 0x11, 8);
  gq_tp_set_present (&tp, GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID);
  tp.initial_source_connection_id.len = 4;
  memset (tp.initial_source_connection_id.data, 0x22, 4);
  gq_tp_set_present (&tp, GQ_TP_INITIAL_SOURCE_CONNECTION_ID);
  tp.retry_source_connection_id.len = 0;
  gq_tp_set_present (&tp, GQ_TP_RETRY_SOURCE_CONNECTION_ID);
  memset (tp.stateless_reset_token, 0x33, 16);
  gq_tp_set_present (&tp, GQ_TP_STATELESS_RESET_TOKEN);
  tp.max_idle_timeout = 60000;
  gq_tp_set_present (&tp, GQ_TP_MAX_IDLE_TIMEOUT);
  tp.max_udp_payload_size = 1452;
  gq_tp_set_present (&tp, GQ_TP_MAX_UDP_PAYLOAD_SIZE);
  tp.initial_max_data = 1 << 24;
  gq_tp_set_present (&tp, GQ_TP_INITIAL_MAX_DATA);
  tp.initial_max_streams_bidi = 100;
  gq_tp_set_present (&tp, GQ_TP_INITIAL_MAX_STREAMS_BIDI);
  tp.ack_delay_exponent = 5;
  gq_tp_set_present (&tp, GQ_TP_ACK_DELAY_EXPONENT);
  tp.max_ack_delay = 100;
  gq_tp_set_present (&tp, GQ_TP_MAX_ACK_DELAY);
  gq_tp_set_present (&tp, GQ_TP_DISABLE_ACTIVE_MIGRATION);
  tp.active_connection_id_limit = 8;
  gq_tp_set_present (&tp, GQ_TP_ACTIVE_CONNECTION_ID_LIMIT);
  tp.max_datagram_frame_size = 1200;
  gq_tp_set_present (&tp, GQ_TP_MAX_DATAGRAM_FRAME_SIZE);
  memset (tp.preferred_address.ipv4, 0x44, 4);
  tp.preferred_address.ipv4_port = 4433;
  memset (tp.preferred_address.ipv6, 0x55, 16);
  tp.preferred_address.ipv6_port = 4434;
  tp.preferred_address.cid.len = 6;
  memset (tp.preferred_address.cid.data, 0x66, 6);
  memset (tp.preferred_address.reset_token, 0x77, 16);
  gq_tp_set_present (&tp, GQ_TP_PREFERRED_ADDRESS);

  CHECK_EQ (gq_tp_encode (&tp, GQ_ROLE_SERVER, buf, sizeof buf, &w), GQ_OK);
  CHECK_EQ (gq_tp_decode (buf, w, GQ_ROLE_SERVER, &back), GQ_OK);
  CHECK (memcmp (&back, &tp, sizeof tp) == 0);
  CHECK (gq_tp_has (&back, GQ_TP_DISABLE_ACTIVE_MIGRATION));
  CHECK (gq_tp_has (&back, GQ_TP_MAX_DATAGRAM_FRAME_SIZE));

  /* The same block is refused if a client claims to have sent it.  */
  CHECK_EQ (gq_tp_decode (buf, w, GQ_ROLE_CLIENT, &back), GQ_ERR_ENCODING);
  CHECK_EQ (gq_tp_encode (&tp, GQ_ROLE_CLIENT, buf, sizeof buf, &w),
            GQ_ERR_INVAL);
  /* Output too small.  */
  CHECK_EQ (gq_tp_encode (&tp, GQ_ROLE_SERVER, buf, 10, &w), GQ_ERR_BUFSIZE);
}

static int
decode_hex (const char *hex, enum gq_role who)
{
  uint8_t b[128];
  size_t n = tst_unhex (hex, b, sizeof b);
  gq_transport_params tp;

  return gq_tp_decode (b, n, who, &tp);
}

static void
test_rejects (void)
{
  /* Valid single parameters first, to pin the encoding.  */
  CHECK_EQ (decode_hex ("0a0114", GQ_ROLE_CLIENT), GQ_OK);	/* exp 20 */
  CHECK_EQ (decode_hex ("", GQ_ROLE_CLIENT), GQ_OK);

  CHECK_EQ (decode_hex ("0a0115", GQ_ROLE_CLIENT), GQ_ERR_ENCODING);	/* 21 */
  CHECK_EQ (decode_hex ("0b024000", GQ_ROLE_CLIENT), GQ_OK);	/* 0 ... */
  CHECK_EQ (decode_hex ("0b0480004000", GQ_ROLE_CLIENT),
            GQ_ERR_ENCODING);					/* 2^14 */
  CHECK_EQ (decode_hex ("0b024000""0b024001", GQ_ROLE_CLIENT),
            GQ_ERR_ENCODING);					/* duplicate */
  CHECK_EQ (decode_hex ("0e0101", GQ_ROLE_CLIENT), GQ_ERR_ENCODING);	/* limit 1 */
  CHECK_EQ (decode_hex ("0e0102", GQ_ROLE_CLIENT), GQ_OK);
  CHECK_EQ (decode_hex ("030244b0", GQ_ROLE_CLIENT), GQ_OK);		/* 1200 */
  CHECK_EQ (decode_hex ("0302" "44af", GQ_ROLE_CLIENT), GQ_ERR_ENCODING);
  CHECK_EQ (decode_hex ("0c00", GQ_ROLE_CLIENT), GQ_OK);
  CHECK_EQ (decode_hex ("0c0100", GQ_ROLE_CLIENT), GQ_ERR_ENCODING);
  CHECK_EQ (decode_hex ("0f15" "000000000000000000000000000000000000000000",
                        GQ_ROLE_CLIENT), GQ_ERR_ENCODING);	/* 21-byte CID */
  /* Server-only parameters from a client.  */
  CHECK_EQ (decode_hex ("0000", GQ_ROLE_CLIENT), GQ_ERR_ENCODING);
  CHECK_EQ (decode_hex ("0000", GQ_ROLE_SERVER), GQ_OK);
  CHECK_EQ (decode_hex ("1000", GQ_ROLE_CLIENT), GQ_ERR_ENCODING);
  /* Reset token must be 16 bytes.  */
  CHECK_EQ (decode_hex ("020100", GQ_ROLE_SERVER), GQ_ERR_ENCODING);
  /* Streams limit above 2^60.  */
  CHECK_EQ (decode_hex ("0808d000000000000001", GQ_ROLE_CLIENT),
            GQ_ERR_ENCODING);
  /* Number with trailing junk in its value.  */
  CHECK_EQ (decode_hex ("0402" "0100", GQ_ROLE_CLIENT), GQ_ERR_ENCODING);
  /* Truncated records.  */
  CHECK_EQ (decode_hex ("04", GQ_ROLE_CLIENT), GQ_ERR_ENCODING);
  CHECK_EQ (decode_hex ("0408ffff", GQ_ROLE_CLIENT), GQ_ERR_ENCODING);
  /* Unknown and GREASE parameters are skipped, even duplicated.  */
  CHECK_EQ (decode_hex ("4a0a03aabbcc4a0a01ff", GQ_ROLE_CLIENT), GQ_OK);
  /* Preferred address with a zero-length CID.  */
  CHECK_EQ (decode_hex ("0d29"
                        "00000000" "0000" "00000000000000000000000000000000" "0000"
                        "00" "00000000000000000000000000000000", GQ_ROLE_SERVER),
            GQ_ERR_ENCODING);
}

static void
test_version_information (void)
{
  gq_transport_params tp, back;
  uint8_t buf[128];
  size_t n, i;
  /* Chosen 0x6b3343cf, available: v2, v1.  */
  static const uint8_t wire[] = { 0x11, 12, 0x6b, 0x33, 0x43, 0xcf, 0x6b,
                                  0x33, 0x43, 0xcf, 0, 0, 0, 1 };

  gq_tp_defaults (&tp);
  tp.chosen_version = GQ_VERSION_2;
  tp.available_versions[0] = GQ_VERSION_2;
  tp.available_versions[1] = GQ_VERSION_1;
  tp.n_available_versions = 2;
  gq_tp_set_present (&tp, GQ_TP_VERSION_INFORMATION);
  CHECK_EQ (gq_tp_encode (&tp, GQ_ROLE_CLIENT, buf, sizeof buf, &n), GQ_OK);
  CHECK (n == sizeof wire && !memcmp (buf, wire, n));
  CHECK_EQ (gq_tp_decode (buf, n, GQ_ROLE_SERVER, &back), GQ_OK);
  CHECK (gq_tp_has (&back, GQ_TP_VERSION_INFORMATION));
  CHECK (back.chosen_version == GQ_VERSION_2 && back.n_available_versions == 2);
  CHECK (back.available_versions[1] == GQ_VERSION_1);
  /* Either role may send it; a zero chosen version or a ragged length is
     refused, and so is a duplicate.  */
  CHECK_EQ (gq_tp_decode (buf, n, GQ_ROLE_CLIENT, &back), GQ_OK);
  for (i = 1; i < 4; i++)
    {
      uint8_t bad[32];

      memcpy (bad, wire, sizeof wire);
      bad[1] = (uint8_t) (12 - i);
      CHECK_EQ (gq_tp_decode (bad, sizeof wire - i, GQ_ROLE_CLIENT, &back),
                GQ_ERR_ENCODING);
    }
  {
    static const uint8_t zero[] = { 0x11, 4, 0, 0, 0, 0 };
    uint8_t dup[32];

    CHECK_EQ (gq_tp_decode (zero, sizeof zero, GQ_ROLE_CLIENT, &back),
              GQ_ERR_ENCODING);
    memcpy (dup, wire, sizeof wire);
    memcpy (dup + sizeof wire, wire, sizeof wire);
    CHECK_EQ (gq_tp_decode (dup, 2 * sizeof wire, GQ_ROLE_CLIENT, &back),
              GQ_ERR_ENCODING);
  }
}

int
main (void)
{
  test_rfc_vector ();
  test_server_roundtrip ();
  test_rejects ();
  test_version_information ();
  TST_DONE ();
}
