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

/* QUIC transport parameters (RFC 9000 section 18, RFC 9221).

   Transport parameters travel inside a TLS extension as a sequence of
   (id, length, value) records.  gq_tp_foreach is the generic walker: it
   delivers each record as an event, values as slices into the caller's
   buffer.  gq_tp_decode builds on it to fill a fixed-size struct
   (nothing is allocated) and enforces the validity rules of RFC 9000
   section 18.2, including the ones that depend on which side sent the
   parameters.  Unknown parameters, including GREASE, are ignored.  */

#ifndef GNUQUIC_TPARAMS_H
#define GNUQUIC_TPARAMS_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/frame.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Which endpoint sent (or will send) the parameters.  */
enum gq_role
{
  GQ_ROLE_CLIENT = 1,
  GQ_ROLE_SERVER = 2
};

/* Parameter identifiers.  */
enum
{
  GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID = 0x00,
  GQ_TP_MAX_IDLE_TIMEOUT = 0x01,
  GQ_TP_STATELESS_RESET_TOKEN = 0x02,
  GQ_TP_MAX_UDP_PAYLOAD_SIZE = 0x03,
  GQ_TP_INITIAL_MAX_DATA = 0x04,
  GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05,
  GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06,
  GQ_TP_INITIAL_MAX_STREAM_DATA_UNI = 0x07,
  GQ_TP_INITIAL_MAX_STREAMS_BIDI = 0x08,
  GQ_TP_INITIAL_MAX_STREAMS_UNI = 0x09,
  GQ_TP_ACK_DELAY_EXPONENT = 0x0a,
  GQ_TP_MAX_ACK_DELAY = 0x0b,
  GQ_TP_DISABLE_ACTIVE_MIGRATION = 0x0c,
  GQ_TP_PREFERRED_ADDRESS = 0x0d,
  GQ_TP_ACTIVE_CONNECTION_ID_LIMIT = 0x0e,
  GQ_TP_INITIAL_SOURCE_CONNECTION_ID = 0x0f,
  GQ_TP_RETRY_SOURCE_CONNECTION_ID = 0x10,
  GQ_TP_VERSION_INFORMATION = 0x11,	/* RFC 9368.  */
  GQ_TP_MAX_DATAGRAM_FRAME_SIZE = 0x20
};

typedef struct gq_cid
{
  uint8_t len;
  uint8_t data[GQ_MAX_CID_LEN];
} gq_cid;

#define GQ_TP_MAX_VERSIONS 8

typedef struct gq_preferred_address
{
  uint8_t ipv4[4];
  uint16_t ipv4_port;
  uint8_t ipv6[16];
  uint16_t ipv6_port;
  gq_cid cid;
  uint8_t reset_token[GQ_RESET_TOKEN_LEN];
} gq_preferred_address;

/* Decoded parameters.  Numeric fields hold the RFC default when the
   parameter was absent (see gq_tp_defaults); the PRESENT mask records
   which parameters were actually on the wire, and is what gq_tp_encode
   uses to decide what to send.  Bit N of PRESENT corresponds to
   parameter id N for ids below 32 (GQ_TP_MAX_DATAGRAM_FRAME_SIZE is
   bit 0x20 and lives in PRESENT_HI as bit 0).  Use gq_tp_has and
   gq_tp_set_present rather than touching the masks directly.  */
typedef struct gq_transport_params
{
  uint32_t present;
  uint32_t present_hi;
  gq_cid original_destination_connection_id;
  gq_cid initial_source_connection_id;
  gq_cid retry_source_connection_id;
  uint8_t stateless_reset_token[GQ_RESET_TOKEN_LEN];
  uint64_t max_idle_timeout;		/* Milliseconds; 0 = disabled.  */
  uint64_t max_udp_payload_size;
  uint64_t initial_max_data;
  uint64_t initial_max_stream_data_bidi_local;
  uint64_t initial_max_stream_data_bidi_remote;
  uint64_t initial_max_stream_data_uni;
  uint64_t initial_max_streams_bidi;
  uint64_t initial_max_streams_uni;
  uint64_t ack_delay_exponent;
  uint64_t max_ack_delay;		/* Milliseconds.  */
  uint64_t active_connection_id_limit;
  uint64_t max_datagram_frame_size;	/* 0 = DATAGRAM not supported.  */
  gq_preferred_address preferred_address;
  /* version_information (RFC 9368): the version in use and the versions
     the sender is willing to use.  */
  uint32_t chosen_version;
  uint32_t available_versions[GQ_TP_MAX_VERSIONS];
  size_t n_available_versions;
} gq_transport_params;

/* Fill TP with the defaults of RFC 9000 section 18.2 and no parameter
   present.  */
void gq_tp_defaults (gq_transport_params *tp);

int gq_tp_has (const gq_transport_params *tp, unsigned id);
void gq_tp_set_present (gq_transport_params *tp, unsigned id);

/* Event walker: call CB with each (ID, VALUE) record in BUF.  Returns
   GQ_OK, GQ_ERR_ENCODING if the block is malformed (truncated record),
   or GQ_ERR_HANDLER if CB returned nonzero.  */
int gq_tp_foreach (const uint8_t *buf, size_t len,
                   int (*cb) (void *user, uint64_t id, gq_slice value),
                   void *user);

/* Decode and validate the parameters sent by SENDER.  Returns GQ_OK or
   GQ_ERR_ENCODING (the connection layer maps this to
   TRANSPORT_PARAMETER_ERROR).  A client that sends a server-only
   parameter, a duplicated parameter, or an out-of-range value is
   rejected.  */
int gq_tp_decode (const uint8_t *buf, size_t len, enum gq_role sender,
                  gq_transport_params *tp);

/* Encode the present parameters of TP as sent by SENDER, in ascending id
   order.  Returns GQ_OK, GQ_ERR_BUFSIZE, or GQ_ERR_INVAL for parameters
   that SENDER may not send.  */
int gq_tp_encode (const gq_transport_params *tp, enum gq_role sender,
                  uint8_t *out, size_t cap, size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TPARAMS_H */
