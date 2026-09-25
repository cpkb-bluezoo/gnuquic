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

/* QUIC packet headers (RFC 8999, RFC 9000 section 17, RFC 9369).

   This module deals with the unprotected framing of packets: packet
   numbers, long and short header parsing and construction, Version
   Negotiation, Retry and stateless reset packets.  Encryption and header
   protection are in protect.h.

   Parsers here work on one complete UDP datagram (or one coalesced
   packet inside it).  They follow the push-parser conventions: a header
   that ends before its fields do yields GQ_NEED_MORE, a header that is
   syntactically wrong yields GQ_ERR_ENCODING, and output fields that are
   variable-length are slices into the caller's buffer, never copies.

   QUIC versions 1 (RFC 9000) and 2 (RFC 9369) are supported.  They share
   one wire format and differ in the long header type bits, the Initial
   salt, the HKDF labels and the Retry integrity key.  */

#ifndef GNUQUIC_PACKET_H
#define GNUQUIC_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/frame.h>	/* gq_slice, GQ_MAX_CID_LEN */

#ifdef __cplusplus
extern "C" {
#endif

#define GQ_VERSION_NEGOTIATION 0x00000000u
#define GQ_VERSION_1 0x00000001u
#define GQ_VERSION_2 0x6b3343cfu

/* A client must pad datagrams carrying an Initial packet to this size.  */
#define GQ_MIN_INITIAL_DATAGRAM 1200

#define GQ_RETRY_TAG_LEN 16
#define GQ_STATELESS_RESET_TOKEN_LEN 16

/* Smallest datagram that can be a stateless reset (RFC 9000 10.3).  */
#define GQ_STATELESS_RESET_MIN_LEN 21

/* Logical packet types.  These are independent of version: QUIC v2
   permutes the wire type bits and gq_long_header_parse undoes that.  */
enum gq_packet_type
{
  GQ_PKT_INITIAL = 1,
  GQ_PKT_ZERO_RTT,
  GQ_PKT_HANDSHAKE,
  GQ_PKT_RETRY,
  GQ_PKT_VERSION_NEGOTIATION,
  GQ_PKT_SHORT
};

/* 1 if VERSION is a version this library implements (1 or 2).  */
int gq_version_supported (uint32_t version);

/* ---- Packet numbers (RFC 9000 section 17.1, appendix A) ---- */

/* Bytes (1 to 4) needed to encode FULL so the receiver can recover it,
   given the largest packet number the peer has acknowledged (if any).  */
size_t gq_pn_encoded_len (uint64_t full, int have_acked,
                          uint64_t largest_acked);

/* Write the low LEN bytes of FULL, big endian.  */
void gq_pn_encode (uint64_t full, size_t len, uint8_t *out);

/* Recover the full packet number from LEN truncated bytes read from the
   wire, given the largest packet number received so far (if any).  */
uint64_t gq_pn_decode (int have_largest, uint64_t largest_received,
                       uint64_t truncated, size_t len);

/* ---- Long headers ---- */

typedef struct gq_long_header
{
  uint8_t first;		/* First byte as on the wire.  */
  uint32_t version;
  enum gq_packet_type type;
  gq_slice dcid, scid;
  gq_slice token;		/* Initial: token.  Retry: retry token.  */
  gq_slice retry_tag;		/* Retry only: the 16-byte integrity tag.  */
  gq_slice versions;		/* Version Negotiation: raw version list.  */
  uint64_t length;		/* Length field: packet number + payload.  */
  size_t pn_offset;		/* Offset of the packet number field.  */
  size_t packet_len;		/* Bytes used by this packet in the input;
				   lets the caller step over coalesced
				   packets.  */
} gq_long_header;

/* Parse the long header at PKT (LEN bytes remaining in the datagram).

   Returns GQ_OK; GQ_NEED_MORE if the header is truncated; GQ_ERR_ENCODING
   if it is malformed (not a long header, connection ID too long, fixed
   bit clear, length beyond the datagram, empty Retry token...); or
   GQ_ERR_UNSUPPORTED for a version this library does not implement, in
   which case version, dcid and scid are filled so a server can answer
   with Version Negotiation.  The reserved bits and the packet number
   length are header-protected and are not examined here.  */
int gq_long_header_parse (const uint8_t *pkt, size_t len,
                          gq_long_header *h);

/* Number of versions in a parsed Version Negotiation packet, and the
   I'th of them.  */
size_t gq_vn_count (const gq_long_header *h);
uint32_t gq_vn_get (const gq_long_header *h, size_t i);

/* Build the unprotected header of an Initial, 0-RTT or Handshake packet
   into OUT, ending with the (cleartext) packet number.  PAYLOAD_LEN is
   the plaintext payload size; the Length field accounts for the AEAD tag
   that gq_packet_seal will append.  TOKEN is used only for Initial.
   On success *HDR_LEN is the header size and the packet number field
   starts at *HDR_LEN - PN_LEN.  */
int gq_long_header_build (enum gq_packet_type type, uint32_t version,
                          const uint8_t *dcid, size_t dcid_len,
                          const uint8_t *scid, size_t scid_len,
                          const uint8_t *token, size_t token_len,
                          uint64_t pn, size_t pn_len, size_t payload_len,
                          uint8_t *out, size_t cap, size_t *hdr_len);

/* ---- Short headers ---- */

typedef struct gq_short_header
{
  uint8_t first;
  gq_slice dcid;
  size_t pn_offset;
} gq_short_header;

/* Parse a 1-RTT header.  The Destination Connection ID length is not on
   the wire; the receiver must know it (DCID_LEN).  Returns GQ_OK,
   GQ_NEED_MORE or GQ_ERR_ENCODING (long header form, fixed bit clear).  */
int gq_short_header_parse (const uint8_t *pkt, size_t len, size_t dcid_len,
                           gq_short_header *h);

/* Build a 1-RTT header ending with the cleartext packet number.  */
int gq_short_header_build (const uint8_t *dcid, size_t dcid_len,
                           int spin, int key_phase, uint64_t pn,
                           size_t pn_len, uint8_t *out, size_t cap,
                           size_t *hdr_len);

/* ---- Version Negotiation (RFC 9000 section 17.2.1) ---- */

/* Build a Version Negotiation reply.  DCID and SCID are the client's SCID
   and DCID respectively (swapped by the caller).  UNUSED_BITS supplies
   the 7 arbitrary low bits of the first byte; pass random data.  */
int gq_vn_build (const uint8_t *dcid, size_t dcid_len,
                 const uint8_t *scid, size_t scid_len,
                 const uint32_t *versions, size_t n_versions,
                 uint8_t unused_bits, uint8_t *out, size_t cap,
                 size_t *written);

/* ---- Retry (RFC 9000 section 17.2.5, RFC 9001 section 5.8) ---- */

/* Build a complete Retry packet, integrity tag included.  ODCID is the
   Destination Connection ID of the client Initial being answered.
   UNUSED_BITS supplies the 4 arbitrary low bits of the first byte.  */
int gq_retry_build (uint32_t version, const uint8_t *dcid, size_t dcid_len,
                    const uint8_t *scid, size_t scid_len,
                    const uint8_t *token, size_t token_len,
                    const uint8_t *odcid, size_t odcid_len,
                    uint8_t unused_bits, uint8_t *out, size_t cap,
                    size_t *written);

/* Verify the integrity tag of a Retry packet PKT (LEN bytes, already
   parsed as H).  Returns GQ_OK or GQ_ERR_CRYPTO.  */
int gq_retry_verify (const gq_long_header *h, const uint8_t *pkt,
                     size_t len, const uint8_t *odcid, size_t odcid_len);

/* ---- Stateless reset (RFC 9000 section 10.3) ---- */

/* Size to use for a stateless reset answering a datagram of
   RECEIVED_LEN bytes: at least GQ_STATELESS_RESET_MIN_LEN so it can pass
   for a real packet, and strictly smaller than the trigger so two
   endpoints cannot loop.  Returns 0 if the trigger is too small to
   answer.  */
size_t gq_stateless_reset_size (size_t received_len);

/* Build a stateless reset for the given token: random bytes with the
   first byte shaped like a short header and the token at the end.  */
int gq_stateless_reset_build (size_t received_len, const uint8_t *token,
                              uint8_t *out, size_t cap, size_t *written);

/* 1 if the last 16 bytes of the datagram equal TOKEN (constant time).  */
int gq_stateless_reset_match (const uint8_t *datagram, size_t len,
                              const uint8_t *token);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_PACKET_H */
