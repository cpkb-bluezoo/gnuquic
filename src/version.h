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

/* Per-version constants (internal).  QUIC v1 and v2 share a wire format
   and differ only in what is tabulated here.  */

#ifndef GQ_VERSION_H
#define GQ_VERSION_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/packet.h>

struct gq_version_info
{
  uint32_t wire;
  const char *label_key, *label_iv, *label_hp, *label_ku;
  uint8_t initial_salt[20];
  uint8_t retry_key[16];
  uint8_t retry_nonce[12];
  /* Long header type bits for INITIAL, ZERO_RTT, HANDSHAKE, RETRY.  */
  uint8_t type_bits[4];
};

/* NULL if VERSION is not implemented.  */
const struct gq_version_info *gq_version_lookup (uint32_t version);

/* Map wire type bits to a logical type for VI.  */
enum gq_packet_type gq_version_type_from_bits (const struct gq_version_info *vi,
                                               unsigned bits);

#endif
