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

/* QUIC variable-length integers (RFC 9000 section 16).  */

#ifndef GNUQUIC_VARINT_H
#define GNUQUIC_VARINT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest representable value, 2^62 - 1.  */
#define GQ_VARINT_MAX ((UINT64_C (1) << 62) - 1)

/* Number of bytes gq_varint_encode would use for VALUE (1, 2, 4 or 8),
   or 0 if VALUE exceeds GQ_VARINT_MAX.  */
size_t gq_varint_size (uint64_t value);

/* Total encoded length announced by the first byte alone.  */
size_t gq_varint_peek_size (uint8_t first);

/* Encode VALUE minimally into OUT (capacity OUTLEN).  Returns the number
   of bytes written, or 0 if VALUE is out of range or OUT is too small.  */
size_t gq_varint_encode (uint64_t value, uint8_t *out, size_t outlen);

/* Push-style decode.  Reads one varint from *BUF, which has *LEN bytes
   remaining, and on success advances *BUF and shrinks *LEN past it.
   Returns GQ_OK, or GQ_NEED_MORE (with *BUF and *LEN untouched) if the
   input is shorter than the encoding.  */
int gq_varint_decode (const uint8_t **buf, size_t *len, uint64_t *value);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_VARINT_H */
