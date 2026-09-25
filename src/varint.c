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
#include <gnuquic/varint.h>

size_t
gq_varint_size (uint64_t value)
{
  if (value <= 0x3f)
    return 1;
  if (value <= 0x3fff)
    return 2;
  if (value <= 0x3fffffff)
    return 4;
  if (value <= GQ_VARINT_MAX)
    return 8;
  return 0;
}

size_t
gq_varint_peek_size (uint8_t first)
{
  return (size_t) 1 << (first >> 6);
}

size_t
gq_varint_encode (uint64_t value, uint8_t *out, size_t outlen)
{
  size_t n = gq_varint_size (value);
  size_t i;

  if (n == 0 || outlen < n)
    return 0;

  for (i = 0; i < n; i++)
    out[i] = (uint8_t) (value >> (8 * (n - 1 - i)));
  /* The two high bits of the first byte carry log2 of the length.  */
  out[0] |= (uint8_t) ((n == 1 ? 0 : n == 2 ? 1 : n == 4 ? 2 : 3) << 6);
  return n;
}

int
gq_varint_decode (const uint8_t **buf, size_t *len, uint64_t *value)
{
  const uint8_t *p = *buf;
  size_t n, i;
  uint64_t v;

  if (*len == 0)
    return GQ_NEED_MORE;
  n = gq_varint_peek_size (p[0]);
  if (*len < n)
    return GQ_NEED_MORE;

  v = p[0] & 0x3f;
  for (i = 1; i < n; i++)
    v = (v << 8) | p[i];

  *value = v;
  *buf = p + n;
  *len -= n;
  return GQ_OK;
}
