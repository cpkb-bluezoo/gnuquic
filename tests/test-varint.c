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

#include "tst-util.h"

static void
decode_vector (const char *hex, uint64_t expect)
{
  uint8_t b[8];
  size_t n = tst_unhex (hex, b, sizeof b);
  const uint8_t *p = b;
  size_t len = n;
  uint64_t v = 0;
  size_t k;

  CHECK_EQ (gq_varint_decode (&p, &len, &v), GQ_OK);
  CHECK (v == expect);
  CHECK_EQ (len, 0);

  /* Every strict prefix must report NEED_MORE and consume nothing.  */
  for (k = 0; k < n; k++)
    {
      p = b;
      len = k;
      CHECK_EQ (gq_varint_decode (&p, &len, &v), GQ_NEED_MORE);
      CHECK (p == b && len == k);
    }
}

int
main (void)
{
  /* RFC 9000 appendix A.1.  */
  uint64_t edges[] = { 0, 63, 64, 16383, 16384, 1073741823, 1073741824,
                       GQ_VARINT_MAX };
  size_t sizes[] = { 1, 1, 2, 2, 4, 4, 8, 8 };
  size_t i;
  uint8_t out[8];

  decode_vector ("c2197c5eff14e88c", UINT64_C (151288809941952652));
  decode_vector ("9d7f3e7d", 494878333);
  decode_vector ("7bbd", 15293);
  decode_vector ("25", 37);
  decode_vector ("4025", 37);	/* Non-minimal encodings are accepted.  */

  for (i = 0; i < sizeof edges / sizeof edges[0]; i++)
    {
      const uint8_t *p = out;
      size_t len;
      uint64_t v;

      CHECK_EQ (gq_varint_size (edges[i]), sizes[i]);
      len = gq_varint_encode (edges[i], out, sizeof out);
      CHECK_EQ (len, sizes[i]);
      CHECK_EQ (gq_varint_peek_size (out[0]), sizes[i]);
      CHECK_EQ (gq_varint_decode (&p, &len, &v), GQ_OK);
      CHECK (v == edges[i]);
    }

  CHECK_EQ (gq_varint_size (GQ_VARINT_MAX + 1), 0);
  CHECK_EQ (gq_varint_encode (GQ_VARINT_MAX + 1, out, sizeof out), 0);
  CHECK_EQ (gq_varint_encode (16384, out, 3), 0);	/* Too small.  */

  TST_DONE ();
}
