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

/* Minimal helpers shared by the test programs.  */

#ifndef GQ_TST_UTIL_H
#define GQ_TST_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tst_failures;

#define CHECK(cond) \
  do { \
    if (!(cond)) \
      { \
        fprintf (stderr, "%s:%d: check failed: %s\n", \
                 __FILE__, __LINE__, #cond); \
        tst_failures++; \
      } \
  } while (0)

#define CHECK_EQ(a, b) \
  do { \
    long long a_ = (long long) (a), b_ = (long long) (b); \
    if (a_ != b_) \
      { \
        fprintf (stderr, "%s:%d: %s == %s failed (%lld vs %lld)\n", \
                 __FILE__, __LINE__, #a, #b, a_, b_); \
        tst_failures++; \
      } \
  } while (0)

/* Decode HEX (no separators) into OUT; returns the byte count.  */
static inline size_t
tst_unhex (const char *hex, uint8_t *out, size_t cap)
{
  size_t n = 0;

  while (hex[0] && hex[1] && n < cap)
    {
      unsigned v;

      if (sscanf (hex, "%2x", &v) != 1)
        break;
      out[n++] = (uint8_t) v;
      hex += 2;
    }
  return n;
}

/* Compare BUF (LEN bytes) with the hex string HEX.  */
static inline int
tst_eq_hex (const uint8_t *buf, size_t len, const char *hex)
{
  uint8_t tmp[4096];
  size_t n = tst_unhex (hex, tmp, sizeof tmp);

  return n == len && memcmp (tmp, buf, len) == 0;
}

#define TST_DONE() \
  do { \
    if (tst_failures) \
      fprintf (stderr, "%d failure(s)\n", tst_failures); \
    return tst_failures ? 1 : 0; \
  } while (0)

#endif
