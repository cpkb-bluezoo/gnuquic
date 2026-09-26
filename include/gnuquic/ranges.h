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

/* Sets of 64-bit half-open ranges [lo, hi), kept sorted and merged.

   QUIC keeps track of several things as ranges: which packet numbers have
   arrived (to build ACK frames), which stream bytes have arrived out of
   order, which have been acknowledged, and which were lost.  One small
   structure serves all of them.  Storage is allocated on demand and
   never grows past the maximum given at initialisation, so a peer cannot
   make the set grow without bound; what a full set does with a new range
   is chosen by the caller (see gq_ranges_add).  */

#ifndef GNUQUIC_RANGES_H
#define GNUQUIC_RANGES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_range
{
  uint64_t lo, hi;		/* [lo, hi), lo < hi.  */
} gq_range;

typedef struct gq_ranges
{
  gq_range *r;			/* Sorted by lo, disjoint, not adjacent.  */
  size_t n, cap, max;
} gq_ranges;

/* An empty set holding at most MAX ranges.  */
void gq_ranges_init (gq_ranges *s, size_t max);
void gq_ranges_free (gq_ranges *s);
void gq_ranges_clear (gq_ranges *s);

/* Add [LO, HI).  If the set is full and the new range cannot merge with
   an existing one, the outcome depends on EVICT_LOW: 0 drops the new range
   and returns GQ_ERR_RANGE; nonzero discards the lowest range to make
   room (right for packet numbers, where old history is what to forget).
   Returns GQ_OK, GQ_ERR_RANGE or GQ_ERR_NOMEM.  Empty ranges are
   ignored.  */
int gq_ranges_add (gq_ranges *s, uint64_t lo, uint64_t hi, int evict_low);

/* Remove [LO, HI) from the set (splitting a range if needed).  */
int gq_ranges_remove (gq_ranges *s, uint64_t lo, uint64_t hi);

/* Drop everything below X.  */
void gq_ranges_trim_below (gq_ranges *s, uint64_t x);

/* 1 if V is in the set.  */
int gq_ranges_contains (const gq_ranges *s, uint64_t v);

/* 1 if all of [LO, HI) is in the set.  */
int gq_ranges_covers (const gq_ranges *s, uint64_t lo, uint64_t hi);

/* Take up to MAX_LEN from the lowest range: sets [*LO, *HI) and removes it
   from the set.  Returns 0 if the set is empty.  */
int gq_ranges_pop_front (gq_ranges *s, uint64_t max_len, uint64_t *lo,
                         uint64_t *hi);

/* Bytes in the set, saturating.  */
uint64_t gq_ranges_total (const gq_ranges *s);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_RANGES_H */
