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

#include <stdlib.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/ranges.h>

void
gq_ranges_init (gq_ranges *s, size_t max)
{
  s->r = NULL;
  s->n = s->cap = 0;
  s->max = max;
}

void
gq_ranges_free (gq_ranges *s)
{
  free (s->r);
  s->r = NULL;
  s->n = s->cap = 0;
}

void
gq_ranges_clear (gq_ranges *s)
{
  s->n = 0;
}

static int
reserve (gq_ranges *s, size_t want)
{
  gq_range *nr;
  size_t cap;

  if (want <= s->cap)
    return GQ_OK;
  cap = s->cap ? s->cap * 2 : 4;
  while (cap < want)
    cap *= 2;
  nr = realloc (s->r, cap * sizeof *nr);
  if (nr == NULL)
    return GQ_ERR_NOMEM;
  s->r = nr;
  s->cap = cap;
  return GQ_OK;
}

/* Index of the first range whose hi >= x (so it may touch or contain x).  */
static size_t
first_at_or_after (const gq_ranges *s, uint64_t x)
{
  size_t lo = 0, hi = s->n;

  while (lo < hi)
    {
      size_t mid = lo + (hi - lo) / 2;

      if (s->r[mid].hi < x)
        lo = mid + 1;
      else
        hi = mid;
    }
  return lo;
}

int
gq_ranges_add (gq_ranges *s, uint64_t lo, uint64_t hi, int evict_low)
{
  size_t i, j;

  if (lo >= hi)
    return GQ_OK;
  i = first_at_or_after (s, lo);
  /* Ranges i..j-1 touch or overlap the new one: merge them.  */
  for (j = i; j < s->n && s->r[j].lo <= hi; j++)
    {
      if (s->r[j].lo < lo)
        lo = s->r[j].lo;
      if (s->r[j].hi > hi)
        hi = s->r[j].hi;
    }
  if (j > i)
    {
      s->r[i].lo = lo;
      s->r[i].hi = hi;
      if (j > i + 1)
        {
          memmove (&s->r[i + 1], &s->r[j], (s->n - j) * sizeof s->r[0]);
          s->n -= j - i - 1;
        }
      return GQ_OK;
    }
  /* A new, separate range at position i.  */
  if (s->n >= s->max)
    {
      if (!evict_low || s->n == 0)
        return GQ_ERR_RANGE;
      /* Forget the lowest; if the new range is lower still, forget it.  */
      if (i == 0)
        return GQ_ERR_RANGE;
      memmove (&s->r[0], &s->r[1], (s->n - 1) * sizeof s->r[0]);
      s->n--;
      i--;
    }
  if (reserve (s, s->n + 1) != GQ_OK)
    return GQ_ERR_NOMEM;
  memmove (&s->r[i + 1], &s->r[i], (s->n - i) * sizeof s->r[0]);
  s->r[i].lo = lo;
  s->r[i].hi = hi;
  s->n++;
  return GQ_OK;
}

int
gq_ranges_remove (gq_ranges *s, uint64_t lo, uint64_t hi)
{
  size_t i;

  if (lo >= hi)
    return GQ_OK;
  i = first_at_or_after (s, lo);
  while (i < s->n && s->r[i].lo < hi)
    {
      gq_range cur = s->r[i];

      if (cur.lo < lo && cur.hi > hi)
        {
          /* Split in two.  */
          if (s->n >= s->max || reserve (s, s->n + 1) != GQ_OK)
            {
              /* No room for the second half: keep the lower part only.  */
              s->r[i].hi = lo;
              return GQ_ERR_RANGE;
            }
          memmove (&s->r[i + 2], &s->r[i + 1], (s->n - i - 1) * sizeof s->r[0]);
          s->r[i].hi = lo;
          s->r[i + 1].lo = hi;
          s->r[i + 1].hi = cur.hi;
          s->n++;
          return GQ_OK;
        }
      if (cur.lo < lo)
        {
          s->r[i].hi = lo;
          i++;
        }
      else if (cur.hi > hi)
        {
          s->r[i].lo = hi;
          i++;
        }
      else
        {
          memmove (&s->r[i], &s->r[i + 1], (s->n - i - 1) * sizeof s->r[0]);
          s->n--;
        }
    }
  return GQ_OK;
}

void
gq_ranges_trim_below (gq_ranges *s, uint64_t x)
{
  size_t i = 0;

  while (i < s->n && s->r[i].hi <= x)
    i++;
  if (i)
    {
      memmove (&s->r[0], &s->r[i], (s->n - i) * sizeof s->r[0]);
      s->n -= i;
    }
  if (s->n && s->r[0].lo < x)
    s->r[0].lo = x;
}

int
gq_ranges_contains (const gq_ranges *s, uint64_t v)
{
  size_t i = first_at_or_after (s, v);

  return i < s->n && s->r[i].lo <= v && v < s->r[i].hi;
}

int
gq_ranges_covers (const gq_ranges *s, uint64_t lo, uint64_t hi)
{
  size_t i;

  if (lo >= hi)
    return 1;
  i = first_at_or_after (s, lo);
  return i < s->n && s->r[i].lo <= lo && hi <= s->r[i].hi;
}

int
gq_ranges_pop_front (gq_ranges *s, uint64_t max_len, uint64_t *lo,
                     uint64_t *hi)
{
  if (s->n == 0 || max_len == 0)
    return 0;
  *lo = s->r[0].lo;
  if (s->r[0].hi - s->r[0].lo <= max_len)
    {
      *hi = s->r[0].hi;
      memmove (&s->r[0], &s->r[1], (s->n - 1) * sizeof s->r[0]);
      s->n--;
    }
  else
    {
      *hi = *lo + max_len;
      s->r[0].lo = *hi;
    }
  return 1;
}

uint64_t
gq_ranges_total (const gq_ranges *s)
{
  uint64_t t = 0;
  size_t i;

  for (i = 0; i < s->n; i++)
    {
      uint64_t d = s->r[i].hi - s->r[i].lo;

      if (t > UINT64_MAX - d)
        return UINT64_MAX;
      t += d;
    }
  return t;
}
