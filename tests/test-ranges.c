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

/* Range sets: checked against a plain bitmap model over random operations,
   plus the boundary behaviours callers depend on.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/ranges.h>

#include "tst-util.h"

#define SPACE 200

static uint32_t rng = 17;

static uint32_t
rnd (void)
{
  rng = rng * 1664525u + 1013904223u;
  return rng >> 8;
}

/* The set must equal the model, be sorted, disjoint and non-adjacent.  */
static void
check (const gq_ranges *s, const uint8_t *model)
{
  size_t i;
  uint64_t v;

  for (i = 0; i < s->n; i++)
    {
      CHECK (s->r[i].lo < s->r[i].hi);
      if (i)
        CHECK (s->r[i - 1].hi < s->r[i].lo);
    }
  for (v = 0; v < SPACE; v++)
    CHECK_EQ (gq_ranges_contains (s, v), model[v]);
}

static void
test_model (void)
{
  int round, op;

  for (round = 0; round < 40; round++)
    {
      gq_ranges s;
      uint8_t model[SPACE];
      uint64_t i;

      memset (model, 0, sizeof model);
      gq_ranges_init (&s, 1000);
      for (op = 0; op < 200; op++)
        {
          uint64_t lo = rnd () % SPACE, hi = lo + rnd () % 20;

          if (hi > SPACE)
            hi = SPACE;
          switch (rnd () % 5)
            {
            case 0: case 1: case 2:
              CHECK_EQ (gq_ranges_add (&s, lo, hi, 0), GQ_OK);
              for (i = lo; i < hi; i++)
                model[i] = 1;
              break;
            case 3:
              CHECK_EQ (gq_ranges_remove (&s, lo, hi), GQ_OK);
              for (i = lo; i < hi; i++)
                model[i] = 0;
              break;
            default:
              gq_ranges_trim_below (&s, lo);
              for (i = 0; i < lo; i++)
                model[i] = 0;
              break;
            }
          check (&s, model);
          {
            uint64_t q = rnd () % SPACE, e = q + rnd () % 10, total = 0;
            int all = 1;

            if (e > SPACE)
              e = SPACE;
            for (i = q; i < e; i++)
              all &= model[i];
            CHECK_EQ (gq_ranges_covers (&s, q, e), all);
            for (i = 0; i < SPACE; i++)
              total += model[i];
            CHECK_EQ ((long long) gq_ranges_total (&s), (long long) total);
          }
        }
      /* Popping in pieces reproduces the model in order.  */
      {
        uint64_t lo, hi, next = 0;

        while (gq_ranges_pop_front (&s, 7, &lo, &hi))
          {
            CHECK (hi - lo <= 7 && hi > lo);
            for (i = lo; i < hi; i++)
              CHECK (model[i] == 1 && i >= next);
            for (i = lo; i < hi; i++)
              model[i] = 0;
            next = hi;
          }
        for (i = 0; i < SPACE; i++)
          CHECK_EQ (model[i], 0);
      }
      gq_ranges_free (&s);
    }
}

static void
test_limits (void)
{
  gq_ranges s;
  uint64_t i;

  /* A full set drops a new separate range, or, asked to, its lowest.  */
  gq_ranges_init (&s, 3);
  CHECK_EQ (gq_ranges_add (&s, 10, 12, 0), GQ_OK);
  CHECK_EQ (gq_ranges_add (&s, 20, 22, 0), GQ_OK);
  CHECK_EQ (gq_ranges_add (&s, 30, 32, 0), GQ_OK);
  CHECK_EQ (gq_ranges_add (&s, 40, 42, 0), GQ_ERR_RANGE);
  CHECK_EQ (s.n, 3);
  CHECK_EQ (gq_ranges_add (&s, 11, 21, 0), GQ_OK);	/* Merges: fits.  */
  CHECK_EQ (s.n, 2);
  CHECK_EQ (gq_ranges_add (&s, 50, 52, 0), GQ_OK);
  CHECK_EQ (gq_ranges_add (&s, 60, 62, 1), GQ_OK);	/* Evicts [10,22).  */
  CHECK (!gq_ranges_contains (&s, 10) && gq_ranges_contains (&s, 60));
  CHECK_EQ (gq_ranges_add (&s, 1, 2, 1), GQ_ERR_RANGE);	/* Lower than all.  */
  /* Splitting needs a slot too.  */
  gq_ranges_clear (&s);
  CHECK_EQ (gq_ranges_add (&s, 0, 100, 0), GQ_OK);
  CHECK_EQ (gq_ranges_add (&s, 200, 210, 0), GQ_OK);
  CHECK_EQ (gq_ranges_add (&s, 300, 310, 0), GQ_OK);
  CHECK_EQ (gq_ranges_remove (&s, 40, 50), GQ_ERR_RANGE);
  gq_ranges_free (&s);

  /* Adjacent ranges merge; empty ranges are ignored; huge values work.  */
  gq_ranges_init (&s, 8);
  gq_ranges_add (&s, 5, 10, 0);
  gq_ranges_add (&s, 10, 15, 0);
  gq_ranges_add (&s, 3, 3, 0);
  CHECK (s.n == 1 && s.r[0].lo == 5 && s.r[0].hi == 15);
  gq_ranges_add (&s, UINT64_MAX - 5, UINT64_MAX, 0);
  CHECK_EQ (s.n, 2);
  CHECK_EQ ((long long) gq_ranges_total (&s), 15);
  for (i = 0; i < 4; i++)
    gq_ranges_add (&s, 100 + 10 * i, 105 + 10 * i, 0);
  gq_ranges_trim_below (&s, 102);
  CHECK (s.r[0].lo == 102 && s.r[0].hi == 105);
  gq_ranges_free (&s);
}

int
main (void)
{
  test_model ();
  test_limits ();
  TST_DONE ();
}
