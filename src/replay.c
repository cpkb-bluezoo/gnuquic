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
#include <gnuquic/replay.h>

struct entry
{
  uint8_t id[32];
  uint64_t expires;		/* 0: slot unused.  */
};

struct gq_replay_cache
{
  struct entry *slot;
  size_t n;			/* Power of two.  */
  size_t live;
  size_t limit;			/* Refuse above this many live entries.  */
};

int
gq_replay_cache_new (gq_replay_cache **out, size_t capacity)
{
  gq_replay_cache *c;
  size_t n = 16;

  if (out == NULL || capacity == 0 || capacity > ((size_t) 1 << 26))
    return GQ_ERR_INVAL;
  /* Keep the load factor at or below 1/2 so probes stay short.  */
  while (n < capacity * 2)
    n <<= 1;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  c->slot = calloc (n, sizeof *c->slot);
  if (c->slot == NULL)
    {
      free (c);
      return GQ_ERR_NOMEM;
    }
  c->n = n;
  c->limit = capacity;
  *out = c;
  return GQ_OK;
}

void
gq_replay_cache_free (gq_replay_cache *c)
{
  if (c == NULL)
    return;
  free (c->slot);
  free (c);
}

size_t
gq_replay_cache_size (const gq_replay_cache *c)
{
  return c ? c->live : 0;
}

/* The ID is already a hash, so its first bytes index the table.  */
static size_t
home (const gq_replay_cache *c, const uint8_t id[32])
{
  size_t h = 0;
  int i;

  for (i = 0; i < 8; i++)
    h = (h << 8) | id[i];
  return h & (c->n - 1);
}

int
gq_replay_cache_check (void *cache, const uint8_t id_hash[32],
                       uint64_t expires_ms, uint64_t now_ms)
{
  gq_replay_cache *c = cache;
  size_t i, idx, first_free = (size_t) -1;

  if (c == NULL || id_hash == NULL || expires_ms <= now_ms)
    return 0;			/* Expired tickets cannot carry early data.  */

  idx = home (c, id_hash);
  for (i = 0; i < c->n; i++)
    {
      struct entry *e = &c->slot[(idx + i) & (c->n - 1)];

      if (e->expires == 0)
        {
          if (first_free == (size_t) -1)
            first_free = (idx + i) & (c->n - 1);
          break;		/* End of the probe chain: not present.  */
        }
      if (e->expires <= now_ms)
        {
          /* A dead entry: its ticket can no longer be replayed, so the
             slot is reusable, but do not break the chain by clearing.  */
          if (first_free == (size_t) -1)
            first_free = (idx + i) & (c->n - 1);
          continue;
        }
      if (memcmp (e->id, id_hash, 32) == 0)
        return 0;		/* Seen before: a replay.  */
    }

  if (first_free == (size_t) -1 || c->live >= c->limit)
    {
      /* Full of live entries: purge the dead ones once, then retry.  */
      size_t k;

      c->live = 0;
      for (k = 0; k < c->n; k++)
        if (c->slot[k].expires > now_ms)
          c->live++;
      if (c->live >= c->limit || first_free == (size_t) -1)
        return 0;		/* Fail closed.  */
    }
  {
    /* FIRST_FREE is an unused slot or a dead entry: either way it is ours.
       The live count is an upper bound, recounted exactly when it would
       otherwise refuse an entry.  */
    struct entry *e = &c->slot[first_free];

    memcpy (e->id, id_hash, 32);
    e->expires = expires_ms;
    c->live++;
  }
  return 1;
}
