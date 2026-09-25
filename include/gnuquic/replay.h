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

/* Anti-replay for 0-RTT (RFC 8446 section 8).

   Early data is not forward secret and, unlike everything else in TLS, can
   be replayed by an attacker who records it: the server has no fresh
   randomness from the client when it decrypts it.  The defence this
   library implements is single-use tickets (RFC 8446 section 8.1): the
   server remembers which tickets it has already accepted early data for
   and refuses early data on a second use.  Resumption itself still works
   for a replayed ticket (only the early data is refused), so the client
   loses at most a round trip.

   The server engine asks a callback with the same signature as
   gq_replay_cache_check.  A deployment that runs several servers behind
   one address needs a store they share, so it supplies its own callback;
   this cache is the single-process implementation.  Returning "not fresh"
   whenever the answer is uncertain is always safe.

   The cache is a bounded open-addressing table of ticket identifiers.
   Entries expire with the ticket, and if the table fills with unexpired
   entries the cache refuses new ones (it fails closed) rather than
   forgetting, since forgetting would re-enable replays.  It is not thread
   safe.  */

#ifndef GNUQUIC_REPLAY_H
#define GNUQUIC_REPLAY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_replay_cache gq_replay_cache;

/* Create a cache holding up to about CAPACITY live tickets.  */
int gq_replay_cache_new (gq_replay_cache **out, size_t capacity);
void gq_replay_cache_free (gq_replay_cache *cache);

/* Record ID_HASH (a 32-byte digest of the ticket) if it has not been seen
   and has not expired, keeping it until EXPIRES_MS.  Returns nonzero if it
   was fresh (early data may be accepted), 0 if it is a replay, already
   expired, or the cache is full.  CACHE is a gq_replay_cache pointer, in
   the shape the engine's callback wants.  */
int gq_replay_cache_check (void *cache, const uint8_t id_hash[32],
                           uint64_t expires_ms, uint64_t now_ms);

/* Number of live entries (for tests and monitoring).  */
size_t gq_replay_cache_size (const gq_replay_cache *cache);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_REPLAY_H */
