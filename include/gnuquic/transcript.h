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

/* TLS 1.3 handshake transcript hash (RFC 8446 section 4.4.1).

   A running hash over the handshake messages, each fed whole including
   its 4-byte header.  Reading the current value does not disturb it, so
   the engine can take the hashes it needs at each stage (after
   ServerHello, after server Finished, after client Finished, and so on)
   while continuing to feed messages.  The hash context lives in libgcrypt
   memory, so a transcript is created and freed rather than embedded.  */

#ifndef GNUQUIC_TRANSCRIPT_H
#define GNUQUIC_TRANSCRIPT_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_transcript gq_transcript;

int gq_transcript_new (gq_transcript **out, enum gq_hash alg);
void gq_transcript_free (gq_transcript *t);

/* Feed bytes (a whole handshake message, header included).  */
int gq_transcript_update (gq_transcript *t, const void *data, size_t len);

/* Store the hash of everything fed so far in OUT, which must be
   gq_hash_size bytes.  The transcript remains usable.  */
int gq_transcript_hash (const gq_transcript *t, uint8_t *out, size_t outlen);

/* Duplicate a transcript, for keeping the state at a point in time
   (for example the ClientHello hash needed for PSK binders).  */
int gq_transcript_copy (const gq_transcript *t, gq_transcript **out);

/* Restart after a HelloRetryRequest (RFC 8446 section 4.4.1): replace the
   transcript, which so far holds ClientHello1, by the synthetic
   message_hash message carrying Hash(ClientHello1).  */
int gq_transcript_hello_retry (gq_transcript *t);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TRANSCRIPT_H */
