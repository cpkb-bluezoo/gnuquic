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

/* Key exchange for TLS 1.3 / DTLS 1.3 key_share extensions.

   Supported groups (see policy.h): X25519, secp256r1, secp384r1 and the
   three hybrid post-quantum groups of RFC 10024, which combine one of
   those curves with ML-KEM.  All arithmetic is done by libgcrypt through
   its KEM interface; this module adds the TLS wire encodings and the
   hybrid concatenation.

   The client calls gq_kx_generate and sends the key's client share.  The
   server calls gq_kx_respond with that share and sends back its own
   server share.  The client calls gq_kx_complete with the server share.
   Both ends then hold the same shared secret, which feeds the TLS 1.3
   key schedule as the (EC)DHE input.

   For the hybrid groups the wire format and the secret concatenation
   order differ between groups, as the RFC specifies:

     X25519MLKEM768    ML-KEM first:   share = mlkem || x25519
     SecP256r1MLKEM768 classical first: share = secp256r1 || mlkem
     SecP384r1MLKEM1024 classical first: share = secp384r1 || mlkem

   and the shared secret is concatenated in the same order.  Curve points
   use the uncompressed SEC1 form; the ECDH secret is the x coordinate.  */

#ifndef GNUQUIC_KX_H
#define GNUQUIC_KX_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/policy.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Upper bounds over all groups, for sizing buffers.  */
#define GQ_KX_SHARE_MAX 1665	/* secp384r1 point + ML-KEM-1024.  */
#define GQ_KX_SHARED_MAX 80	/* secp384r1 x (48) + ML-KEM secret (32).  */
#define GQ_KX_SECRET_MAX 3216	/* secp384r1 scalar + ML-KEM-1024 dk.  */

/* A client's ephemeral key.  Treat the contents as opaque; wipe with
   gq_kx_key_wipe when done.  */
typedef struct gq_kx_key
{
  uint16_t group;
  uint8_t share[GQ_KX_SHARE_MAX];	/* Client key share for the wire.  */
  size_t share_len;
  uint8_t secret[GQ_KX_SECRET_MAX];	/* Classical scalar, then ML-KEM key.  */
} gq_kx_key;

/* Sizes for GROUP in bytes, or 0 if the group is not supported.  */
size_t gq_kx_client_share_len (unsigned group);
size_t gq_kx_server_share_len (unsigned group);
size_t gq_kx_shared_len (unsigned group);

/* Generate an ephemeral key pair for GROUP.  GQ_ERR_UNSUPPORTED if the
   policy does not allow the group.  */
int gq_kx_generate (unsigned group, gq_kx_key *key);

/* Server side.  Consume CLIENT_SHARE, write the server share to
   SERVER_SHARE (CAP bytes) and the shared secret to SHARED (SHARED_CAP
   bytes).  GQ_ERR_ENCODING for a share of the wrong size,
   GQ_ERR_CRYPTO for an invalid point or a degenerate (all-zero) X25519
   result.  */
int gq_kx_respond (unsigned group, const uint8_t *client_share,
                   size_t client_len, uint8_t *server_share, size_t cap,
                   size_t *server_len, uint8_t *shared, size_t shared_cap,
                   size_t *shared_len);

/* Client side: derive the shared secret from the server's share.  */
int gq_kx_complete (const gq_kx_key *key, const uint8_t *server_share,
                    size_t server_len, uint8_t *shared, size_t shared_cap,
                    size_t *shared_len);

void gq_kx_key_wipe (gq_kx_key *key);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_KX_H */
