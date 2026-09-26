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

/* Stateless DTLS 1.2 cookie exchange for servers (RFC 6347 section 4.2.1).

   The DTLS 1.2 counterpart of gq_dtls_listen: in front of the
   associations, it answers the first datagram from an address without
   one.  It returns

     GQ_DTLS_LISTEN_DROP    nothing to do;
     GQ_DTLS_LISTEN_REPLY   REPLY holds a HelloVerifyRequest, and nothing
                            has been remembered;
     GQ_DTLS_LISTEN_ACCEPT  a ClientHello carrying a valid cookie: create
                            the association with gq_dtls12_server_new
                            (..., PRIME) and give it this datagram.

   The cookie is HMAC-SHA256 over the address binding and the parts of
   the ClientHello that must not change between the two hellos (random,
   session ID and cipher suites), keyed by the rotating secrets of
   dtlscookie.h (whose gq_dtls_cookies is used here too).  So nothing is
   stored, a cookie is useless from another address, and the reply is
   smaller than the request.  As RFC 6347 requires, the HelloVerifyRequest
   uses the record sequence number of the ClientHello.

   Only the first fragment of the ClientHello need hold the fields the
   cookie covers, which it always does.  */

#ifndef GNUQUIC_DTLS12COOKIE_H
#define GNUQUIC_DTLS12COOKIE_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/dtls12.h>
#include <gnuquic/dtlscookie.h>

#ifdef __cplusplus
extern "C" {
#endif

/* REPLY needs GQ_DTLS_LISTEN_REPLY_MAX bytes.  Returns the result, or a
   negative status for bad arguments.  */
int gq_dtls12_listen (gq_dtls_cookies *ck, const uint8_t *binding,
                      size_t binding_len, const uint8_t *dgram, size_t len,
                      uint8_t *reply, size_t reply_cap, size_t *reply_len,
                      gq_dtls12_prime *prime);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_DTLS12COOKIE_H */
