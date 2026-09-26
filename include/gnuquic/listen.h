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

/* Admission of a client's first datagram, before any connection exists.

   A server endpoint routes datagrams for known connection IDs to their
   connections.  A datagram for an unknown ID that could start a
   connection goes through gq_quic_admit first.  It is stateless: from the
   datagram, the client's address and the token keys it decides to

     drop       the datagram is not a valid first Initial;
     reply      send back what it wrote to OUT: a Version Negotiation
                packet for a version we do not speak, or a Retry asking
                the client to prove its address;
     accept     create a connection with gq_conn_server_accept, passing
                the filled gq_conn_accept, and give it this datagram.

   With require_retry off, a client without a valid token is accepted
   unvalidated (the connection then obeys the anti-amplification limit and
   may issue NEW_TOKEN for next time); with it on, such a client gets a
   Retry.  A valid token, whichever kind, marks the client validated.  */

#ifndef GNUQUIC_LISTEN_H
#define GNUQUIC_LISTEN_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/conn.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_admit_config
{
  int require_retry;
  uint32_t retry_lifetime_s;	/* 0: 10 seconds.  */
  uint32_t new_token_lifetime_s;	/* 0: one day.  */
  size_t retry_cid_len;		/* Length of the ID chosen in a Retry;
				   0: 8.  */
  /* Versions the server speaks, for Version Negotiation; an Initial in
     any other version is answered with the list.  Empty: v1 and v2.  */
  uint32_t versions[GQ_TP_MAX_VERSIONS];
  size_t n_versions;
} gq_admit_config;

enum gq_admit_action
{
  GQ_ADMIT_DROP = 0,
  GQ_ADMIT_REPLY = 1,
  GQ_ADMIT_ACCEPT = 2
};

/* ADDR is the client's address as opaque bytes (at most 64), bound into
   tokens.  NOW_S is wall-clock seconds.  On GQ_ADMIT_REPLY, *REPLY_LEN
   bytes were written to OUT (capacity CAP, at least 1200 is plenty).  On
   GQ_ADMIT_ACCEPT, *ACCEPT is filled.  Returns the action, or a negative
   status for an internal failure.  DATA is not modified.  */
int gq_quic_admit (const gq_token_keys *keys, const gq_admit_config *cfg,
                   const uint8_t *addr, size_t addr_len, const uint8_t *data,
                   size_t len, uint64_t now_s, uint8_t *out, size_t cap,
                   size_t *reply_len, gq_conn_accept *accept);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_LISTEN_H */
