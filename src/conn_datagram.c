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

/* Unreliable DATAGRAM frames (RFC 9221): the send queue and the API.
   Receiving is in conn_recv.c and packing into packets in conn_send.c.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "conn_int.h"

struct dgram *
datagram_front (gq_conn *c)
{
  return &c->dq[c->dq_head];
}

void
datagram_pop (gq_conn *c)
{
  struct dgram *d = &c->dq[c->dq_head];

  c->dq_bytes -= d->len;
  free (d->data);
  d->data = NULL;
  c->dq_head++;
  c->dq_n--;
  if (c->dq_n == 0)
    c->dq_head = 0;
}

/* Datagrams still waiting when the connection ends were never sent.  */
void
datagrams_free (gq_conn *c)
{
  while (c->dq_n)
    {
      datagram_pop (c);
      c->datagrams_dropped++;
    }
  free (c->dq);
  c->dq = NULL;
  c->dq_cap = c->dq_head = 0;
}

size_t
gq_conn_datagram_max (const gq_conn *c)
{
  uint64_t peer, room;

  if (!c->have_peer_tp)
    return 0;
  peer = c->peer_tp.max_datagram_frame_size;
  if (peer == 0)
    return 0;
  /* One packet: a short header, the frame type and a two byte length.  */
  room = conn_max_datagram (c);
  room = room > 1 + c->dcid.len + 4 + GQ_AEAD_TAG_LEN + 1 + 2
         ? room - (1 + c->dcid.len + 4 + GQ_AEAD_TAG_LEN + 1 + 2) : 0;
  /* The peer's limit counts the whole frame.  */
  peer = peer > 3 ? peer - 3 : 0;
  return (size_t) (peer < room ? peer : room);
}

int
gq_conn_datagram_send (gq_conn *c, const uint8_t *data, size_t len,
                       uint64_t *id)
{
  struct dgram *d;
  uint8_t *copy;

  if (c->state != GQ_CONN_ESTABLISHED || gq_conn_datagram_max (c) == 0)
    return GQ_ERR_UNAVAILABLE;
  if (len > gq_conn_datagram_max (c))
    return GQ_ERR_RANGE;
  if (c->dq_bytes + len > c->cfg.datagram_queue)
    {
      c->datagrams_dropped++;
      return GQ_ERR_BUFSIZE;
    }
  if (c->dq_head + c->dq_n == c->dq_cap)
    {
      if (c->dq_head)
        {
          memmove (c->dq, c->dq + c->dq_head, c->dq_n * sizeof *c->dq);
          c->dq_head = 0;
        }
      else
        {
          size_t cap = c->dq_cap ? c->dq_cap * 2 : 16;
          struct dgram *nq = realloc (c->dq, cap * sizeof *nq);

          if (nq == NULL)
            return GQ_ERR_NOMEM;
          c->dq = nq;
          c->dq_cap = cap;
        }
    }
  copy = malloc (len ? len : 1);
  if (copy == NULL)
    return GQ_ERR_NOMEM;
  if (len)
    memcpy (copy, data, len);
  d = &c->dq[c->dq_head + c->dq_n++];
  d->data = copy;
  d->len = len;
  d->id = c->next_dgram_id++;
  c->dq_bytes += len;
  if (id)
    *id = d->id;
  conn_wake (c);
  return GQ_OK;
}
