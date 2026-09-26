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

#include "conn_int.h"

#define MAX_STREAMS_LIMIT ((uint64_t) 1 << 60)

/* Index into the per-type arrays: [1] bidirectional, [0] unidirectional.  */
#define TIDX(id) (((id) & 2) ? 0 : 1)

static int
locally_initiated (const gq_conn *c, uint64_t id)
{
  return (int) (id & 1) == (c->role == GQ_ROLE_SERVER);
}

/* ---- Table ---- */

static size_t
lower_bound (const gq_conn *c, uint64_t id)
{
  size_t lo = 0, hi = c->n_streams;

  while (lo < hi)
    {
      size_t mid = lo + (hi - lo) / 2;

      if (c->streams[mid]->id < id)
        lo = mid + 1;
      else
        hi = mid;
    }
  return lo;
}

stream *
stream_find (const gq_conn *c, uint64_t id)
{
  size_t i = lower_bound (c, id);

  return i < c->n_streams && c->streams[i]->id == id ? c->streams[i] : NULL;
}

uint64_t
stream_initial_send_credit (const gq_conn *c, uint64_t id)
{
  const gq_transport_params *p = &c->peer_tp;

  if (!c->have_peer_tp)
    return 0;
  if (id & 2)
    return p->initial_max_stream_data_uni;
  return locally_initiated (c, id) ? p->initial_max_stream_data_bidi_remote
                                   : p->initial_max_stream_data_bidi_local;
}

uint64_t
stream_initial_recv_credit (const gq_conn *c, uint64_t id)
{
  (void) id;
  return c->cfg.initial_max_stream_data;
}

static stream *
stream_create (gq_conn *c, uint64_t id)
{
  stream *st;
  size_t i;

  if (c->n_streams == c->cap_streams)
    {
      size_t cap = c->cap_streams ? c->cap_streams * 2 : 16;
      stream **nv = realloc (c->streams, cap * sizeof *nv);

      if (nv == NULL)
        return NULL;
      c->streams = nv;
      c->cap_streams = cap;
    }
  st = calloc (1, sizeof *st);
  if (st == NULL)
    return NULL;
  st->id = id;
  st->has_send = !(id & 2) || locally_initiated (c, id);
  st->has_recv = !(id & 2) || !locally_initiated (c, id);
  if (st->has_send)
    gq_sstream_init (&st->s, c->cfg.send_buffer,
                     stream_initial_send_credit (c, id));
  if (st->has_recv)
    gq_rstream_init (&st->r, stream_initial_recv_credit (c, id));
  i = lower_bound (c, id);
  memmove (&c->streams[i + 1], &c->streams[i],
           (c->n_streams - i) * sizeof *c->streams);
  c->streams[i] = st;
  c->n_streams++;
  return st;
}

static void
stream_destroy (stream *st)
{
  if (st->has_send)
    gq_sstream_free (&st->s);
  if (st->has_recv)
    gq_rstream_free (&st->r);
  free (st);
}

void
streams_free (gq_conn *c)
{
  size_t i;

  for (i = 0; i < c->n_streams; i++)
    stream_destroy (c->streams[i]);
  free (c->streams);
  c->streams = NULL;
  c->n_streams = c->cap_streams = 0;
}

void
streams_apply_peer_params (gq_conn *c)
{
  size_t i;

  for (i = 0; i < c->n_streams; i++)
    if (c->streams[i]->has_send)
      gq_sstream_set_max (&c->streams[i]->s,
                          stream_initial_send_credit (c, c->streams[i]->id));
}

/* Release a stream whose halves have both finished.  */
void
stream_remove_if_done (gq_conn *c, stream *st)
{
  size_t i;
  uint64_t id = st->id;

  if (st->has_send)
    {
      enum gq_send_state s = gq_sstream_state (&st->s);

      if (s != GQ_SS_DATA_RECVD && s != GQ_SS_RESET_RECVD)
        return;
    }
  if (st->has_recv)
    {
      enum gq_recv_state r = gq_rstream_state (&st->r);

      if (r != GQ_RS_DATA_READ && r != GQ_RS_RESET_RECVD)
        return;
    }
  i = lower_bound (c, id);
  memmove (&c->streams[i], &c->streams[i + 1],
           (c->n_streams - i - 1) * sizeof *c->streams);
  c->n_streams--;
  if (c->rr > i)
    c->rr--;
  stream_destroy (st);
  if (!locally_initiated (c, id))
    {
      /* Let the peer open another stream of this kind.  */
      c->max_streams_local[TIDX (id)]++;
    }
  if (c->ev.stream_closed)
    c->ev.stream_closed (c->ev.user, id);
}

void
stream_on_acked (gq_conn *c, uint64_t id)
{
  stream *st = stream_find (c, id);

  if (st == NULL || !st->has_send)
    return;
  if (st->full && gq_sstream_room (&st->s) > 0)
    {
      st->full = 0;
      if (c->ev.stream_writable)
        c->ev.stream_writable (c->ev.user, id);
      st = stream_find (c, id);
      if (st == NULL)
        return;
    }
  stream_remove_if_done (c, st);
}

/* Find or create the stream a frame refers to.  Returns NULL with no
   error for a stream that is already closed, and NULL with the connection
   failed for an illegal one.  */
stream *
stream_for_frame (gq_conn *c, uint64_t id, int for_send)
{
  stream *st = stream_find (c, id);
  int t = TIDX (id);
  uint64_t idx = id >> 2;

  (void) for_send;
  if (st)
    return st;
  if (locally_initiated (c, id))
    {
      if (idx >= c->next_local_stream[t])
        conn_fail (c, GQ_QERR_STREAM_STATE, "frame for unopened stream");
      return NULL;
    }
  if (idx >= c->max_streams_local[t])
    {
      conn_fail (c, GQ_QERR_STREAM_LIMIT, "stream limit exceeded");
      return NULL;
    }
  if (idx < c->next_peer_stream[t])
    return NULL;			/* Closed.  */
  /* Opening a stream opens all lower ones of its type.  */
  while (c->next_peer_stream[t] <= idx)
    {
      uint64_t nid = (c->next_peer_stream[t] << 2) | (uint64_t) (id & 3);

      st = stream_create (c, nid);
      if (st == NULL)
        {
          conn_fail (c, GQ_QERR_INTERNAL, "out of memory");
          return NULL;
        }
      c->next_peer_stream[t]++;
      if (c->ev.stream_opened)
        c->ev.stream_opened (c->ev.user, nid);
      /* The application may have closed things down meanwhile.  */
      if (c->state >= GQ_CONN_CLOSING)
        return NULL;
    }
  return stream_find (c, id);
}

/* ---- Frames from the peer ---- */

typedef struct deliver_user
{
  gq_conn *c;
  uint64_t id;
} deliver_user;

static int
stream_deliver (void *user, uint64_t off, const uint8_t *data, size_t len,
                int fin)
{
  deliver_user *u = user;

  (void) off;
  if (u->c->ev.stream_data == NULL)
    return 0;
  return u->c->ev.stream_data (u->c->ev.user, u->id, data, len, fin);
}

static int
check_conn_credit (gq_conn *c, uint64_t add)
{
  if (add > c->max_data_local || c->data_recv_total > c->max_data_local - add)
    {
      conn_fail (c, GQ_QERR_FLOW_CONTROL, "connection flow control");
      return 1;
    }
  return 0;
}

static int
map_stream_error (gq_conn *c, int r)
{
  switch (r)
    {
    case GQ_OK:
      return 0;
    case GQ_ERR_FLOW:
      conn_fail (c, GQ_QERR_FLOW_CONTROL, "stream flow control");
      break;
    case GQ_ERR_FINAL_SIZE:
      conn_fail (c, GQ_QERR_FINAL_SIZE, "final size violated");
      break;
    case GQ_ERR_HANDLER:
      conn_fail (c, GQ_QERR_INTERNAL, "application aborted");
      break;
    default:
      conn_fail (c, GQ_QERR_INTERNAL, "stream failure");
      break;
    }
  return 1;
}

int
stream_handle_frame (gq_conn *c, const gq_frame *f)
{
  stream *st;
  uint64_t id, nb, before;
  int r;

  switch (f->type)
    {
    case GQ_FRAME_STREAM:
      {
        deliver_user u;
        uint64_t end, know;

        id = f->u.stream.id;
        if ((id & 2) && locally_initiated (c, id))
          {
            conn_fail (c, GQ_QERR_STREAM_STATE, "STREAM on send-only stream");
            return 1;
          }
        st = stream_for_frame (c, id, 0);
        if (st == NULL)
          return c->state >= GQ_CONN_CLOSING;
        end = f->u.stream.offset + f->u.stream.data.len;
        know = st->r.highest;
        if (end > know && check_conn_credit (c, end - know))
          return 1;
        u.c = c;
        u.id = id;
        before = st->r.off;
        r = gq_rstream_push (&st->r, f->u.stream.offset, f->u.stream.data.data,
                             f->u.stream.data.len, f->u.stream.fin,
                             stream_deliver, &u, &nb);
        c->data_recv_total += nb;
        /* The callback may have released the stream; look it up again.  */
        st = stream_find (c, id);
        if (st)
          c->data_consumed += st->r.off - before;
        if (map_stream_error (c, r))
          return 1;
        if (st)
          stream_remove_if_done (c, st);
        return c->state >= GQ_CONN_CLOSING;
      }
    case GQ_FRAME_RESET_STREAM:
      id = f->u.reset_stream.id;
      if ((id & 2) && locally_initiated (c, id))
        {
          conn_fail (c, GQ_QERR_STREAM_STATE, "RESET_STREAM on send-only");
          return 1;
        }
      st = stream_for_frame (c, id, 0);
      if (st == NULL)
        return c->state >= GQ_CONN_CLOSING;
      {
        int was = gq_rstream_state (&st->r) == GQ_RS_RESET_RECVD
                  || gq_rstream_state (&st->r) == GQ_RS_DATA_READ;
        uint64_t off = st->r.off;

        if (f->u.reset_stream.final_size > st->r.highest
            && check_conn_credit (c, f->u.reset_stream.final_size
                                     - st->r.highest))
          return 1;
        r = gq_rstream_reset (&st->r, f->u.reset_stream.error,
                              f->u.reset_stream.final_size, &nb);
        if (map_stream_error (c, r))
          return 1;
        c->data_recv_total += nb;
        if (!was)
          {
            c->data_consumed += st->r.final - off;
            if (c->ev.stream_reset)
              c->ev.stream_reset (c->ev.user, id, f->u.reset_stream.error);
            st = stream_find (c, id);
            if (st)
              stream_remove_if_done (c, st);
          }
      }
      return c->state >= GQ_CONN_CLOSING;
    case GQ_FRAME_STOP_SENDING:
      id = f->u.stop_sending.id;
      if ((id & 2) && !locally_initiated (c, id))
        {
          conn_fail (c, GQ_QERR_STREAM_STATE, "STOP_SENDING on receive-only");
          return 1;
        }
      st = stream_for_frame (c, id, 1);
      if (st == NULL)
        return c->state >= GQ_CONN_CLOSING;
      if (st->has_send && gq_sstream_state (&st->s) != GQ_SS_DATA_RECVD
          && gq_sstream_state (&st->s) != GQ_SS_RESET_SENT
          && gq_sstream_state (&st->s) != GQ_SS_RESET_RECVD)
        {
          gq_sstream_reset (&st->s, f->u.stop_sending.error);
          if (c->ev.stream_stopped)
            c->ev.stream_stopped (c->ev.user, id, f->u.stop_sending.error);
        }
      return c->state >= GQ_CONN_CLOSING;
    case GQ_FRAME_MAX_DATA:
      if (f->u.max_data.max > c->max_data_peer)
        c->max_data_peer = f->u.max_data.max;
      return 0;
    case GQ_FRAME_MAX_STREAM_DATA:
      id = f->u.max_stream_data.id;
      if ((id & 2) && !locally_initiated (c, id))
        {
          conn_fail (c, GQ_QERR_STREAM_STATE, "MAX_STREAM_DATA on recv-only");
          return 1;
        }
      st = stream_for_frame (c, id, 1);
      if (st && st->has_send)
        gq_sstream_set_max (&st->s, f->u.max_stream_data.max);
      return c->state >= GQ_CONN_CLOSING;
    case GQ_FRAME_MAX_STREAMS:
      if (f->u.max_streams.max > MAX_STREAMS_LIMIT)
        {
          conn_fail (c, GQ_QERR_FRAME_ENCODING, "MAX_STREAMS too large");
          return 1;
        }
      {
        int t = f->u.max_streams.bidi ? 1 : 0;

        if (f->u.max_streams.max > c->max_streams_peer[t])
          c->max_streams_peer[t] = f->u.max_streams.max;
      }
      return 0;
    case GQ_FRAME_STREAM_DATA_BLOCKED:
      id = f->u.stream_data_blocked.id;
      if ((id & 2) && locally_initiated (c, id))
        {
          conn_fail (c, GQ_QERR_STREAM_STATE, "blocked on send-only stream");
          return 1;
        }
      stream_for_frame (c, id, 0);
      return c->state >= GQ_CONN_CLOSING;
    case GQ_FRAME_DATA_BLOCKED:
    case GQ_FRAME_STREAMS_BLOCKED:
      return 0;
    default:
      return 0;
    }
}

/* ---- Application interface ---- */

int
gq_conn_stream_open (gq_conn *c, int bidi, uint64_t *id)
{
  int t = bidi ? 1 : 0;
  uint64_t nid;
  stream *st;

  if (c->state != GQ_CONN_ESTABLISHED && !(c->state == GQ_CONN_HANDSHAKE
                                            && c->have_peer_tp))
    return GQ_ERR_INVAL;
  if (c->next_local_stream[t] >= c->max_streams_peer[t])
    {
      c->streams_blocked_pending[t] = 1;
      return GQ_ERR_RANGE;
    }
  nid = (c->next_local_stream[t] << 2) | (bidi ? 0 : 2)
        | (uint64_t) (c->role == GQ_ROLE_SERVER);
  st = stream_create (c, nid);
  if (st == NULL)
    return GQ_ERR_NOMEM;
  c->next_local_stream[t]++;
  *id = nid;
  return GQ_OK;
}

uint64_t
gq_conn_streams_available (const gq_conn *c, int bidi)
{
  int t = bidi ? 1 : 0;

  return c->max_streams_peer[t] > c->next_local_stream[t]
         ? c->max_streams_peer[t] - c->next_local_stream[t] : 0;
}

long
gq_conn_stream_write (gq_conn *c, uint64_t id, const uint8_t *data,
                      size_t len)
{
  stream *st = stream_find (c, id);
  long w;

  if (st == NULL || !st->has_send || c->state >= GQ_CONN_CLOSING)
    return GQ_ERR_INVAL;
  w = gq_sstream_write (&st->s, data, len);
  if (w >= 0 && (size_t) w < len)
    st->full = 1;
  return w;
}

int
gq_conn_stream_finish (gq_conn *c, uint64_t id)
{
  stream *st = stream_find (c, id);

  if (st == NULL || !st->has_send)
    return GQ_ERR_INVAL;
  return gq_sstream_finish (&st->s);
}

int
gq_conn_stream_reset (gq_conn *c, uint64_t id, uint64_t error)
{
  stream *st = stream_find (c, id);

  if (st == NULL || !st->has_send)
    return GQ_ERR_INVAL;
  gq_sstream_reset (&st->s, error);
  return GQ_OK;
}

int
gq_conn_stream_stop_sending (gq_conn *c, uint64_t id, uint64_t error)
{
  stream *st = stream_find (c, id);

  if (st == NULL || !st->has_recv)
    return GQ_ERR_INVAL;
  gq_rstream_stop (&st->r, error);
  return GQ_OK;
}

size_t
gq_conn_stream_room (const gq_conn *c, uint64_t id)
{
  stream *st = stream_find (c, id);

  return st && st->has_send ? gq_sstream_room (&st->s) : 0;
}
