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
#include <gnuquic/stream.h>

#define RANGE_MAX 256

/* ---- Send half ---- */

void
gq_sstream_init (gq_sstream *s, size_t limit, uint64_t max_data)
{
  memset (s, 0, sizeof *s);
  s->limit = limit;
  s->max_data = max_data;
  gq_ranges_init (&s->acked, RANGE_MAX);
  gq_ranges_init (&s->lost, RANGE_MAX);
}

void
gq_sstream_free (gq_sstream *s)
{
  free (s->buf);
  gq_ranges_free (&s->acked);
  gq_ranges_free (&s->lost);
  s->buf = NULL;
  s->cap = s->len = 0;
}

size_t
gq_sstream_room (const gq_sstream *s)
{
  if (s->fin_set || s->reset)
    return 0;
  return s->limit - s->len;
}

long
gq_sstream_write (gq_sstream *s, const uint8_t *data, size_t len)
{
  size_t room;

  if (s->fin_set || s->reset)
    return GQ_ERR_INVAL;
  room = s->limit - s->len;
  if (len > room)
    len = room;
  if (len == 0)
    return 0;
  if (s->len + len > s->cap)
    {
      size_t cap = s->cap ? s->cap : 256;
      uint8_t *nb;

      while (cap < s->len + len)
        cap *= 2;
      if (cap > s->limit)
        cap = s->limit;
      nb = realloc (s->buf, cap);
      if (nb == NULL)
        return GQ_ERR_NOMEM;
      s->buf = nb;
      s->cap = cap;
    }
  memcpy (s->buf + s->len, data, len);
  s->len += len;
  return (long) len;
}

int
gq_sstream_finish (gq_sstream *s)
{
  if (s->reset)
    return GQ_ERR_INVAL;
  s->fin_set = 1;
  return GQ_OK;
}

void
gq_sstream_reset (gq_sstream *s, uint64_t err)
{
  if (s->reset || s->fin_acked)
    return;
  s->reset = 1;
  s->reset_pending = 1;
  s->reset_err = err;
  free (s->buf);
  s->buf = NULL;
  s->cap = s->len = 0;
  gq_ranges_clear (&s->acked);
  gq_ranges_clear (&s->lost);
}

void
gq_sstream_rewind (gq_sstream *s)
{
  if (s->reset)
    return;
  s->sent = s->base;
  s->fin_sent = s->fin_lost = 0;
  s->blocked_at = 0;
  gq_ranges_clear (&s->lost);
  gq_ranges_clear (&s->acked);
}

void
gq_sstream_set_max (gq_sstream *s, uint64_t max)
{
  if (max > s->max_data)
    s->max_data = max;
}

/* Offset just past the last byte written.  */
static uint64_t
end_of (const gq_sstream *s)
{
  return s->base + s->len;
}

int
gq_sstream_next (gq_sstream *s, size_t max, uint64_t conn_credit,
                 uint64_t *off, const uint8_t **data, size_t *len,
                 int *fin, uint64_t *new_bytes)
{
  uint64_t lo, hi, avail;

  *new_bytes = 0;
  if (s->reset)
    return 0;
  /* Lost data first.  */
  if (gq_ranges_pop_front (&s->lost, max, &lo, &hi))
    {
      *off = lo;
      *len = (size_t) (hi - lo);
      *data = s->buf + (lo - s->base);
      *fin = 0;
      if (s->fin_lost && s->fin_set && hi == end_of (s))
        {
          *fin = 1;
          s->fin_lost = 0;
        }
      return 1;
    }
  /* Then new data, within both credits.  */
  avail = end_of (s) - s->sent;
  if (avail > s->max_data - s->sent)
    avail = s->max_data - s->sent;
  if (avail > conn_credit)
    avail = conn_credit;
  if (avail > max)
    avail = max;
  if (avail > 0)
    {
      *off = s->sent;
      *len = (size_t) avail;
      *data = s->buf + (s->sent - s->base);
      s->sent += avail;
      *new_bytes = avail;
      *fin = 0;
      if (s->fin_set && !s->fin_sent && s->sent == end_of (s))
        {
          *fin = 1;
          s->fin_sent = 1;
        }
      return 1;
    }
  /* A FIN on its own, or one that must be sent again.  */
  if (s->fin_set && s->sent == end_of (s) && (!s->fin_sent || s->fin_lost))
    {
      *off = s->sent;
      *len = 0;
      *data = s->buf;
      *fin = 1;
      s->fin_sent = 1;
      s->fin_lost = 0;
      return 1;
    }
  return 0;
}

int
gq_sstream_pending (const gq_sstream *s, uint64_t conn_credit)
{
  if (s->reset)
    return s->reset_pending;
  if (s->lost.n)
    return 1;
  if (end_of (s) > s->sent && s->max_data > s->sent && conn_credit > 0)
    return 1;
  return s->fin_set && s->sent == end_of (s) && (!s->fin_sent || s->fin_lost);
}

void
gq_sstream_on_acked (gq_sstream *s, uint64_t off, size_t len, int fin)
{
  uint64_t hi = off + len;

  if (s->reset)
    return;
  if (fin)
    s->fin_acked = 1;
  if (hi > s->base)
    {
      if (off < s->base)
        off = s->base;
      gq_ranges_add (&s->acked, off, hi, 0);
      gq_ranges_remove (&s->lost, off, hi);
    }
  /* Free the acknowledged prefix.  */
  if (s->acked.n && s->acked.r[0].lo <= s->base)
    {
      uint64_t nb = s->acked.r[0].hi;
      size_t drop = (size_t) (nb - s->base);

      memmove (s->buf, s->buf + drop, s->len - drop);
      s->len -= drop;
      s->base = nb;
      gq_ranges_trim_below (&s->acked, nb);
      gq_ranges_trim_below (&s->lost, nb);
    }
}

void
gq_sstream_on_lost (gq_sstream *s, uint64_t off, size_t len, int fin)
{
  uint64_t hi = off + len;
  size_t i;

  if (s->reset)
    return;
  if (fin && !s->fin_acked)
    s->fin_lost = 1;
  if (off < s->base)
    off = s->base;
  if (off >= hi)
    return;
  gq_ranges_add (&s->lost, off, hi, 0);
  /* Anything acknowledged in the meantime need not be sent again.  */
  for (i = 0; i < s->acked.n; i++)
    gq_ranges_remove (&s->lost, s->acked.r[i].lo, s->acked.r[i].hi);
}

int
gq_sstream_take_reset (gq_sstream *s, uint64_t *err, uint64_t *final)
{
  if (!s->reset_pending)
    return 0;
  s->reset_pending = 0;
  *err = s->reset_err;
  *final = s->sent;
  return 1;
}

void
gq_sstream_reset_lost (gq_sstream *s)
{
  if (s->reset && !s->reset_acked)
    s->reset_pending = 1;
}

void
gq_sstream_reset_acked (gq_sstream *s)
{
  if (s->reset)
    s->reset_acked = 1;
}

int
gq_sstream_take_blocked (gq_sstream *s, uint64_t *limit)
{
  if (s->reset || end_of (s) <= s->sent || s->sent < s->max_data)
    return 0;
  if (s->blocked_at == s->max_data + 1)
    return 0;
  s->blocked_at = s->max_data + 1;
  *limit = s->max_data;
  return 1;
}

enum gq_send_state
gq_sstream_state (const gq_sstream *s)
{
  if (s->reset)
    return s->reset_acked ? GQ_SS_RESET_RECVD : GQ_SS_RESET_SENT;
  if (s->fin_acked && s->base == end_of (s))
    return GQ_SS_DATA_RECVD;
  if (s->fin_sent)
    return GQ_SS_DATA_SENT;
  if (s->sent > 0 || s->len > 0)
    return GQ_SS_SEND;
  return GQ_SS_READY;
}

/* ---- Receive half ---- */

void
gq_rstream_init (gq_rstream *s, uint64_t max_data)
{
  memset (s, 0, sizeof *s);
  s->max_data = max_data;
  s->max_sent = max_data;
  gq_ranges_init (&s->have, RANGE_MAX);
}

void
gq_rstream_free (gq_rstream *s)
{
  free (s->buf);
  gq_ranges_free (&s->have);
  s->buf = NULL;
  s->cap = 0;
}

enum gq_recv_state
gq_rstream_state (const gq_rstream *s)
{
  if (s->reset)
    return GQ_RS_RESET_RECVD;
  if (s->fin_delivered)
    return GQ_RS_DATA_READ;
  return s->final_known ? GQ_RS_SIZE_KNOWN : GQ_RS_RECV;
}

/* Hand [off, off + len) to the application, honouring STOP_SENDING.  */
static int
deliver (gq_rstream *s, const uint8_t *d, size_t len, gq_rstream_cb cb,
         void *user)
{
  int fin = s->final_known && s->off + len == s->final;
  int r;

  if (len == 0 && !(fin && !s->fin_delivered))
    return GQ_OK;
  if (!s->discard && cb)
    {
      s->off += len;		/* The callback may inspect the stream.  */
      if (fin)
        s->fin_delivered = 1;
      r = cb (user, s->off - len, d, len, fin);
      return r ? GQ_ERR_HANDLER : GQ_OK;
    }
  s->off += len;
  if (fin)
    s->fin_delivered = 1;
  return GQ_OK;
}

int
gq_rstream_push (gq_rstream *s, uint64_t off, const uint8_t *data,
                 size_t len, int fin, gq_rstream_cb cb, void *user,
                 uint64_t *new_bytes)
{
  uint64_t end = off + len;
  int r;

  if (new_bytes)
    *new_bytes = 0;
  if (end < off || end > s->max_data)
    return GQ_ERR_FLOW;
  if (fin)
    {
      if ((s->final_known && s->final != end) || end < s->highest)
        return GQ_ERR_FINAL_SIZE;
      s->final = end;
      s->final_known = 1;
    }
  else if (s->final_known && end > s->final)
    return GQ_ERR_FINAL_SIZE;
  if (s->reset)
    return GQ_OK;
  if (end > s->highest)
    {
      if (new_bytes)
        *new_bytes = end - s->highest;
      s->highest = end;
    }
  /* Drop what was delivered already.  */
  if (off < s->off)
    {
      uint64_t skip = s->off - off;

      if (skip >= len)
        {
          data += len;
          len = 0;
        }
      else
        {
          data += skip;
          len -= (size_t) skip;
        }
      off = s->off;
    }
  if (off == s->off && s->have.n == 0)
    return deliver (s, data, len, cb, user);
  if (len)
    {
      uint64_t need = end - s->off;

      if (need > s->cap)
        {
          size_t cap = s->cap ? s->cap : 512;
          uint8_t *nb;

          while (cap < need)
            cap *= 2;
          if (cap > s->max_data - s->off)
            cap = (size_t) (s->max_data - s->off);
          nb = realloc (s->buf, cap);
          if (nb == NULL)
            return GQ_ERR_NOMEM;
          s->buf = nb;
          s->cap = cap;
        }
      memcpy (s->buf + (off - s->off), data, len);
      r = gq_ranges_add (&s->have, off, end, 0);
      if (r == GQ_ERR_NOMEM)
        return r;
      /* A full set drops the range; the peer will send it again.  */
    }
  /* Deliver the prefix that is now contiguous.  */
  if (s->have.n && s->have.r[0].lo == s->off)
    {
      size_t n = (size_t) (s->have.r[0].hi - s->off);
      uint64_t start = s->off;

      gq_ranges_trim_below (&s->have, start + n);
      r = deliver (s, s->buf, n, cb, user);
      if (s->have.n)
        memmove (s->buf, s->buf + n,
                 (size_t) (s->have.r[s->have.n - 1].hi - s->off));
      else if (s->cap > 4096)
        {
          free (s->buf);
          s->buf = NULL;
          s->cap = 0;
        }
      return r;
    }
  if (len == 0 && fin)
    return deliver (s, data, 0, cb, user);
  return GQ_OK;
}

int
gq_rstream_reset (gq_rstream *s, uint64_t err, uint64_t final,
                  uint64_t *new_bytes)
{
  if (new_bytes)
    *new_bytes = 0;
  if (final > s->max_data)
    return GQ_ERR_FLOW;
  if ((s->final_known && s->final != final) || final < s->highest)
    return GQ_ERR_FINAL_SIZE;
  s->final = final;
  s->final_known = 1;
  if (s->fin_delivered || s->reset)
    return GQ_OK;
  if (final > s->highest)
    {
      if (new_bytes)
        *new_bytes = final - s->highest;
      s->highest = final;
    }
  s->reset = 1;
  s->reset_err = err;
  s->stop_pending = 0;
  free (s->buf);
  s->buf = NULL;
  s->cap = 0;
  gq_ranges_clear (&s->have);
  return GQ_OK;
}

void
gq_rstream_stop (gq_rstream *s, uint64_t err)
{
  if (s->reset || s->fin_delivered || s->discard)
    return;
  s->discard = 1;
  s->stop_pending = 1;
  s->stop_err = err;
}

int
gq_rstream_take_stop (gq_rstream *s, uint64_t *err)
{
  if (!s->stop_pending)
    return 0;
  s->stop_pending = 0;
  *err = s->stop_err;
  return 1;
}

void
gq_rstream_stop_lost (gq_rstream *s)
{
  if (s->discard && !s->reset && !s->fin_delivered)
    s->stop_pending = 1;
}

int
gq_rstream_take_update (gq_rstream *s, uint64_t window, uint64_t *max)
{
  if (s->reset || s->final_known)
    return 0;
  if (s->off + window > s->max_data && s->off + window - s->max_data >= window / 2)
    s->max_data = s->off + window;
  if (s->max_data <= s->max_sent)
    return 0;
  s->max_sent = s->max_data;
  *max = s->max_data;
  return 1;
}

void
gq_rstream_update_lost (gq_rstream *s, uint64_t max)
{
  if (max == s->max_sent && !s->final_known)
    s->max_sent = 0;
}
