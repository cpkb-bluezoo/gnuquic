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

/* Building datagrams: what goes into each packet, coalescing, padding,
   protection and the bookkeeping recovery needs.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "conn_int.h"

#define MAX_DGRAM 2048
#define ACK_RANGES_MAX 24
#define MIN_PACKET_ROOM 40	/* Not worth starting a packet in less.  */

/* One packet under construction.  */
typedef struct pk
{
  int sp;
  uint8_t pl[MAX_DGRAM];
  size_t cap, len;
  sent_frame sf[MAX_FRAMES_PER_PACKET];
  unsigned nsf;
  int ae;			/* Contains an ack-eliciting frame.  */
  int closing;
  size_t hdr_est;		/* Header estimate used to size cap.  */
} pk;

static size_t
room (const pk *p)
{
  return p->cap - p->len;
}

static int
add (pk *p, const gq_frame *f, int ae, const sent_frame *e)
{
  size_t w;

  if (e && p->nsf >= MAX_FRAMES_PER_PACKET)
    return -1;
  if (gq_frame_write (f, p->pl + p->len, room (p), &w) != GQ_OK)
    return -1;
  p->len += w;
  if (ae)
    p->ae = 1;
  if (e)
    p->sf[p->nsf++] = *e;
  return 0;
}

static uint64_t
window_credit (uint64_t max, uint64_t used)
{
  return max > used ? max - used : 0;
}

/* ---- What is waiting to be sent? ---- */

static int
stream_wants (const gq_conn *c, stream *st)
{
  uint64_t lim;

  if (st->has_send)
    {
      if (gq_sstream_pending (&st->s, window_credit (c->max_data_peer,
                                                      c->data_sent)))
        return 1;
      if (!st->s.reset && st->s.sent >= st->s.max_data
          && st->s.blocked_at != st->s.max_data + 1
          && st->s.len + st->s.base > st->s.sent)
        return 1;
      (void) lim;
    }
  if (st->has_recv)
    {
      if (st->r.stop_pending)
        return 1;
      if (!st->r.final_known && !st->r.reset
          && st->r.max_data > st->r.max_sent)
        return 1;
      if (!st->r.final_known && !st->r.reset
          && st->r.off + c->cfg.initial_max_stream_data > st->r.max_data
          && st->r.off + c->cfg.initial_max_stream_data - st->r.max_data
             >= c->cfg.initial_max_stream_data / 2)
        return 1;
    }
  return 0;
}

static int
conn_update_wanted (const gq_conn *c)
{
  uint64_t w = c->cfg.initial_max_data;

  return c->max_data_local > c->max_data_sent
         || (c->data_consumed + w > c->max_data_local
             && c->data_consumed + w - c->max_data_local >= w / 2);
}

static int
app_pending (gq_conn *c)
{
  size_t i;

  if (c->handshake_done_pending || c->new_token_pending || c->n_path_response || conn_update_wanted (c))
    return 1;
  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].need_send)
      return 1;
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].retire == 1)
      return 1;
  if (c->max_streams_local[0] > c->max_streams_local_sent[0]
      || c->max_streams_local[1] > c->max_streams_local_sent[1])
    return 1;
  for (i = 0; i < c->n_streams; i++)
    if (stream_wants (c, c->streams[i]))
      return 1;
  return 0;
}

int
conn_have_work (gq_conn *c, int sp)
{
  space *s = &c->sp[sp];

  if (s->discarded || !s->have_wk)
    return 0;
  if (s->ack_now || s->probes)
    return 1;
  if (conn_can_send_ae (c))
    {
      if (gq_sstream_pending (&s->cs, UINT64_MAX))
        return 1;
      if (sp == SP_APP && app_pending (c))
        return 1;
    }
  return 0;
}

/* ---- Frames ---- */

static void
add_ack (gq_conn *c, pk *p, uint64_t now)
{
  space *s = &c->sp[p->sp];
  gq_ack_range r[ACK_RANGES_MAX];
  uint8_t enc[ACK_RANGES_MAX * 16];
  size_t n = 0, i, w;
  gq_frame f;
  unsigned e = 3;			/* Our ack_delay_exponent.  */

  if (!s->ack_pending || s->recv.n == 0)
    {
      s->ack_pending = s->ack_now = 0;
      return;
    }
  for (i = s->recv.n; i > 0 && n < ACK_RANGES_MAX; i--, n++)
    {
      r[n].lo = s->recv.r[i - 1].lo;
      r[n].hi = s->recv.r[i - 1].hi - 1;
    }
  while (n > 0)
    {
      if (gq_ack_ranges_encode (r, n, enc, sizeof enc, &w) == GQ_OK)
        break;
      n--;
    }
  if (n == 0)
    return;
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_ACK;
  f.u.ack.largest = r[0].hi;
  f.u.ack.delay = (now > s->largest_recv_time
                   ? now - s->largest_recv_time : 0) >> e;
  f.u.ack.range_count = n - 1;
  f.u.ack.ranges.data = enc;
  f.u.ack.ranges.len = w;
  if (add (p, &f, 0, NULL) == 0)
    {
      s->ack_pending = s->ack_now = 0;
      s->ack_deadline = 0;
      s->ae_since_ack = 0;
    }
}

static void
add_crypto (gq_conn *c, pk *p)
{
  space *s = &c->sp[p->sp];
  uint64_t off, nb;
  const uint8_t *d;
  size_t n;
  int fin;

  while (room (p) > 16 && p->nsf < MAX_FRAMES_PER_PACKET)
    {
      gq_frame f;
      sent_frame e;

      if (!gq_sstream_next (&s->cs, room (p) - 11, UINT64_MAX, &off, &d, &n,
                            &fin, &nb))
        break;
      memset (&f, 0, sizeof f);
      f.type = GQ_FRAME_CRYPTO;
      f.u.crypto.offset = off;
      f.u.crypto.data.data = d;
      f.u.crypto.data.len = n;
      memset (&e, 0, sizeof e);
      e.type = SF_CRYPTO;
      e.a = off;
      e.len = (uint32_t) n;
      if (add (p, &f, 1, &e))
        {
          gq_sstream_on_lost (&s->cs, off, n, 0);
          break;
        }
    }
}

/* Simple one-value control frames.  */
static int
add_simple (pk *p, enum gq_frame_type t, uint64_t v1, uint64_t v2,
            const sent_frame *e)
{
  gq_frame f;

  memset (&f, 0, sizeof f);
  f.type = t;
  switch (t)
    {
    case GQ_FRAME_MAX_DATA:		f.u.max_data.max = v1; break;
    case GQ_FRAME_MAX_STREAM_DATA:
      f.u.max_stream_data.id = v1;
      f.u.max_stream_data.max = v2;
      break;
    case GQ_FRAME_DATA_BLOCKED:		f.u.data_blocked.limit = v1; break;
    case GQ_FRAME_STREAM_DATA_BLOCKED:
      f.u.stream_data_blocked.id = v1;
      f.u.stream_data_blocked.limit = v2;
      break;
    case GQ_FRAME_STOP_SENDING:
      f.u.stop_sending.id = v1;
      f.u.stop_sending.error = v2;
      break;
    case GQ_FRAME_RETIRE_CONNECTION_ID:
      f.u.retire_connection_id.seq = v1;
      break;
    default:
      break;
    }
  return add (p, &f, 1, e);
}

static void
add_stream_control (gq_conn *c, pk *p, stream *st)
{
  sent_frame e;
  uint64_t v, err, fin;
  gq_frame f;

  memset (&e, 0, sizeof e);
  if (st->has_send)
    {
      if (st->s.reset_pending && room (p) >= 26)
        {
          gq_sstream_take_reset (&st->s, &err, &fin);
          memset (&f, 0, sizeof f);
          f.type = GQ_FRAME_RESET_STREAM;
          f.u.reset_stream.id = st->id;
          f.u.reset_stream.error = err;
          f.u.reset_stream.final_size = fin;
          e.type = SF_RESET_STREAM;
          e.a = st->id;
          if (add (p, &f, 1, &e))
            gq_sstream_reset_lost (&st->s);
        }
      if (room (p) >= 20 && gq_sstream_take_blocked (&st->s, &v))
        {
          e.type = SF_STREAM_DATA_BLOCKED;
          e.a = st->id;
          e.b = v;
          if (add_simple (p, GQ_FRAME_STREAM_DATA_BLOCKED, st->id, v, &e))
            st->s.blocked_at = 0;
        }
    }
  if (st->has_recv)
    {
      if (room (p) >= 20 && gq_rstream_take_stop (&st->r, &err))
        {
          e.type = SF_STOP_SENDING;
          e.a = st->id;
          if (add_simple (p, GQ_FRAME_STOP_SENDING, st->id, err, &e))
            gq_rstream_stop_lost (&st->r);
        }
      if (room (p) >= 20
          && gq_rstream_take_update (&st->r, c->cfg.initial_max_stream_data,
                                     &v))
        {
          e.type = SF_MAX_STREAM_DATA;
          e.a = st->id;
          e.b = v;
          if (add_simple (p, GQ_FRAME_MAX_STREAM_DATA, st->id, v, &e))
            gq_rstream_update_lost (&st->r, v);
        }
    }
}

static void
add_stream_data (gq_conn *c, pk *p, stream *st)
{
  uint64_t off, nb;
  const uint8_t *d;
  size_t n;
  int fin;

  if (!st->has_send)
    return;
  while (room (p) > 24 && p->nsf < MAX_FRAMES_PER_PACKET)
    {
      gq_frame f;
      sent_frame e;
      size_t over = 1 + gq_varint_size (st->id) + 8 + 2;

      if (room (p) <= over)
        break;
      if (!gq_sstream_next (&st->s, room (p) - over,
                            window_credit (c->max_data_peer, c->data_sent),
                            &off, &d, &n, &fin, &nb))
        break;
      memset (&f, 0, sizeof f);
      f.type = GQ_FRAME_STREAM;
      f.u.stream.id = st->id;
      f.u.stream.offset = off;
      f.u.stream.data.data = d;
      f.u.stream.data.len = n;
      f.u.stream.fin = fin;
      memset (&e, 0, sizeof e);
      e.type = SF_STREAM;
      e.a = st->id;
      e.b = off;
      e.len = (uint32_t) n;
      e.fin = (uint8_t) fin;
      if (add (p, &f, 1, &e))
        {
          gq_sstream_on_lost (&st->s, off, n, fin);
          break;
        }
      c->data_sent += nb;
    }
}

static void
add_app_frames (gq_conn *c, pk *p)
{
  size_t i, start;
  sent_frame e;
  gq_frame f;

  memset (&e, 0, sizeof e);
  if (c->handshake_done_pending && room (p) >= 1)
    {
      memset (&f, 0, sizeof f);
      f.type = GQ_FRAME_HANDSHAKE_DONE;
      e.type = SF_HANDSHAKE_DONE;
      if (add (p, &f, 1, &e) == 0)
        c->handshake_done_pending = 0;
    }
  if (c->new_token_pending && room (p) >= GQ_TOKEN_MAX + 8)
    {
      uint8_t tok[GQ_TOKEN_MAX];
      size_t tl;

      if (gq_token_make (c->token_keys, GQ_TOKEN_NEW_TOKEN, c->addr,
                         c->addr_len, NULL, NULL, conn_wall_seconds (c), tok,
                         &tl) == GQ_OK)
        {
          memset (&f, 0, sizeof f);
          f.type = GQ_FRAME_NEW_TOKEN;
          f.u.new_token.token.data = tok;
          f.u.new_token.token.len = tl;
          memset (&e, 0, sizeof e);
          e.type = SF_NEW_TOKEN;
          if (add (p, &f, 1, &e) == 0)
            c->new_token_pending = 0;
        }
      else
        c->new_token_pending = 0;
    }
  for (i = 0; i < c->n_path_response; i++)
    if (room (p) >= 9)
      {
        memset (&f, 0, sizeof f);
        f.type = GQ_FRAME_PATH_RESPONSE;
        memcpy (f.u.path_challenge.data, c->path_response[i], 8);
        add (p, &f, 1, NULL);
      }
  c->n_path_response = 0;
  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].need_send && room (p) >= 40)
      {
        memset (&f, 0, sizeof f);
        f.type = GQ_FRAME_NEW_CONNECTION_ID;
        f.u.new_connection_id.seq = c->l[i].seq;
        f.u.new_connection_id.cid_len = c->l[i].cid.len;
        memcpy (f.u.new_connection_id.cid, c->l[i].cid.data, c->l[i].cid.len);
        memcpy (f.u.new_connection_id.reset_token, c->l[i].token,
                GQ_RESET_TOKEN_LEN);
        memset (&e, 0, sizeof e);
        e.type = SF_NEW_CID;
        e.a = c->l[i].seq;
        if (add (p, &f, 1, &e) == 0)
          c->l[i].need_send = 0;
      }
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].retire == 1 && room (p) >= 12)
      {
        memset (&e, 0, sizeof e);
        e.type = SF_RETIRE_CID;
        e.a = c->p[i].seq;
        if (add_simple (p, GQ_FRAME_RETIRE_CONNECTION_ID, c->p[i].seq, 0, &e)
            == 0)
          c->p[i].retire = 2;
      }
  /* Connection-level credit.  */
  {
    uint64_t w = c->cfg.initial_max_data;

    if (c->data_consumed + w > c->max_data_local
        && c->data_consumed + w - c->max_data_local >= w / 2)
      c->max_data_local = c->data_consumed + w;
  }
  if (c->max_data_local > c->max_data_sent && room (p) >= 10)
    {
      memset (&e, 0, sizeof e);
      e.type = SF_MAX_DATA;
      e.a = c->max_data_local;
      if (add_simple (p, GQ_FRAME_MAX_DATA, c->max_data_local, 0, &e) == 0)
        c->max_data_sent = c->max_data_local;
    }
  for (i = 0; i < 2; i++)
    if (c->max_streams_local[i] > c->max_streams_local_sent[i]
        && room (p) >= 10)
      {
        memset (&f, 0, sizeof f);
        f.type = GQ_FRAME_MAX_STREAMS;
        f.u.max_streams.bidi = (int) i;
        f.u.max_streams.max = c->max_streams_local[i];
        memset (&e, 0, sizeof e);
        e.type = SF_MAX_STREAMS;
        e.a = i;
        e.b = c->max_streams_local[i];
        if (add (p, &f, 1, &e) == 0)
          c->max_streams_local_sent[i] = c->max_streams_local[i];
      }
  if (c->data_sent >= c->max_data_peer && c->blocked_sent_at
      != c->max_data_peer + 1 && room (p) >= 10)
    {
      size_t k;
      int want = 0;

      for (k = 0; k < c->n_streams; k++)
        if (c->streams[k]->has_send
            && c->streams[k]->s.len + c->streams[k]->s.base
               > c->streams[k]->s.sent)
          want = 1;
      if (want)
        {
          memset (&e, 0, sizeof e);
          e.type = SF_DATA_BLOCKED;
          e.a = c->max_data_peer;
          if (add_simple (p, GQ_FRAME_DATA_BLOCKED, c->max_data_peer, 0, &e)
              == 0)
            c->blocked_sent_at = c->max_data_peer + 1;
        }
    }
  /* Streams, starting one further along each time for fairness.  */
  start = c->n_streams ? c->rr % c->n_streams : 0;
  for (i = 0; i < c->n_streams; i++)
    add_stream_control (c, p, c->streams[(start + i) % c->n_streams]);
  for (i = 0; i < c->n_streams; i++)
    add_stream_data (c, p, c->streams[(start + i) % c->n_streams]);
  if (c->n_streams)
    c->rr = (start + 1) % c->n_streams;
}

/* ---- Packet assembly ---- */

static size_t
overhead_of (const gq_conn *c, int sp)
{
  size_t pn = 4;

  if (sp == SP_APP)
    return 1 + c->dcid.len + pn + GQ_AEAD_TAG_LEN;
  /* First byte, version, both connection IDs with their lengths, the
     token length, a two-byte Length, the packet number, the tag.  */
  return 1 + 4 + 1 + c->dcid.len + 1 + c->scid_first.len
         + (sp == SP_INITIAL ? gq_varint_size (c->token_len) + c->token_len : 0)
         + 2 + pn + GQ_AEAD_TAG_LEN;
}

static void
add_close (gq_conn *c, pk *p)
{
  gq_frame f;
  int app = c->close_app;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_CONNECTION_CLOSE;
  /* Handshake packets cannot carry application errors.  */
  if (p->sp != SP_APP && app)
    {
      f.u.connection_close.application = 0;
      f.u.connection_close.error = GQ_QERR_APPLICATION;
    }
  else
    {
      f.u.connection_close.application = app;
      f.u.connection_close.error = c->close_err;
      if (p->sp != SP_APP || !app)
        {
          f.u.connection_close.reason.data
            = (const uint8_t *) c->close_reason;
          f.u.connection_close.reason.len = c->close_reason_len;
        }
    }
  if (app && p->sp == SP_APP)
    {
      f.u.connection_close.reason.data = (const uint8_t *) c->close_reason;
      f.u.connection_close.reason.len = c->close_reason_len;
    }
  f.u.connection_close.frame_type = c->close_frame;
  add (p, &f, 0, NULL);
  p->closing = 1;
}

/* Fill P with what SP has to say.  Returns 1 if there is a packet.  */
static int
assemble (gq_conn *c, int sp, uint64_t now, size_t budget, pk *p)
{
  space *s = &c->sp[sp];
  size_t ov = overhead_of (c, sp);

  if (budget < ov + MIN_PACKET_ROOM)
    return 0;
  memset (&p->sf, 0, 0);
  p->sp = sp;
  p->len = 0;
  p->nsf = 0;
  p->ae = 0;
  p->closing = 0;
  p->cap = budget - ov;
  p->hdr_est = ov;
  if (c->state == GQ_CONN_CLOSING)
    {
      add_close (c, p);
      return p->len > 0;
    }
  if (!conn_have_work (c, sp))
    return 0;
  add_ack (c, p, now);
  if (conn_can_send_ae (c) || s->probes)
    {
      add_crypto (c, p);
      if (sp == SP_APP)
        add_app_frames (c, p);
    }
  if (s->probes)
    {
      if (!p->ae && room (p) >= 1)
        {
          gq_frame f;

          memset (&f, 0, sizeof f);
          f.type = GQ_FRAME_PING;
          add (p, &f, 1, NULL);
        }
      if (p->ae)
        s->probes--;
    }
  return p->len > 0;
}

/* ---- Sealing ---- */

static size_t
hdr_len_for (const gq_conn *c, int sp, size_t payload_len, size_t pn_len,
             uint64_t pn)
{
  uint8_t tmp[128];
  size_t h = 0;

  if (sp == SP_APP)
    gq_short_header_build (c->dcid.data, c->dcid.len, 0, c->w_phase, pn,
                           pn_len, tmp, sizeof tmp, &h);
  else
    gq_long_header_build (sp == SP_INITIAL ? GQ_PKT_INITIAL : GQ_PKT_HANDSHAKE,
                          c->version, c->dcid.data, c->dcid.len,
                          c->scid_first.data, c->scid_first.len,
                          sp == SP_INITIAL ? c->token : NULL,
                          sp == SP_INITIAL ? c->token_len : 0, pn,
                          pn_len, payload_len, tmp, sizeof tmp, &h);
  return h;
}

static int
seal (gq_conn *c, uint64_t now, pk *p, uint64_t pn, size_t pn_len, uint8_t *out,
      size_t cap, size_t *out_len)
{
  space *s = &c->sp[p->sp];
  size_t hdr = 0;
  int r;

  if (p->sp == SP_APP)
    r = gq_short_header_build (c->dcid.data, c->dcid.len, 0, c->w_phase, pn,
                               pn_len, out, cap, &hdr);
  else
    r = gq_long_header_build (p->sp == SP_INITIAL ? GQ_PKT_INITIAL
                                                  : GQ_PKT_HANDSHAKE,
                              c->version, c->dcid.data, c->dcid.len,
                              c->scid_first.data, c->scid_first.len,
                              p->sp == SP_INITIAL ? c->token : NULL,
                              p->sp == SP_INITIAL ? c->token_len : 0,
                              pn, pn_len, p->len, out, cap, &hdr);
  if (r != GQ_OK)
    return r;
  if (hdr + p->len + GQ_AEAD_TAG_LEN > cap)
    return GQ_ERR_BUFSIZE;
  memcpy (out + hdr, p->pl, p->len);
  r = gq_packet_seal (&s->wk, pn, out, hdr - pn_len, pn_len, p->len, cap,
                      out_len);
  (void) now;
  return r;
}

int
conn_build_datagram (gq_conn *c, uint64_t now, uint8_t *out, size_t cap,
                     size_t *len)
{
  size_t maxdg = conn_max_datagram (c), est = 0, total = 0;
  static const int order[N_SPACES] = { SP_INITIAL, SP_HANDSHAKE, SP_APP };
  pk *pks[N_SPACES];
  uint64_t pns[N_SPACES];
  size_t pnl[N_SPACES];
  int n = 0, i, need_pad = 0, sent_handshake = 0, ae = 0, r = GQ_OK;
  pk *storage;

  *len = 0;
  if (maxdg > cap)
    maxdg = cap;
  if (c->role == GQ_ROLE_SERVER && !c->peer_addr_validated)
    {
      uint64_t lim = 3 * c->bytes_recv;

      if (c->bytes_sent >= lim)
        return GQ_OK;
      if (lim - c->bytes_sent < maxdg)
        maxdg = (size_t) (lim - c->bytes_sent);
    }
  if (c->state == GQ_CONN_CLOSING && !c->close_pending)
    return GQ_OK;
  storage = malloc (N_SPACES * sizeof *storage);
  if (storage == NULL)
    return GQ_ERR_NOMEM;
  for (i = 0; i < N_SPACES; i++)
    {
      int sp = order[i];
      pk *p = &storage[n];
      space *s = &c->sp[sp];

      if (s->discarded || !s->have_wk)
        continue;
      if (est + 1 >= maxdg)
        break;
      if (!assemble (c, sp, now, maxdg - est, p))
        continue;
      pks[n] = p;
      pns[n] = s->next_pn++;
      pnl[n] = gq_pn_encoded_len (pns[n], s->have_acked, s->largest_acked);
      /* Pad tiny payloads so the header protection sample exists.  */
      while (p->len < 4 - pnl[n] + 0 && p->len < p->cap)
        p->pl[p->len++] = 0;
      est += p->hdr_est + p->len;
      n++;
      if (c->state == GQ_CONN_CLOSING)
        continue;
    }
  if (n == 0)
    {
      free (storage);
      return GQ_OK;
    }
  /* Datagrams with an Initial packet are padded to 1200 bytes: always for
     a client, and for a server when the Initial is ack-eliciting.  */
  for (i = 0; i < n; i++)
    if (pks[i]->sp == SP_INITIAL
        && (c->role == GQ_ROLE_CLIENT || pks[i]->ae || pks[i]->closing))
      need_pad = 1;
  if (need_pad && maxdg >= GQ_MIN_INITIAL_DATAGRAM)
    {
      pk *last = pks[n - 1];
      size_t t = 0, guard, padded = 0;

      for (guard = 0; guard < 3; guard++)
        {
          t = 0;
          for (i = 0; i < n; i++)
            t += hdr_len_for (c, pks[i]->sp, pks[i]->len, pnl[i], pns[i])
                 + pks[i]->len + GQ_AEAD_TAG_LEN;
          if (t >= GQ_MIN_INITIAL_DATAGRAM)
            break;
          {
            size_t add_n = GQ_MIN_INITIAL_DATAGRAM - t;

            if (add_n > sizeof last->pl - last->len)
              add_n = sizeof last->pl - last->len;
            memset (last->pl + last->len, 0, add_n);
            last->len += add_n;
            padded += add_n;
          }
        }
      /* A longer payload can widen the Length field by a byte.  */
      if (t > GQ_MIN_INITIAL_DATAGRAM && padded >= t - GQ_MIN_INITIAL_DATAGRAM)
        last->len -= t - GQ_MIN_INITIAL_DATAGRAM;
    }
  for (i = 0; i < n && r == GQ_OK; i++)
    {
      pk *p = pks[i];
      size_t w = 0;

      r = seal (c, now, p, pns[i], pnl[i], out + total, maxdg - total, &w);
      if (r != GQ_OK)
        break;
      total += w;
      c->st.packets_sent++;
      if (p->ae)
        {
          sent_pkt sp;

          ae = 1;
          memset (&sp, 0, sizeof sp);
          sp.pn = pns[i];
          sp.time_us = now;
          sp.size = (uint32_t) w;
          sp.ack_eliciting = 1;
          sp.in_flight = 1;
          if (p->nsf)
            {
              sp.frames = malloc (p->nsf * sizeof *sp.frames);
              if (sp.frames == NULL)
                r = GQ_ERR_NOMEM;
              else
                {
                  memcpy (sp.frames, p->sf, p->nsf * sizeof *sp.frames);
                  sp.nframes = p->nsf;
                }
            }
          if (r == GQ_OK)
            sp_sent_add (c, p->sp, &sp);
        }
      if (p->sp == SP_HANDSHAKE)
        sent_handshake = 1;
    }
  free (storage);
  if (r != GQ_OK)
    {
      conn_fail (c, GQ_QERR_INTERNAL, "cannot build packet");
      return r;
    }
  *len = total;
  c->bytes_sent += total;
  c->st.bytes_sent += total;
  if (c->state == GQ_CONN_CLOSING)
    {
      c->close_pending = 0;
      c->last_close_sent = now;
    }
  if (ae && !c->idle_send_reset)
    {
      c->idle_send_reset = 1;
      conn_recompute_idle (c, now);
    }
  if (sent_handshake && c->role == GQ_ROLE_CLIENT)
    conn_discard_space (c, SP_INITIAL);
  /* Rekey before the AEAD limits (2^23 packets for AES-GCM).  */
  if (c->sp[SP_APP].next_pn - c->w_first_pn > ((uint64_t) 1 << 22))
    gq_conn_update_keys (c, now);
  return GQ_OK;
}
