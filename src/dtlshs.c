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
#include <gnuquic/crypto.h>
#include <gnuquic/dtlshs.h>

/* ------------------------------------------------------------------ */
/* Decoding                                                           */
/* ------------------------------------------------------------------ */

static uint32_t
be24 (const uint8_t *p)
{
  return ((uint32_t) p[0] << 16) | ((uint32_t) p[1] << 8) | p[2];
}

int
gq_dtls_hs_parse (gq_slice s, uint32_t max_len, gq_dtls_hs_cb cb, void *user)
{
  const uint8_t *p = s.data;
  size_t n = s.len;

  while (n > 0)
    {
      gq_dtls_hs_frag f;

      if (n < GQ_DTLS_HS_HEADER)
        return GQ_ERR_ENCODING;
      f.type = p[0];
      f.length = be24 (p + 1);
      f.message_seq = (uint16_t) (((unsigned) p[4] << 8) | p[5]);
      f.frag_off = be24 (p + 6);
      f.frag_len = be24 (p + 9);
      if (f.length > max_len)
        return GQ_ERR_PROTOCOL;
      if (f.frag_len > n - GQ_DTLS_HS_HEADER
          || f.frag_off > f.length || f.frag_len > f.length - f.frag_off)
        return GQ_ERR_ENCODING;
      f.data.data = p + GQ_DTLS_HS_HEADER;
      f.data.len = f.frag_len;
      if (cb && cb (user, &f))
        return GQ_ERR_HANDLER;
      p += GQ_DTLS_HS_HEADER + f.frag_len;
      n -= GQ_DTLS_HS_HEADER + f.frag_len;
    }
  return GQ_OK;
}

int
gq_dtls_acks (gq_slice s, gq_dtls_ack_cb cb, void *user)
{
  const uint8_t *p = s.data;
  size_t n, i, j;

  if (s.len < 2)
    return GQ_ERR_ENCODING;
  n = ((size_t) p[0] << 8) | p[1];
  if (n != s.len - 2 || n % 16)
    return GQ_ERR_ENCODING;
  p += 2;
  for (i = 0; i < n / 16; i++, p += 16)
    {
      gq_dtls_recno r = { 0, 0 };

      for (j = 0; j < 8; j++)
        {
          r.epoch = (r.epoch << 8) | p[j];
          r.seq = (r.seq << 8) | p[8 + j];
        }
      if (cb && cb (user, r))
        return GQ_ERR_HANDLER;
    }
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Reassembly                                                         */
/* ------------------------------------------------------------------ */

void
gq_dtls_reasm_init (gq_dtls_reasm *r, uint32_t max_len, uint16_t first)
{
  memset (r, 0, sizeof *r);
  r->max_len = max_len;
  r->next_seq = first;
}

void
gq_dtls_reasm_trim (gq_dtls_reasm *r)
{
  if (r->buf)
    {
      gq_wipe (r->buf, r->cap);
      free (r->buf);
    }
  r->buf = NULL;
  r->cap = 0;
  r->active = 0;
  r->n = 0;
}

void
gq_dtls_reasm_free (gq_dtls_reasm *r)
{
  gq_dtls_reasm_trim (r);
}

int
gq_dtls_reasm_partial (const gq_dtls_reasm *r)
{
  return r->active;
}

/* Is [LO, HI) entirely within the received ranges?  */
static int
covered (const gq_dtls_reasm *r, uint32_t lo, uint32_t hi)
{
  unsigned i;

  for (i = 0; i < r->n; i++)
    if (r->range[i].lo <= lo && hi <= r->range[i].hi)
      return 1;
  return 0;
}

/* Overlapping bytes must be identical (RFC 9147 section 5.5).  */
static int
overlap_agrees (const gq_dtls_reasm *r, const gq_dtls_hs_frag *f)
{
  unsigned i;
  uint32_t lo, hi;

  for (i = 0; i < r->n; i++)
    {
      lo = r->range[i].lo > f->frag_off ? r->range[i].lo : f->frag_off;
      hi = r->range[i].hi < f->frag_off + f->frag_len
        ? r->range[i].hi : f->frag_off + f->frag_len;
      if (lo < hi
          && memcmp (r->buf + 4 + lo, f->data.data + (lo - f->frag_off),
                     hi - lo) != 0)
        return 0;
    }
  return 1;
}

/* Insert [LO, HI), merging with what touches it.  Returns 0, leaving the
   list unchanged, if it would need more than GQ_DTLS_RANGES entries.  */
static int
add_range (gq_dtls_reasm *r, uint32_t lo, uint32_t hi)
{
  gq_dtls_range keep[GQ_DTLS_RANGES], nw;
  unsigned j, k = 0;
  int placed = 0;

  nw.lo = lo;
  nw.hi = hi;
  /* The list is sorted and disjoint: ranges before the new one are kept,
     ranges that touch it are absorbed, and the first one after it is
     preceded by the (merged) new range.  */
  for (j = 0; j < r->n; j++)
    {
      gq_dtls_range cur = r->range[j];

      if (cur.hi < nw.lo)
        ;
      else if (cur.lo > nw.hi)
        {
          if (!placed)
            {
              if (k == GQ_DTLS_RANGES)
                return 0;
              keep[k++] = nw;
              placed = 1;
            }
        }
      else
        {
          if (cur.lo < nw.lo)
            nw.lo = cur.lo;
          if (cur.hi > nw.hi)
            nw.hi = cur.hi;
          continue;
        }
      if (k == GQ_DTLS_RANGES)
        return 0;
      keep[k++] = cur;
    }
  if (!placed)
    {
      if (k == GQ_DTLS_RANGES)
        return 0;
      keep[k++] = nw;
    }
  memcpy (r->range, keep, k * sizeof keep[0]);
  r->n = k;
  return 1;
}

/* message_seq order with wrap-around.  */
static int
seq_before (uint16_t a, uint16_t b)
{
  return (int16_t) (uint16_t) (a - b) < 0;
}

static int
deliver (gq_dtls_reasm *r, gq_dtls_msg_cb cb, void *user)
{
  size_t total = 4 + (size_t) r->length;
  int stop;

  r->active = 0;
  r->n = 0;
  r->next_seq++;
  stop = cb ? cb (user, r->type, (gq_slice) { r->buf, total }) : 0;
  /* Keep small buffers for the next message; drop a big one at once.  */
  if (r->cap > 4096)
    gq_dtls_reasm_trim (r);
  return stop ? GQ_ERR_HANDLER : GQ_DRX_DELIVERED;
}

int
gq_dtls_reasm_push (gq_dtls_reasm *r, const gq_dtls_hs_frag *f,
                    gq_dtls_msg_cb cb, void *user)
{
  if (seq_before (f->message_seq, r->next_seq))
    return GQ_DRX_DUPLICATE;
  if (f->message_seq != r->next_seq)
    return GQ_DRX_DROPPED;
  if (f->length > r->max_len)
    return GQ_ERR_PROTOCOL;

  if (!r->active)
    {
      size_t need = 4 + (size_t) f->length;

      if (need > r->cap)
        {
          uint8_t *nb = realloc (r->buf, need);

          if (nb == NULL)
            return GQ_ERR_NOMEM;
          r->buf = nb;
          r->cap = need;
        }
      r->type = f->type;
      r->length = f->length;
      r->n = 0;
      r->active = 1;
      r->buf[0] = (uint8_t) f->type;
      r->buf[1] = (uint8_t) (f->length >> 16);
      r->buf[2] = (uint8_t) (f->length >> 8);
      r->buf[3] = (uint8_t) f->length;
    }
  else if (f->type != r->type || f->length != r->length)
    return GQ_ERR_PROTOCOL;

  if (f->length == 0)
    return deliver (r, cb, user);
  if (f->frag_len == 0)
    return GQ_DRX_BUFFERED;		/* Nothing to add.  */
  if (!overlap_agrees (r, f))
    return GQ_ERR_PROTOCOL;
  if (covered (r, f->frag_off, f->frag_off + f->frag_len))
    return GQ_DRX_DUPLICATE;
  memcpy (r->buf + 4 + f->frag_off, f->data.data, f->frag_len);
  if (!add_range (r, f->frag_off, f->frag_off + f->frag_len))
    return GQ_DRX_DROPPED;		/* Too fragmented: wait for a resend.  */
  if (r->n == 1 && r->range[0].lo == 0 && r->range[0].hi == r->length)
    return deliver (r, cb, user);
  return GQ_DRX_BUFFERED;
}

/* ------------------------------------------------------------------ */
/* Encoding                                                           */
/* ------------------------------------------------------------------ */

void
gq_dtls_put_hs_frag (gq_wbuf *w, unsigned type, uint32_t length, uint16_t seq,
                     uint32_t off, const uint8_t *data, size_t n)
{
  gq_wbuf_u8 (w, type);
  gq_wbuf_u24 (w, length);
  gq_wbuf_u16 (w, seq);
  gq_wbuf_u24 (w, off);
  gq_wbuf_u24 (w, (unsigned long) n);
  gq_wbuf_bytes (w, data, n);
}

void
gq_dtls_put_acks (gq_wbuf *w, const gq_dtls_recno *nums, size_t n)
{
  size_t i;

  if (n > 8191)
    n = 8191;
  gq_wbuf_u16 (w, (unsigned) (16 * n));
  for (i = 0; i < n; i++)
    {
      gq_wbuf_u32 (w, (uint32_t) (nums[i].epoch >> 32));
      gq_wbuf_u32 (w, (uint32_t) nums[i].epoch);
      gq_wbuf_u32 (w, (uint32_t) (nums[i].seq >> 32));
      gq_wbuf_u32 (w, (uint32_t) nums[i].seq);
    }
}
