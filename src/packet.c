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

#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/varint.h>
#include <gnuquic/crypto.h>
#include <gnuquic/packet.h>

#include "version.h"

#define FORM_LONG 0x80
#define FIXED_BIT 0x40

/* ------------------------------------------------------------------ */
/* Versions                                                           */
/* ------------------------------------------------------------------ */

static const struct gq_version_info versions[] = {
  {
    GQ_VERSION_1, "quic key", "quic iv", "quic hp", "quic ku",
    { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
      0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a },
    { 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
      0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e },
    { 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
      0x23, 0x98, 0x25, 0xbb },
    { 0, 1, 2, 3 }
  },
  {
    GQ_VERSION_2, "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku",
    { 0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
      0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9 },
    { 0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
      0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92 },
    { 0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99,
      0x90, 0xef, 0xb0, 0x4a },
    { 1, 2, 3, 0 }
  }
};

const struct gq_version_info *
gq_version_lookup (uint32_t version)
{
  size_t i;

  for (i = 0; i < sizeof versions / sizeof versions[0]; i++)
    if (versions[i].wire == version)
      return &versions[i];
  return NULL;
}

int
gq_version_supported (uint32_t version)
{
  return gq_version_lookup (version) != NULL;
}

enum gq_packet_type
gq_version_type_from_bits (const struct gq_version_info *vi, unsigned bits)
{
  static const enum gq_packet_type logical[4] = {
    GQ_PKT_INITIAL, GQ_PKT_ZERO_RTT, GQ_PKT_HANDSHAKE, GQ_PKT_RETRY
  };
  size_t i;

  for (i = 0; i < 4; i++)
    if (vi->type_bits[i] == bits)
      return logical[i];
  return GQ_PKT_INITIAL;	/* Unreachable: the table is a permutation.  */
}

static unsigned
type_to_bits (const struct gq_version_info *vi, enum gq_packet_type t)
{
  switch (t)
    {
    case GQ_PKT_INITIAL:   return vi->type_bits[0];
    case GQ_PKT_ZERO_RTT:  return vi->type_bits[1];
    case GQ_PKT_HANDSHAKE: return vi->type_bits[2];
    default:               return vi->type_bits[3];
    }
}

/* ------------------------------------------------------------------ */
/* Packet numbers                                                     */
/* ------------------------------------------------------------------ */

size_t
gq_pn_encoded_len (uint64_t full, int have_acked, uint64_t largest_acked)
{
  /* The receiver needs to distinguish PN from anything within half the
     window of the unacknowledged range (RFC 9000 A.2).  */
  uint64_t unacked = have_acked ? full - largest_acked : full + 1;
  size_t bits = 0;

  while (unacked >> bits)
    bits++;
  bits += 1;			/* Sign-like extra bit.  */
  {
    size_t n = (bits + 7) / 8;

    return n < 1 ? 1 : n > 4 ? 4 : n;
  }
}

void
gq_pn_encode (uint64_t full, size_t len, uint8_t *out)
{
  size_t i;

  for (i = 0; i < len; i++)
    out[i] = (uint8_t) (full >> (8 * (len - 1 - i)));
}

uint64_t
gq_pn_decode (int have_largest, uint64_t largest, uint64_t truncated,
              size_t len)
{
  uint64_t expected = have_largest ? largest + 1 : 0;
  uint64_t win = UINT64_C (1) << (8 * len);
  uint64_t half = win / 2;
  uint64_t mask = win - 1;
  uint64_t candidate = (expected & ~mask) | truncated;

  if (candidate + half <= expected && candidate < (UINT64_C (1) << 62) - win)
    return candidate + win;
  if (candidate > expected + half && candidate >= win)
    return candidate - win;
  return candidate;
}

/* ------------------------------------------------------------------ */
/* Long headers                                                       */
/* ------------------------------------------------------------------ */

struct rd
{
  const uint8_t *p;
  size_t n;
};

static int
rd_bytes (struct rd *r, size_t len, gq_slice *s)
{
  if (len > r->n)
    return GQ_NEED_MORE;
  s->data = r->p;
  s->len = len;
  r->p += len;
  r->n -= len;
  return GQ_OK;
}

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

int
gq_long_header_parse (const uint8_t *pkt, size_t len, gq_long_header *h)
{
  struct rd r = { pkt, len };
  const struct gq_version_info *vi;
  gq_slice s;
  uint8_t l;
  uint64_t v;

  memset (h, 0, sizeof *h);
  if (len == 0)
    return GQ_NEED_MORE;
  if (!(pkt[0] & FORM_LONG))
    return GQ_ERR_ENCODING;

  TRY (rd_bytes (&r, 1, &s));
  h->first = s.data[0];
  TRY (rd_bytes (&r, 4, &s));
  h->version = ((uint32_t) s.data[0] << 24) | ((uint32_t) s.data[1] << 16)
    | ((uint32_t) s.data[2] << 8) | s.data[3];

  /* Connection ID lengths: up to 255 in the invariants, but 20 for any
     version we implement, checked as soon as the length is known.  */
  vi = gq_version_lookup (h->version);
  TRY (rd_bytes (&r, 1, &s));
  l = s.data[0];
  if (vi != NULL && l > GQ_MAX_CID_LEN)
    return GQ_ERR_ENCODING;
  TRY (rd_bytes (&r, l, &h->dcid));
  TRY (rd_bytes (&r, 1, &s));
  l = s.data[0];
  if (vi != NULL && l > GQ_MAX_CID_LEN)
    return GQ_ERR_ENCODING;
  TRY (rd_bytes (&r, l, &h->scid));

  if (h->version == GQ_VERSION_NEGOTIATION)
    {
      h->type = GQ_PKT_VERSION_NEGOTIATION;
      h->versions.data = r.p;
      h->versions.len = r.n;
      h->packet_len = len;
      if (r.n == 0 || r.n % 4 != 0)
        return GQ_ERR_ENCODING;
      return GQ_OK;
    }

  if (vi == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (!(h->first & FIXED_BIT))
    return GQ_ERR_ENCODING;

  h->type = gq_version_type_from_bits (vi, (h->first >> 4) & 3);

  if (h->type == GQ_PKT_RETRY)
    {
      /* Token to end minus the 16-byte tag; the token may not be empty
         (RFC 9000 17.2.5.2).  */
      if (r.n < GQ_RETRY_TAG_LEN + 1)
        return GQ_ERR_ENCODING;
      h->token.data = r.p;
      h->token.len = r.n - GQ_RETRY_TAG_LEN;
      h->retry_tag.data = r.p + h->token.len;
      h->retry_tag.len = GQ_RETRY_TAG_LEN;
      h->packet_len = len;
      return GQ_OK;
    }

  if (h->type == GQ_PKT_INITIAL)
    {
      const uint8_t *q = r.p;
      size_t n = r.n;

      if (gq_varint_decode (&q, &n, &v) != GQ_OK)
        return GQ_NEED_MORE;
      r.p = q;
      r.n = n;
      if (v > r.n)
        return GQ_NEED_MORE;
      TRY (rd_bytes (&r, (size_t) v, &h->token));
    }

  {
    const uint8_t *q = r.p;
    size_t n = r.n;

    if (gq_varint_decode (&q, &n, &h->length) != GQ_OK)
      return GQ_NEED_MORE;
    r.p = q;
    r.n = n;
  }
  h->pn_offset = (size_t) (r.p - pkt);
  /* Length covers at least a 1-byte packet number, and must fit.  */
  if (h->length == 0 || h->length > r.n)
    return GQ_ERR_ENCODING;
  h->packet_len = h->pn_offset + (size_t) h->length;
  return GQ_OK;
}

size_t
gq_vn_count (const gq_long_header *h)
{
  return h->versions.len / 4;
}

uint32_t
gq_vn_get (const gq_long_header *h, size_t i)
{
  const uint8_t *p = h->versions.data + 4 * i;

  return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
    | ((uint32_t) p[2] << 8) | p[3];
}

struct wr
{
  uint8_t *p;
  size_t cap;
  size_t off;
};

static int
wr_bytes (struct wr *w, const void *src, size_t len)
{
  if (w->cap - w->off < len)
    return GQ_ERR_BUFSIZE;
  if (len)
    memcpy (w->p + w->off, src, len);
  w->off += len;
  return GQ_OK;
}

static int
wr_u8 (struct wr *w, unsigned v)
{
  uint8_t b = (uint8_t) v;

  return wr_bytes (w, &b, 1);
}

static int
wr_u32 (struct wr *w, uint32_t v)
{
  uint8_t b[4];

  b[0] = (uint8_t) (v >> 24);
  b[1] = (uint8_t) (v >> 16);
  b[2] = (uint8_t) (v >> 8);
  b[3] = (uint8_t) v;
  return wr_bytes (w, b, 4);
}

static int
wr_vi (struct wr *w, uint64_t v)
{
  size_t n = gq_varint_size (v);

  if (n == 0)
    return GQ_ERR_RANGE;
  if (w->cap - w->off < n)
    return GQ_ERR_BUFSIZE;
  gq_varint_encode (v, w->p + w->off, n);
  w->off += n;
  return GQ_OK;
}

int
gq_long_header_build (enum gq_packet_type type, uint32_t version,
                      const uint8_t *dcid, size_t dcid_len,
                      const uint8_t *scid, size_t scid_len,
                      const uint8_t *token, size_t token_len,
                      uint64_t pn, size_t pn_len, size_t payload_len,
                      uint8_t *out, size_t cap, size_t *hdr_len)
{
  const struct gq_version_info *vi = gq_version_lookup (version);
  struct wr w = { out, cap, 0 };

  if (vi == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (type != GQ_PKT_INITIAL && type != GQ_PKT_ZERO_RTT
      && type != GQ_PKT_HANDSHAKE)
    return GQ_ERR_INVAL;
  if (pn_len < 1 || pn_len > 4 || dcid_len > GQ_MAX_CID_LEN
      || scid_len > GQ_MAX_CID_LEN || (dcid == NULL && dcid_len > 0)
      || (scid == NULL && scid_len > 0) || (token == NULL && token_len > 0)
      || hdr_len == NULL)
    return GQ_ERR_INVAL;

  TRY (wr_u8 (&w, FORM_LONG | FIXED_BIT | (type_to_bits (vi, type) << 4)
                  | (unsigned) (pn_len - 1)));
  TRY (wr_u32 (&w, version));
  TRY (wr_u8 (&w, (unsigned) dcid_len));
  TRY (wr_bytes (&w, dcid, dcid_len));
  TRY (wr_u8 (&w, (unsigned) scid_len));
  TRY (wr_bytes (&w, scid, scid_len));
  if (type == GQ_PKT_INITIAL)
    {
      TRY (wr_vi (&w, token_len));
      TRY (wr_bytes (&w, token, token_len));
    }
  TRY (wr_vi (&w, (uint64_t) pn_len + payload_len + GQ_AEAD_TAG_LEN));
  if (w.cap - w.off < pn_len)
    return GQ_ERR_BUFSIZE;
  gq_pn_encode (pn, pn_len, out + w.off);
  w.off += pn_len;
  *hdr_len = w.off;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Short headers                                                      */
/* ------------------------------------------------------------------ */

int
gq_short_header_parse (const uint8_t *pkt, size_t len, size_t dcid_len,
                       gq_short_header *h)
{
  memset (h, 0, sizeof *h);
  if (len == 0)
    return GQ_NEED_MORE;
  if ((pkt[0] & FORM_LONG) || !(pkt[0] & FIXED_BIT)
      || dcid_len > GQ_MAX_CID_LEN)
    return GQ_ERR_ENCODING;
  if (len < 1 + dcid_len)
    return GQ_NEED_MORE;
  h->first = pkt[0];
  h->dcid.data = pkt + 1;
  h->dcid.len = dcid_len;
  h->pn_offset = 1 + dcid_len;
  return GQ_OK;
}

int
gq_short_header_build (const uint8_t *dcid, size_t dcid_len, int spin,
                       int key_phase, uint64_t pn, size_t pn_len,
                       uint8_t *out, size_t cap, size_t *hdr_len)
{
  struct wr w = { out, cap, 0 };

  if (pn_len < 1 || pn_len > 4 || dcid_len > GQ_MAX_CID_LEN
      || (dcid == NULL && dcid_len > 0) || hdr_len == NULL)
    return GQ_ERR_INVAL;
  TRY (wr_u8 (&w, FIXED_BIT | (spin ? 0x20 : 0) | (key_phase ? 0x04 : 0)
                  | (unsigned) (pn_len - 1)));
  TRY (wr_bytes (&w, dcid, dcid_len));
  if (w.cap - w.off < pn_len)
    return GQ_ERR_BUFSIZE;
  gq_pn_encode (pn, pn_len, out + w.off);
  w.off += pn_len;
  *hdr_len = w.off;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Version Negotiation                                                */
/* ------------------------------------------------------------------ */

int
gq_vn_build (const uint8_t *dcid, size_t dcid_len, const uint8_t *scid,
             size_t scid_len, const uint32_t *versions_, size_t n,
             uint8_t unused_bits, uint8_t *out, size_t cap, size_t *written)
{
  struct wr w = { out, cap, 0 };
  size_t i;

  if (n == 0 || dcid_len > 255 || scid_len > 255 || written == NULL
      || (dcid == NULL && dcid_len > 0) || (scid == NULL && scid_len > 0)
      || versions_ == NULL)
    return GQ_ERR_INVAL;
  TRY (wr_u8 (&w, FORM_LONG | (unused_bits & 0x7f)));
  TRY (wr_u32 (&w, GQ_VERSION_NEGOTIATION));
  TRY (wr_u8 (&w, (unsigned) dcid_len));
  TRY (wr_bytes (&w, dcid, dcid_len));
  TRY (wr_u8 (&w, (unsigned) scid_len));
  TRY (wr_bytes (&w, scid, scid_len));
  for (i = 0; i < n; i++)
    TRY (wr_u32 (&w, versions_[i]));
  *written = w.off;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Stateless reset                                                    */
/* ------------------------------------------------------------------ */

size_t
gq_stateless_reset_size (size_t received_len)
{
  size_t size;

  /* Must be shorter than the trigger so it cannot loop between two
     endpoints, at least 21 bytes so it can look like a real packet, and
     no more than the trigger for amplification.  Aim for a typical
     small-packet size but stay under the trigger (RFC 9000 10.3).  */
  if (received_len <= GQ_STATELESS_RESET_MIN_LEN)
    return 0;
  size = received_len - 1;
  if (size > 43)
    size = 43;
  if (size < GQ_STATELESS_RESET_MIN_LEN)
    size = GQ_STATELESS_RESET_MIN_LEN;
  return size;
}

int
gq_stateless_reset_build (size_t received_len, const uint8_t *token,
                          uint8_t *out, size_t cap, size_t *written)
{
  size_t size = gq_stateless_reset_size (received_len);
  int r;

  if (size == 0)
    return GQ_ERR_RANGE;
  if (token == NULL || written == NULL)
    return GQ_ERR_INVAL;
  if (cap < size)
    return GQ_ERR_BUFSIZE;
  r = gq_random (out, size);
  if (r != GQ_OK)
    return r;
  out[0] = (uint8_t) ((out[0] & 0x3f) | FIXED_BIT);	/* Short header form.  */
  memcpy (out + size - GQ_STATELESS_RESET_TOKEN_LEN, token,
          GQ_STATELESS_RESET_TOKEN_LEN);
  *written = size;
  return GQ_OK;
}

int
gq_stateless_reset_match (const uint8_t *datagram, size_t len,
                          const uint8_t *token)
{
  if (datagram == NULL || token == NULL || len < GQ_STATELESS_RESET_MIN_LEN)
    return 0;
  return gq_ct_equal (datagram + len - GQ_STATELESS_RESET_TOKEN_LEN, token,
                      GQ_STATELESS_RESET_TOKEN_LEN);
}
