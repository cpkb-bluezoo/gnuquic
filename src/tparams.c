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

#include <stddef.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/varint.h>
#include <gnuquic/tparams.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

void
gq_tp_defaults (gq_transport_params *tp)
{
  memset (tp, 0, sizeof *tp);
  tp->max_udp_payload_size = 65527;
  tp->ack_delay_exponent = 3;
  tp->max_ack_delay = 25;
  tp->active_connection_id_limit = 2;
}

int
gq_tp_has (const gq_transport_params *tp, unsigned id)
{
  if (id < 32)
    return (tp->present >> id) & 1;
  if (id == GQ_TP_MAX_DATAGRAM_FRAME_SIZE)
    return tp->present_hi & 1;
  return 0;
}

void
gq_tp_set_present (gq_transport_params *tp, unsigned id)
{
  if (id < 32)
    tp->present |= UINT32_C (1) << id;
  else if (id == GQ_TP_MAX_DATAGRAM_FRAME_SIZE)
    tp->present_hi |= 1;
}

int
gq_tp_foreach (const uint8_t *buf, size_t len,
               int (*cb) (void *, uint64_t, gq_slice), void *user)
{
  while (len > 0)
    {
      uint64_t id, vlen;
      gq_slice v;

      if (gq_varint_decode (&buf, &len, &id) != GQ_OK
          || gq_varint_decode (&buf, &len, &vlen) != GQ_OK
          || vlen > len)
        return GQ_ERR_ENCODING;
      v.data = buf;
      v.len = (size_t) vlen;
      buf += vlen;
      len -= (size_t) vlen;
      if (cb (user, id, v))
        return GQ_ERR_HANDLER;
    }
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Decoding                                                           */
/* ------------------------------------------------------------------ */

struct dec
{
  gq_transport_params *tp;
  enum gq_role sender;
  int error;
};

/* A value that must be exactly one varint.  */
static int
one_varint (gq_slice v, uint64_t *out)
{
  const uint8_t *p = v.data;
  size_t n = v.len;

  return gq_varint_decode (&p, &n, out) == GQ_OK && n == 0;
}

static int
get_cid (gq_slice v, gq_cid *c)
{
  if (v.len > GQ_MAX_CID_LEN)
    return 0;
  c->len = (uint8_t) v.len;
  if (v.len)
    memcpy (c->data, v.data, v.len);
  return 1;
}

static int
get_preferred (gq_slice v, gq_preferred_address *pa)
{
  const uint8_t *p = v.data;
  size_t cl;

  /* 4 + 2 + 16 + 2 + 1 + cid + 16 */
  if (v.len < 41)
    return 0;
  memcpy (pa->ipv4, p, 4);
  pa->ipv4_port = (uint16_t) ((p[4] << 8) | p[5]);
  memcpy (pa->ipv6, p + 6, 16);
  pa->ipv6_port = (uint16_t) ((p[22] << 8) | p[23]);
  cl = p[24];
  if (cl < 1 || cl > GQ_MAX_CID_LEN || v.len != 25 + cl + 16)
    return 0;
  pa->cid.len = (uint8_t) cl;
  memcpy (pa->cid.data, p + 25, cl);
  memcpy (pa->reset_token, p + 25 + cl, 16);
  return 1;
}

static int
on_param (void *user, uint64_t id, gq_slice v)
{
  struct dec *d = user;
  gq_transport_params *tp = d->tp;
  uint64_t x;
  uint64_t *num = NULL;
  int server_only = 0;

  switch (id)
    {
    case GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID:
    case GQ_TP_STATELESS_RESET_TOKEN:
    case GQ_TP_PREFERRED_ADDRESS:
    case GQ_TP_RETRY_SOURCE_CONNECTION_ID:
      server_only = 1;
      break;
    default:
      break;
    }
  /* Each known parameter may appear at most once.  */
  if ((id < 32 || id == GQ_TP_MAX_DATAGRAM_FRAME_SIZE)
      && gq_tp_has (tp, (unsigned) id))
    goto bad;
  if (server_only && d->sender != GQ_ROLE_SERVER)
    goto bad;

  switch (id)
    {
    case GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID:
      if (!get_cid (v, &tp->original_destination_connection_id))
        goto bad;
      break;
    case GQ_TP_INITIAL_SOURCE_CONNECTION_ID:
      if (!get_cid (v, &tp->initial_source_connection_id))
        goto bad;
      break;
    case GQ_TP_RETRY_SOURCE_CONNECTION_ID:
      if (!get_cid (v, &tp->retry_source_connection_id))
        goto bad;
      break;
    case GQ_TP_VERSION_INFORMATION:
      {
        size_t i, n;

        /* Chosen version, then the available versions (RFC 9368 s3).  */
        if (v.len < 4 || v.len % 4 != 0)
          goto bad;
        tp->chosen_version = (uint32_t) v.data[0] << 24 | (uint32_t) v.data[1] << 16
                             | (uint32_t) v.data[2] << 8 | v.data[3];
        n = v.len / 4 - 1;
        if (n > GQ_TP_MAX_VERSIONS)
          n = GQ_TP_MAX_VERSIONS;	/* Keep what fits; the rest is ignored.  */
        for (i = 0; i < n; i++)
          tp->available_versions[i] = (uint32_t) v.data[4 + 4 * i] << 24
            | (uint32_t) v.data[5 + 4 * i] << 16
            | (uint32_t) v.data[6 + 4 * i] << 8 | v.data[7 + 4 * i];
        tp->n_available_versions = n;
        if (tp->chosen_version == 0)
          goto bad;
        break;
      }
    case GQ_TP_STATELESS_RESET_TOKEN:
      if (v.len != GQ_RESET_TOKEN_LEN)
        goto bad;
      memcpy (tp->stateless_reset_token, v.data, GQ_RESET_TOKEN_LEN);
      break;
    case GQ_TP_DISABLE_ACTIVE_MIGRATION:
      if (v.len != 0)
        goto bad;
      break;
    case GQ_TP_PREFERRED_ADDRESS:
      if (!get_preferred (v, &tp->preferred_address))
        goto bad;
      break;

    case GQ_TP_MAX_IDLE_TIMEOUT: num = &tp->max_idle_timeout; break;
    case GQ_TP_MAX_UDP_PAYLOAD_SIZE: num = &tp->max_udp_payload_size; break;
    case GQ_TP_INITIAL_MAX_DATA: num = &tp->initial_max_data; break;
    case GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
      num = &tp->initial_max_stream_data_bidi_local; break;
    case GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
      num = &tp->initial_max_stream_data_bidi_remote; break;
    case GQ_TP_INITIAL_MAX_STREAM_DATA_UNI:
      num = &tp->initial_max_stream_data_uni; break;
    case GQ_TP_INITIAL_MAX_STREAMS_BIDI:
      num = &tp->initial_max_streams_bidi; break;
    case GQ_TP_INITIAL_MAX_STREAMS_UNI:
      num = &tp->initial_max_streams_uni; break;
    case GQ_TP_ACK_DELAY_EXPONENT: num = &tp->ack_delay_exponent; break;
    case GQ_TP_MAX_ACK_DELAY: num = &tp->max_ack_delay; break;
    case GQ_TP_ACTIVE_CONNECTION_ID_LIMIT:
      num = &tp->active_connection_id_limit; break;
    case GQ_TP_MAX_DATAGRAM_FRAME_SIZE:
      num = &tp->max_datagram_frame_size; break;

    default:
      return 0;			/* Unknown or GREASE: ignore.  */
    }

  if (num != NULL)
    {
      if (!one_varint (v, &x))
        goto bad;
      /* Range rules of RFC 9000 18.2.  */
      switch (id)
        {
        case GQ_TP_MAX_UDP_PAYLOAD_SIZE:
          if (x < 1200 || x > 65527) goto bad;
          break;
        case GQ_TP_ACK_DELAY_EXPONENT:
          if (x > 20) goto bad;
          break;
        case GQ_TP_MAX_ACK_DELAY:
          if (x >= (UINT64_C (1) << 14)) goto bad;
          break;
        case GQ_TP_ACTIVE_CONNECTION_ID_LIMIT:
          if (x < 2) goto bad;
          break;
        case GQ_TP_INITIAL_MAX_STREAMS_BIDI:
        case GQ_TP_INITIAL_MAX_STREAMS_UNI:
          if (x > (UINT64_C (1) << 60)) goto bad;
          break;
        default:
          break;
        }
      *num = x;
    }
  gq_tp_set_present (tp, (unsigned) id);
  return 0;

bad:
  d->error = 1;
  return 1;
}

int
gq_tp_decode (const uint8_t *buf, size_t len, enum gq_role sender,
              gq_transport_params *tp)
{
  struct dec d;
  int r;

  if (tp == NULL || (buf == NULL && len > 0)
      || (sender != GQ_ROLE_CLIENT && sender != GQ_ROLE_SERVER))
    return GQ_ERR_INVAL;
  gq_tp_defaults (tp);
  d.tp = tp;
  d.sender = sender;
  d.error = 0;
  r = gq_tp_foreach (buf, len, on_param, &d);
  if (r == GQ_ERR_HANDLER && d.error)
    r = GQ_ERR_ENCODING;
  return r;
}

/* ------------------------------------------------------------------ */
/* Encoding                                                           */
/* ------------------------------------------------------------------ */

struct wr
{
  uint8_t *p;
  size_t cap;
  size_t off;
};

static int
put_vi (struct wr *w, uint64_t v)
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

static int
put_raw (struct wr *w, uint64_t id, const void *v, size_t len)
{
  TRY (put_vi (w, id));
  TRY (put_vi (w, len));
  if (w->cap - w->off < len)
    return GQ_ERR_BUFSIZE;
  if (len)
    memcpy (w->p + w->off, v, len);
  w->off += len;
  return GQ_OK;
}

static int
put_num (struct wr *w, uint64_t id, uint64_t v)
{
  uint8_t tmp[8];
  size_t n = gq_varint_encode (v, tmp, sizeof tmp);

  if (n == 0)
    return GQ_ERR_RANGE;
  return put_raw (w, id, tmp, n);
}

int
gq_tp_encode (const gq_transport_params *tp, enum gq_role sender,
              uint8_t *out, size_t cap, size_t *written)
{
  struct wr w;
  static const struct { unsigned id; size_t off; } nums[] = {
    { GQ_TP_MAX_IDLE_TIMEOUT, offsetof (gq_transport_params, max_idle_timeout) },
    { GQ_TP_MAX_UDP_PAYLOAD_SIZE, offsetof (gq_transport_params, max_udp_payload_size) },
    { GQ_TP_INITIAL_MAX_DATA, offsetof (gq_transport_params, initial_max_data) },
    { GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, offsetof (gq_transport_params, initial_max_stream_data_bidi_local) },
    { GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, offsetof (gq_transport_params, initial_max_stream_data_bidi_remote) },
    { GQ_TP_INITIAL_MAX_STREAM_DATA_UNI, offsetof (gq_transport_params, initial_max_stream_data_uni) },
    { GQ_TP_INITIAL_MAX_STREAMS_BIDI, offsetof (gq_transport_params, initial_max_streams_bidi) },
    { GQ_TP_INITIAL_MAX_STREAMS_UNI, offsetof (gq_transport_params, initial_max_streams_uni) },
    { GQ_TP_ACK_DELAY_EXPONENT, offsetof (gq_transport_params, ack_delay_exponent) },
    { GQ_TP_MAX_ACK_DELAY, offsetof (gq_transport_params, max_ack_delay) },
    { GQ_TP_ACTIVE_CONNECTION_ID_LIMIT, offsetof (gq_transport_params, active_connection_id_limit) },
    { GQ_TP_MAX_DATAGRAM_FRAME_SIZE, offsetof (gq_transport_params, max_datagram_frame_size) }
  };
  unsigned id;

  if (tp == NULL || out == NULL || written == NULL
      || (sender != GQ_ROLE_CLIENT && sender != GQ_ROLE_SERVER))
    return GQ_ERR_INVAL;
  w.p = out;
  w.cap = cap;
  w.off = 0;

  if (sender == GQ_ROLE_CLIENT
      && (gq_tp_has (tp, GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID)
          || gq_tp_has (tp, GQ_TP_STATELESS_RESET_TOKEN)
          || gq_tp_has (tp, GQ_TP_PREFERRED_ADDRESS)
          || gq_tp_has (tp, GQ_TP_RETRY_SOURCE_CONNECTION_ID)))
    return GQ_ERR_INVAL;

  for (id = 0; id <= GQ_TP_MAX_DATAGRAM_FRAME_SIZE; id++)
    {
      size_t i;

      if (!gq_tp_has (tp, id))
        continue;
      switch (id)
        {
        case GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID:
          TRY (put_raw (&w, id, tp->original_destination_connection_id.data,
                        tp->original_destination_connection_id.len));
          break;
        case GQ_TP_INITIAL_SOURCE_CONNECTION_ID:
          TRY (put_raw (&w, id, tp->initial_source_connection_id.data,
                        tp->initial_source_connection_id.len));
          break;
        case GQ_TP_RETRY_SOURCE_CONNECTION_ID:
          TRY (put_raw (&w, id, tp->retry_source_connection_id.data,
                        tp->retry_source_connection_id.len));
          break;
        case GQ_TP_STATELESS_RESET_TOKEN:
          TRY (put_raw (&w, id, tp->stateless_reset_token,
                        GQ_RESET_TOKEN_LEN));
          break;
        case GQ_TP_VERSION_INFORMATION:
          {
            uint8_t b[4 + 4 * GQ_TP_MAX_VERSIONS];
            size_t k, n = 0;

            if (tp->n_available_versions > GQ_TP_MAX_VERSIONS
                || tp->chosen_version == 0)
              return GQ_ERR_INVAL;
            for (k = 0; k < 1 + tp->n_available_versions; k++)
              {
                uint32_t v = k ? tp->available_versions[k - 1]
                               : tp->chosen_version;

                b[n++] = (uint8_t) (v >> 24);
                b[n++] = (uint8_t) (v >> 16);
                b[n++] = (uint8_t) (v >> 8);
                b[n++] = (uint8_t) v;
              }
            TRY (put_raw (&w, id, b, n));
            break;
          }
        case GQ_TP_DISABLE_ACTIVE_MIGRATION:
          TRY (put_raw (&w, id, NULL, 0));
          break;
        case GQ_TP_PREFERRED_ADDRESS:
          {
            const gq_preferred_address *pa = &tp->preferred_address;
            uint8_t b[25 + GQ_MAX_CID_LEN + 16];
            size_t n = 0;

            if (pa->cid.len < 1 || pa->cid.len > GQ_MAX_CID_LEN)
              return GQ_ERR_INVAL;
            memcpy (b, pa->ipv4, 4);
            b[4] = (uint8_t) (pa->ipv4_port >> 8);
            b[5] = (uint8_t) pa->ipv4_port;
            memcpy (b + 6, pa->ipv6, 16);
            b[22] = (uint8_t) (pa->ipv6_port >> 8);
            b[23] = (uint8_t) pa->ipv6_port;
            b[24] = pa->cid.len;
            memcpy (b + 25, pa->cid.data, pa->cid.len);
            memcpy (b + 25 + pa->cid.len, pa->reset_token, 16);
            n = 25 + (size_t) pa->cid.len + 16;
            TRY (put_raw (&w, id, b, n));
            break;
          }
        default:
          for (i = 0; i < sizeof nums / sizeof nums[0]; i++)
            if (nums[i].id == id)
              {
                uint64_t v;

                memcpy (&v, (const uint8_t *) tp + nums[i].off, sizeof v);
                TRY (put_num (&w, id, v));
              }
          break;
        }
    }
  *written = w.off;
  return GQ_OK;
}
