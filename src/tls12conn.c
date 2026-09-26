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
#include <gnuquic/record12.h>
#include <gnuquic/tls12conn.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

struct gq_tls12conn
{
  gq_tls12 *tls;
  int server;
  gq_record12 rec;
  gq_tlsconn_events ev;
  gq_tls12_sink sink;
  int connected;
  int closed;			/* Terminal: no more I/O.  */
  int status;			/* Why: 0 orderly, else a negative status.  */
  int close_sent;
  int in_receive;
  uint64_t limit;		/* Records per AES-GCM direction.  */

  /* Incoming bytes not yet forming a whole record.  */
  uint8_t inbuf[GQ_REC12_MAX_RECORD];
  size_t in_len;
  /* Scratch for one outgoing record.  */
  uint8_t outbuf[GQ_REC12_MAX_RECORD];
};

static void
finish (gq_tls12conn *c, int error, int alert)
{
  if (c->closed)
    return;
  c->closed = 1;
  c->status = error < 0 ? error : 0;
  if (c->ev.closed)
    c->ev.closed (c->ev.user, error, alert);
}

static int
write_record (gq_tls12conn *c, unsigned type, const uint8_t *data, size_t len)
{
  size_t n;
  int r = gq_record12_protect (&c->rec, type, data, len, c->outbuf,
                               sizeof c->outbuf, &n);

  if (r != GQ_OK)
    return r;
  return c->ev.write (c->ev.user, c->outbuf, n) ? GQ_ERR_HANDLER : GQ_OK;
}

static int
write_fragments (gq_tls12conn *c, unsigned type, const uint8_t *data,
                 size_t len)
{
  while (len > 0)
    {
      size_t n = len < GQ_REC_MAX_PLAINTEXT ? len : GQ_REC_MAX_PLAINTEXT;

      TRY (write_record (c, type, data, n));
      data += n;
      len -= n;
    }
  return GQ_OK;
}

static int
send_alert (gq_tls12conn *c, unsigned level, unsigned code)
{
  uint8_t a[2];

  a[0] = (uint8_t) level;
  a[1] = (uint8_t) code;
  return write_record (c, GQ_CT_ALERT, a, 2);
}

/* ------------------------------------------------------------------ */
/* Engine sink                                                        */
/* ------------------------------------------------------------------ */

static int
sink_send (void *u, const uint8_t *data, size_t len)
{
  gq_tls12conn *c = u;

  return write_fragments (c, GQ_CT_HANDSHAKE, data, len) != GQ_OK;
}

static int
sink_change_keys (void *u, enum gq_dir dir, enum gq_aead aead,
                  const uint8_t *key, size_t key_len, const uint8_t *iv,
                  size_t iv_len)
{
  gq_tls12conn *c = u;
  static const uint8_t ccs = 1;

  if (dir == GQ_DIR_WRITE
      && write_record (c, GQ_CT_CHANGE_CIPHER_SPEC, &ccs, 1) != GQ_OK)
    return 1;
  return gq_record12_set_keys (&c->rec, dir, aead, key, key_len, iv, iv_len)
    != GQ_OK;
}

static int
sink_complete (void *u, const gq_tls_info *info)
{
  gq_tls12conn *c = u;

  c->connected = 1;
  if (c->ev.connected)
    return c->ev.connected (c->ev.user, info);
  return 0;
}

static int
sink_ticket (void *u, const gq_tls_ticket *t)
{
  gq_tls12conn *c = u;

  return c->ev.ticket ? c->ev.ticket (c->ev.user, t) : 0;
}

static int
sink_alert (void *u, unsigned code)
{
  gq_tls12conn *c = u;

  if (!c->close_sent && !c->closed)
    {
      c->close_sent = 1;
      send_alert (c, 2, code);
    }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Creation                                                           */
/* ------------------------------------------------------------------ */

static gq_tls12conn *
conn_alloc (const gq_tlsconn_events *events, int server)
{
  gq_tls12conn *c = calloc (1, sizeof *c);

  if (c == NULL)
    return NULL;
  c->server = server;
  gq_record12_init (&c->rec);
  c->ev = *events;
  /* rekey_records lowers the limit (there is no rekeying to trigger).  */
  c->limit = events->rekey_records && events->rekey_records < GQ_REC12_SEQ_LIMIT
    ? events->rekey_records : GQ_REC12_SEQ_LIMIT;
  c->sink.user = c;
  c->sink.send = sink_send;
  c->sink.change_keys = sink_change_keys;
  c->sink.ticket = sink_ticket;
  c->sink.complete = sink_complete;
  c->sink.alert = sink_alert;
  return c;
}

int
gq_tls12conn_client_new (gq_tls12conn **out, const gq_tls_config *config,
                         const gq_tlsconn_events *events)
{
  gq_tls12conn *c;
  int r;

  if (out == NULL || config == NULL || events == NULL || events->write == NULL
      || events->data == NULL)
    return GQ_ERR_INVAL;
  c = conn_alloc (events, 0);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  r = gq_tls12_client_new (&c->tls, config, &c->sink);
  if (r != GQ_OK)
    {
      free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

int
gq_tls12conn_server_new (gq_tls12conn **out,
                         const gq_tls_server_config *config,
                         const gq_tlsconn_events *events)
{
  gq_tls12conn *c;
  int r;

  if (out == NULL || config == NULL || events == NULL || events->write == NULL
      || events->data == NULL)
    return GQ_ERR_INVAL;
  c = conn_alloc (events, 1);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  r = gq_tls12_server_new (&c->tls, config, &c->sink);
  if (r != GQ_OK)
    {
      free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

void
gq_tls12conn_free (gq_tls12conn *c)
{
  if (c == NULL)
    return;
  gq_tls12_free (c->tls);
  gq_record12_wipe (&c->rec);
  gq_wipe (c->inbuf, sizeof c->inbuf);
  gq_wipe (c->outbuf, sizeof c->outbuf);
  free (c);
}

int
gq_tls12conn_start (gq_tls12conn *c)
{
  int r;

  if (c == NULL || c->closed)
    return GQ_ERR_INVAL;
  if (c->server)
    return GQ_OK;
  r = gq_tls12_start (c->tls);
  if (r != GQ_OK)
    finish (c, r, gq_tls12_alert (c->tls));
  return r;
}

int
gq_tls12conn_client_adopt (gq_tls12conn *c, const uint8_t *hello, size_t len)
{
  int r;

  if (c == NULL || c->closed || c->server)
    return GQ_ERR_INVAL;
  r = gq_tls12_client_adopt (c->tls, hello, len);
  if (r != GQ_OK)
    finish (c, r, gq_tls12_alert (c->tls));
  return r;
}

/* ------------------------------------------------------------------ */
/* Input                                                              */
/* ------------------------------------------------------------------ */

/* End the connection after a protocol error of ours: tell the peer.  */
static int
fatal (gq_tls12conn *c, unsigned alert, int status)
{
  if (!c->close_sent)
    {
      c->close_sent = 1;
      send_alert (c, 2, alert);
    }
  finish (c, status, (int) alert);
  return 1;
}

static int
on_record (void *u, unsigned type, const uint8_t *data, size_t len)
{
  gq_tls12conn *c = u;
  const uint8_t *p = data;
  size_t l = len;
  int r;

  switch (type)
    {
    case GQ_CT_HANDSHAKE:
      r = gq_tls12_feed (c->tls, &p, &l);
      if (r != GQ_OK)
        {
          finish (c, r, gq_tls12_alert (c->tls));
          return 1;
        }
      return 0;

    case GQ_CT_CHANGE_CIPHER_SPEC:
      r = gq_tls12_change_cipher_spec (c->tls);
      if (r != GQ_OK)
        {
          finish (c, r, gq_tls12_alert (c->tls));
          return 1;
        }
      return 0;

    case GQ_CT_APPLICATION_DATA:
      if (!c->connected)
        return fatal (c, GQ_ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
      if (c->ev.data (c->ev.user, data, len))
        {
          finish (c, GQ_ERR_HANDLER, -1);
          return 1;
        }
      return 0;

    case GQ_CT_ALERT:
      if (len != 2)
        return fatal (c, GQ_ALERT_DECODE_ERROR, GQ_ERR_PROTOCOL);
      if (data[1] == GQ_ALERT_CLOSE_NOTIFY)
        {
          /* Orderly close: reply in kind, then we are done.  */
          if (!c->close_sent)
            {
              c->close_sent = 1;
              send_alert (c, 1, GQ_ALERT_CLOSE_NOTIFY);
            }
          finish (c, 0, GQ_ALERT_CLOSE_NOTIFY);
          return 1;
        }
      /* Any other alert ends the connection.  */
      c->close_sent = 1;
      finish (c, GQ_ERR_PROTOCOL, data[1]);
      return 1;

    default:
      return 1;
    }
}

int
gq_tls12conn_receive (gq_tls12conn *c, const uint8_t *data, size_t len)
{
  if (c == NULL || (data == NULL && len > 0) || c->closed || c->in_receive)
    return GQ_ERR_INVAL;
  c->in_receive = 1;

  while (len > 0 && !c->closed)
    {
      size_t take = sizeof c->inbuf - c->in_len;
      uint8_t *p;
      size_t l;
      int r;

      if (take > len)
        take = len;
      memcpy (c->inbuf + c->in_len, data, take);
      c->in_len += take;
      data += take;
      len -= take;

      p = c->inbuf;
      l = c->in_len;
      r = gq_record12_receive (&c->rec, &p, &l, on_record, c);
      if (r == GQ_ERR_HANDLER)
        {
          /* A callback already ended the connection.  */
          c->in_len = 0;
          break;
        }
      if (r != GQ_OK && r != GQ_NEED_MORE)
        {
          int alert = gq_record12_alert (&c->rec);

          if (!c->close_sent && alert >= 0)
            {
              c->close_sent = 1;
              send_alert (c, 2, (unsigned) alert);
            }
          finish (c, r, alert);
          c->in_len = 0;
          break;
        }
      memmove (c->inbuf, p, l);
      c->in_len = l;
    }
  c->in_receive = 0;
  return c->status;
}

/* ------------------------------------------------------------------ */
/* Output                                                             */
/* ------------------------------------------------------------------ */

/* An AES-GCM direction cannot go past its record limit and there is no
   rekeying: leave room for close_notify and stop.  */
static int
write_limit_near (const gq_tls12conn *c)
{
  return c->rec.write.active && c->rec.write.aead != GQ_AEAD_CHACHA20_POLY1305
    && c->rec.write.seq + 2 >= c->limit;
}

int
gq_tls12conn_send (gq_tls12conn *c, const uint8_t *data, size_t len)
{
  if (c == NULL || (data == NULL && len > 0) || !c->connected || c->closed
      || c->close_sent)
    return GQ_ERR_INVAL;

  while (len > 0)
    {
      size_t n = len < GQ_REC_MAX_PLAINTEXT ? len : GQ_REC_MAX_PLAINTEXT;
      int r;

      if (write_limit_near (c))
        {
          c->close_sent = 1;
          send_alert (c, 1, GQ_ALERT_CLOSE_NOTIFY);
          finish (c, GQ_ERR_RANGE, -1);
          return GQ_ERR_RANGE;
        }
      r = write_record (c, GQ_CT_APPLICATION_DATA, data, n);
      if (r != GQ_OK)
        {
          finish (c, r, -1);
          return r;
        }
      data += n;
      len -= n;
    }
  return GQ_OK;
}

int
gq_tls12conn_close (gq_tls12conn *c)
{
  if (c == NULL || c->closed)
    return GQ_ERR_INVAL;
  if (c->close_sent)
    return GQ_OK;
  c->close_sent = 1;
  return send_alert (c, 1, GQ_ALERT_CLOSE_NOTIFY);
}

int
gq_tls12conn_is_connected (const gq_tls12conn *c)
{
  return c != NULL && c->connected && !c->closed;
}

int
gq_tls12conn_is_closed (const gq_tls12conn *c)
{
  return c == NULL || c->closed;
}

int
gq_tls12conn_export (const gq_tls12conn *c, const char *label,
                     const uint8_t *context, size_t context_len, uint8_t *out,
                     size_t out_len)
{
  if (c == NULL || !c->connected)
    return GQ_ERR_INVAL;
  return gq_tls12_export (c->tls, label, context, context_len, out, out_len);
}

uint64_t
gq_tls12conn_write_seq (const gq_tls12conn *c)
{
  return gq_record12_write_seq (&c->rec);
}

uint64_t
gq_tls12conn_read_seq (const gq_tls12conn *c)
{
  return gq_record12_read_seq (&c->rec);
}
