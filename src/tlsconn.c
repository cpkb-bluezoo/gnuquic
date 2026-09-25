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
#include <gnuquic/record.h>
#include <gnuquic/tlsconn.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

struct gq_tlsconn
{
  gq_tls *tls;
  int server;
  gq_record rec;
  gq_tlsconn_events ev;
  gq_tls_sink sink;
  enum gq_level read_level;
  int connected;
  int closed;			/* Terminal: no more I/O.  */
  int status;			/* Why: 0 orderly, else a negative status.  */
  int close_sent;
  int ccs_sent;
  int early_active;		/* Client: early write keys are in use.  */
  size_t early_sent, early_max;
  size_t early_received, early_limit;
  int in_receive;
  uint64_t rekey_after;

  /* Incoming bytes not yet forming a whole record.  */
  uint8_t inbuf[GQ_REC_MAX_RECORD];
  size_t in_len;
  /* Scratch for building one outgoing record.  */
  uint8_t outbuf[GQ_REC_MAX_RECORD];
};

/* ------------------------------------------------------------------ */
/* Output                                                             */
/* ------------------------------------------------------------------ */

static void
finish (gq_tlsconn *c, int error, int alert)
{
  if (c->closed)
    return;
  c->closed = 1;
  c->status = error < 0 ? error : 0;
  if (c->ev.closed)
    c->ev.closed (c->ev.user, error, alert);
}

/* Emit one record of TYPE carrying DATA (at most one fragment).  */
static int
write_record (gq_tlsconn *c, unsigned type, const uint8_t *data, size_t len)
{
  size_t n;
  int r = gq_record_protect (&c->rec, type, data, len, 0, c->outbuf,
                             sizeof c->outbuf, &n);

  if (r != GQ_OK)
    return r;
  return c->ev.write (c->ev.user, c->outbuf, n) ? GQ_ERR_HANDLER : GQ_OK;
}

static int
write_fragments (gq_tlsconn *c, unsigned type, const uint8_t *data, size_t len)
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
send_alert (gq_tlsconn *c, unsigned level, unsigned code)
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
sink_send (void *u, enum gq_level level, const uint8_t *data, size_t len)
{
  gq_tlsconn *c = u;

  /* The engine's level and our write state must agree.  */
  if ((level == GQ_LEVEL_INITIAL) == gq_record_write_protected (&c->rec))
    return 1;
  return write_fragments (c, GQ_CT_HANDSHAKE, data, len) != GQ_OK;
}

static int
sink_early_result (void *u, int accepted)
{
  gq_tlsconn *c = u;

  if (c->ev.early_data_result)
    c->ev.early_data_result (c->ev.user, accepted);
  if (!accepted && c->early_active)
    {
      /* Back to plaintext: the next ClientHello (after a retry) is in the
         clear, and the handshake keys replace ours otherwise.  */
      gq_record_reset_write (&c->rec);
      c->early_active = 0;
    }
  return 0;
}

static int
sink_secret (void *u, const gq_tls_secret *s)
{
  gq_tlsconn *c = u;
  static const uint8_t ccs = 1;

  if (s->dir == GQ_DIR_WRITE && s->level == GQ_LEVEL_EARLY)
    {
      /* With early data the compatibility ChangeCipherSpec goes right
         after the ClientHello, before the first protected record.  */
      if (!c->ccs_sent)
        {
          c->ccs_sent = 1;
          if (write_record (c, GQ_CT_CHANGE_CIPHER_SPEC, &ccs, 1) != GQ_OK)
            return 1;
        }
      if (gq_record_set_keys (&c->rec, s->dir, s->aead, s->secret, s->len)
          != GQ_OK)
        return 1;
      c->early_active = 1;
      return 0;
    }
  if (s->dir == GQ_DIR_WRITE && s->level == GQ_LEVEL_HANDSHAKE)
    c->early_active = 0;
  if (s->dir == GQ_DIR_WRITE && s->level == GQ_LEVEL_HANDSHAKE && !c->ccs_sent)
    {
      /* Compatibility ChangeCipherSpec before the first encrypted record
         (RFC 8446 appendix D.4).  */
      c->ccs_sent = 1;
      if (write_record (c, GQ_CT_CHANGE_CIPHER_SPEC, &ccs, 1) != GQ_OK)
        return 1;
    }
  if (gq_record_set_keys (&c->rec, s->dir, s->aead, s->secret, s->len)
      != GQ_OK)
    return 1;
  if (s->dir == GQ_DIR_READ)
    c->read_level = s->level;
  return 0;
}

static int
sink_complete (void *u, const gq_tls_info *info)
{
  gq_tlsconn *c = u;

  c->connected = 1;
  /* After the peer's Finished no compatibility record is legitimate, and
     any declined early data has passed.  */
  gq_record_allow_ccs (&c->rec, 0);
  gq_record_set_skip_budget (&c->rec, 0);
  if (c->ev.connected)
    return c->ev.connected (c->ev.user, info);
  return 0;
}

static int
sink_ticket (void *u, const gq_tls_ticket *t)
{
  gq_tlsconn *c = u;

  return c->ev.ticket ? c->ev.ticket (c->ev.user, t) : 0;
}

static int
sink_alert (void *u, unsigned code)
{
  gq_tlsconn *c = u;

  /* Tell the peer (best effort), then the application.  */
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

static gq_tlsconn *
conn_alloc (const gq_tlsconn_events *events, int server)
{
  gq_tlsconn *c = calloc (1, sizeof *c);

  if (c == NULL)
    return NULL;
  c->server = server;
  gq_record_init (&c->rec);
  if (server)
    gq_record_set_server (&c->rec);
  gq_record_allow_ccs (&c->rec, 1);
  c->ev = *events;
  c->rekey_after = events->rekey_records ? events->rekey_records
                                         : GQ_REC_REKEY_ADVISED;
  c->read_level = GQ_LEVEL_INITIAL;
  c->sink.user = c;
  c->sink.send = sink_send;
  c->sink.secret = sink_secret;
  c->sink.ticket = sink_ticket;
  c->sink.early_data = sink_early_result;
  c->sink.complete = sink_complete;
  c->sink.alert = sink_alert;
  return c;
}

int
gq_tlsconn_client_new (gq_tlsconn **out, const gq_tls_config *config,
                       const gq_tlsconn_events *events)
{
  gq_tlsconn *c;
  int r;

  if (out == NULL || config == NULL || events == NULL || events->write == NULL
      || events->data == NULL || config->quic || config->transport_params)
    return GQ_ERR_INVAL;
  c = conn_alloc (events, 0);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  c->early_max = config->resume ? config->resume->max_early_data : 0;
  r = gq_tls_client_new (&c->tls, config, &c->sink);
  if (r != GQ_OK)
    {
      free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

int
gq_tlsconn_server_new (gq_tlsconn **out, const gq_tls_server_config *config,
                       const gq_tlsconn_events *events)
{
  gq_tlsconn *c;
  int r;

  if (out == NULL || config == NULL || events == NULL || events->write == NULL
      || events->data == NULL || config->quic || config->transport_params)
    return GQ_ERR_INVAL;
  c = conn_alloc (events, 1);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  {
    /* Early data is replayable: accept it only if the application has a
       callback that knows to treat it so.  */
    gq_tls_server_config sc = *config;

    if (events->early_data == NULL)
      sc.max_early_data = 0;
    c->early_limit = sc.max_early_data;
    r = gq_tls_server_new (&c->tls, &sc, &c->sink);
  }
  if (r != GQ_OK)
    {
      free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

void
gq_tlsconn_free (gq_tlsconn *c)
{
  if (c == NULL)
    return;
  gq_tls_free (c->tls);
  gq_record_wipe (&c->rec);
  gq_wipe (c->inbuf, sizeof c->inbuf);
  free (c);
}

int
gq_tlsconn_start (gq_tlsconn *c)
{
  int r;

  if (c == NULL || c->closed)
    return GQ_ERR_INVAL;
  if (c->server)		/* Servers wait for the ClientHello.  */
    return GQ_OK;
  r = gq_tls_start (c->tls);
  if (r != GQ_OK)
    finish (c, r, gq_tls_alert (c->tls));
  return r;
}

/* ------------------------------------------------------------------ */
/* Input                                                              */
/* ------------------------------------------------------------------ */

static int
on_record (void *u, unsigned type, const uint8_t *data, size_t len)
{
  gq_tlsconn *c = u;
  const uint8_t *p = data;
  size_t l = len;
  int r;

  switch (type)
    {
    case GQ_CT_HANDSHAKE:
      r = gq_tls_feed (c->tls, c->read_level, &p, &l);
      if (r != GQ_OK)
        {
          finish (c, r, gq_tls_alert (c->tls));
          return 1;
        }
      /* A client that offered 0-RTT will send early records we cannot
         decrypt; skip up to one record's worth (we never accept early
         data, so a well-behaved client sends no more than it is allowed
         and we advertised none).  */
      if (c->server && !c->connected && gq_tls_early_data_offered (c->tls)
          && gq_record_skip_budget (&c->rec) == 0)
        gq_record_set_skip_budget (&c->rec, GQ_REC_MAX_CIPHERTEXT * 2);
      return 0;

    case GQ_CT_APPLICATION_DATA:
      if (!c->connected && c->server && c->read_level == GQ_LEVEL_EARLY
          && c->ev.early_data)
        {
          /* Accepted 0-RTT data, within the limit we advertised.  */
          c->early_received += len;
          if (c->early_received > c->early_limit)
            {
              send_alert (c, 2, GQ_ALERT_UNEXPECTED_MESSAGE);
              c->close_sent = 1;
              finish (c, GQ_ERR_PROTOCOL, GQ_ALERT_UNEXPECTED_MESSAGE);
              return 1;
            }
          if (len && c->ev.early_data (c->ev.user, data, len))
            {
              finish (c, GQ_ERR_HANDLER, -1);
              return 1;
            }
          return 0;
        }
      if (!c->connected)
        {
          send_alert (c, 2, GQ_ALERT_UNEXPECTED_MESSAGE);
          c->close_sent = 1;
          finish (c, GQ_ERR_PROTOCOL, GQ_ALERT_UNEXPECTED_MESSAGE);
          return 1;
        }
      if (len && c->ev.data (c->ev.user, data, len))
        {
          finish (c, GQ_ERR_HANDLER, -1);
          return 1;
        }
      return 0;

    case GQ_CT_ALERT:
      if (len != 2)
        {
          send_alert (c, 2, GQ_ALERT_DECODE_ERROR);
          c->close_sent = 1;
          finish (c, GQ_ERR_PROTOCOL, GQ_ALERT_DECODE_ERROR);
          return 1;
        }
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
      /* Everything else ends the connection (RFC 8446 section 6).  */
      c->close_sent = 1;
      finish (c, GQ_ERR_PROTOCOL, data[1]);
      return 1;

    default:
      return 1;
    }
}

int
gq_tlsconn_receive (gq_tlsconn *c, const uint8_t *data, size_t len)
{
  if (c == NULL || (data == NULL && len > 0))
    return GQ_ERR_INVAL;
  if (c->closed)
    return GQ_ERR_INVAL;
  if (c->in_receive)		/* Not reentrant from our own callbacks.  */
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
      gq_record_allow_ccs (&c->rec, !c->connected);
      r = gq_record_receive (&c->rec, &p, &l, on_record, c);
      if (r == GQ_ERR_HANDLER)
        {
          /* A callback already ended the connection.  */
          c->in_len = 0;
          break;
        }
      if (r != GQ_OK && r != GQ_NEED_MORE)
        {
          int alert = gq_record_alert (&c->rec);

          if (!c->close_sent && alert >= 0)
            {
              c->close_sent = 1;
              send_alert (c, 2, (unsigned) alert);
            }
          finish (c, r, alert);
          c->in_len = 0;
          break;
        }
      /* Keep any partial record at the front of the buffer.  */
      memmove (c->inbuf, p, l);
      c->in_len = l;
    }
  c->in_receive = 0;
  return c->status;
}

/* ------------------------------------------------------------------ */
/* Output API                                                         */
/* ------------------------------------------------------------------ */

int
gq_tlsconn_send (gq_tlsconn *c, const uint8_t *data, size_t len)
{
  if (c == NULL || (data == NULL && len > 0) || !c->connected || c->closed
      || c->close_sent)
    return GQ_ERR_INVAL;

  while (len > 0)
    {
      size_t n = len < GQ_REC_MAX_PLAINTEXT ? len : GQ_REC_MAX_PLAINTEXT;
      int r;

      /* Rekey ahead of the AEAD limit.  The KeyUpdate goes out under the
         old keys, then the new ones take over.  */
      if (gq_record_write_seq (&c->rec) >= c->rekey_after)
        {
          r = gq_tls_key_update (c->tls, 0);
          if (r != GQ_OK)
            {
              finish (c, r, gq_tls_alert (c->tls));
              return r;
            }
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
gq_tlsconn_send_early (gq_tlsconn *c, const uint8_t *data, size_t len)
{
  if (c == NULL || (data == NULL && len > 0) || c->server || c->closed
      || c->connected || !c->early_active)
    return GQ_ERR_INVAL;
  if (len > c->early_max - c->early_sent)
    return GQ_ERR_RANGE;
  while (len > 0)
    {
      size_t n = len < GQ_REC_MAX_PLAINTEXT ? len : GQ_REC_MAX_PLAINTEXT;
      int r = write_record (c, GQ_CT_APPLICATION_DATA, data, n);

      if (r != GQ_OK)
        {
          finish (c, r, -1);
          return r;
        }
      data += n;
      len -= n;
      c->early_sent += n;
    }
  return GQ_OK;
}

int
gq_tlsconn_key_update (gq_tlsconn *c, int request_peer)
{
  int r;

  if (c == NULL || !c->connected || c->closed)
    return GQ_ERR_INVAL;
  r = gq_tls_key_update (c->tls, request_peer);
  if (r != GQ_OK)
    finish (c, r, gq_tls_alert (c->tls));
  return r;
}

int
gq_tlsconn_close (gq_tlsconn *c)
{
  int r;

  if (c == NULL || c->closed)
    return GQ_ERR_INVAL;
  if (c->close_sent)
    return GQ_OK;
  c->close_sent = 1;
  r = send_alert (c, 1, GQ_ALERT_CLOSE_NOTIFY);
  return r;
}

int
gq_tlsconn_is_connected (const gq_tlsconn *c)
{
  return c != NULL && c->connected && !c->closed;
}

int
gq_tlsconn_is_closed (const gq_tlsconn *c)
{
  return c == NULL || c->closed;
}

uint64_t
gq_tlsconn_write_seq (const gq_tlsconn *c)
{
  return gq_record_write_seq (&c->rec);
}

uint64_t
gq_tlsconn_read_seq (const gq_tlsconn *c)
{
  return gq_record_read_seq (&c->rec);
}
