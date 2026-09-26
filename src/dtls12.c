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

/* DTLS 1.2 association: engine, records, flights.  See dtls12.h.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/dtls12rec.h>
#include <gnuquic/dtlshs.h>
#include <gnuquic/dtls12.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

#define FL_MSGS 12		/* Messages in one flight.  */
#define FL_ITEMS 16		/* Messages and ChangeCipherSpecs.  */
#define PLAIN_HS_OVERHEAD (GQ_DTLS12_HEADER + GQ_DTLS_HS_HEADER)
#define CIPHER_HS_OVERHEAD (GQ_DTLS12_CIPHER_OVERHEAD + GQ_DTLS_HS_HEADER)

/* ------------------------------------------------------------------ */
/* State                                                              */
/* ------------------------------------------------------------------ */

struct fmsg
{
  uint16_t seq;
  uint8_t type;
  uint16_t epoch;
  size_t off, len;		/* In the buffer; len includes the header.  */
};

struct fitem
{
  uint8_t ccs;			/* A ChangeCipherSpec, else message MSG.  */
  uint8_t msg;
};

/* Everything we last sent, in order.  The bytes are kept once and cut
   into records again for each transmission.  */
struct flight
{
  int active;
  int final;			/* The handshake's last: no timer.  */
  int superseded;		/* The peer has begun its answer; keep the
				   timer until ours replaces this, since the
				   rest of the answer may still be lost.  */
  uint8_t *buf;
  size_t len, cap;
  struct fmsg msg[FL_MSGS];
  unsigned n_msg;
  struct fitem item[FL_ITEMS];
  unsigned n_item, sent_items;
  unsigned rto, retries;
  uint64_t deadline, last_tx;
};

struct gq_dtls12
{
  gq_tls12 *tls;
  int server;
  gq_dtls_events ev;
  unsigned mtu, rto0, max_rto, max_retx;
  uint64_t now;
  int connected, closed, alert_sent, in_receive;
  int status;

  gq_dtls12_epoch wr0, rd0, wr1, rd1;	/* Epoch 0 (plain) and 1.  */
  uint16_t wr_epoch;		/* Epoch of the messages we add now.  */
  int ccs_pending;		/* A ChangeCipherSpec arrived early.  */
  uint16_t tx_seq;		/* message_seq of the next message.  */

  gq_dtls_reasm reasm;
  struct flight fl;

  uint8_t *dg, *tmp;		/* Datagram under construction, scratch.  */
  size_t dl;
  uint8_t *rx;
  size_t rx_cap;

  int d_dup, d_hs;		/* What the datagram being processed did.  */
};

/* ------------------------------------------------------------------ */
/* Sending records                                                    */
/* ------------------------------------------------------------------ */

static int
flush_dgram (gq_dtls12 *c)
{
  int r = GQ_OK;

  if (c->dl)
    {
      size_t n = c->dl;

      c->dl = 0;
      if (c->ev.send (c->ev.user, c->dg, n))
        r = GQ_ERR_HANDLER;
    }
  return r;
}

/* Append one record under EPOCH (0 plain, else protected), sending the
   datagram first if it does not fit.  */
static int
put_record (gq_dtls12 *c, unsigned epoch, unsigned type,
            const uint8_t *payload, size_t plen)
{
  size_t need = plen + (epoch ? GQ_DTLS12_CIPHER_OVERHEAD : GQ_DTLS12_HEADER);

  if (need > c->mtu)
    return GQ_ERR_BUFSIZE;
  if (c->dl + need > c->mtu)
    TRY (flush_dgram (c));
  if (epoch == 0)
    {
      gq_wbuf w;

      gq_wbuf_init (&w, c->dg + c->dl, c->mtu - c->dl);
      gq_dtls12_put_plain (&w, &c->wr0, type, payload, plen);
      TRY (gq_wbuf_status (&w));
      c->dl += w.len;
    }
  else
    {
      size_t n;

      TRY (gq_dtls12_protect (&c->wr1, type, payload, plen, c->dg + c->dl,
                              c->mtu - c->dl, &n));
      c->dl += n;
    }
  return GQ_OK;
}

static void
finish (gq_dtls12 *c, int error, int alert)
{
  if (c->closed)
    return;
  c->closed = 1;
  c->status = error < 0 ? error : 0;
  c->fl.deadline = 0;
  if (c->ev.closed)
    c->ev.closed (c->ev.user, error, alert);
}

/* Best-effort alert, never retransmitted.  */
static void
send_alert (gq_dtls12 *c, unsigned level, unsigned code)
{
  uint8_t a[2];

  if (c->alert_sent)
    return;
  c->alert_sent = 1;
  a[0] = (uint8_t) level;
  a[1] = (uint8_t) code;
  if (put_record (c, c->wr_epoch, GQ_D12_CT_ALERT, a, 2) == GQ_OK)
    flush_dgram (c);
}

/* ------------------------------------------------------------------ */
/* The flight                                                         */
/* ------------------------------------------------------------------ */

static void
fl_release (gq_dtls12 *c)
{
  struct flight *f = &c->fl;

  if (f->buf)
    {
      gq_wipe (f->buf, f->cap);
      free (f->buf);
    }
  f->buf = NULL;
  f->cap = f->len = 0;
  f->active = f->final = f->superseded = 0;
  f->deadline = 0;
}

static void
fl_start (gq_dtls12 *c)
{
  struct flight *f = &c->fl;

  /* The engine's answer replaces what we sent before.  */
  if (f->active && f->superseded)
    fl_release (c);
  if (f->active)
    return;
  f->active = 1;
  f->final = 0;
  f->superseded = 0;
  f->len = 0;
  f->n_msg = f->n_item = f->sent_items = 0;
  f->rto = c->rto0;
  f->retries = 0;
  f->deadline = 0;
}

static int
fl_add_msg (gq_dtls12 *c, const uint8_t *msg, size_t len)
{
  struct flight *f = &c->fl;
  struct fmsg *m;

  fl_start (c);
  if (f->n_msg == FL_MSGS || f->n_item == FL_ITEMS)
    return GQ_ERR_RANGE;
  if (f->len + len > f->cap)
    {
      size_t cap = f->cap ? f->cap : 1024;
      uint8_t *nb;

      while (cap < f->len + len)
        cap *= 2;
      nb = malloc (cap);
      if (nb == NULL)
        return GQ_ERR_NOMEM;
      if (f->buf)
        {
          memcpy (nb, f->buf, f->len);
          gq_wipe (f->buf, f->cap);
          free (f->buf);
        }
      f->buf = nb;
      f->cap = cap;
    }
  m = &f->msg[f->n_msg];
  m->seq = c->tx_seq++;
  m->type = msg[0];
  m->epoch = c->wr_epoch;
  m->off = f->len;
  m->len = len;
  memcpy (f->buf + f->len, msg, len);
  f->len += len;
  f->item[f->n_item].ccs = 0;
  f->item[f->n_item++].msg = (uint8_t) f->n_msg++;
  return GQ_OK;
}

static int
fl_add_ccs (gq_dtls12 *c)
{
  struct flight *f = &c->fl;

  fl_start (c);
  if (f->n_item == FL_ITEMS)
    return GQ_ERR_RANGE;
  f->item[f->n_item].ccs = 1;
  f->item[f->n_item++].msg = 0;
  return GQ_OK;
}

/* Send the items not yet sent, or (RETRANSMIT) all of them.  */
static int
fl_flush (gq_dtls12 *c, int retransmit)
{
  struct flight *f = &c->fl;
  unsigned i;
  int any = 0;

  if (!f->active)
    return GQ_OK;
  for (i = retransmit ? 0 : f->sent_items; i < f->n_item; i++)
    {
      const struct fmsg *m;
      size_t body, off = 0, maxfrag;

      any = 1;
      if (f->item[i].ccs)
        {
          static const uint8_t one = 1;

          TRY (put_record (c, 0, GQ_D12_CT_CHANGE_CIPHER_SPEC, &one, 1));
          continue;
        }
      m = &f->msg[f->item[i].msg];
      body = m->len - 4;
      maxfrag = c->mtu - (m->epoch ? CIPHER_HS_OVERHEAD : PLAIN_HS_OVERHEAD);
      do
        {
          size_t n = body - off < maxfrag ? body - off : maxfrag;
          gq_wbuf w;

          gq_wbuf_init (&w, c->tmp, c->mtu);
          gq_dtls_put_hs_frag (&w, m->type, (uint32_t) body, m->seq,
                               (uint32_t) off, f->buf + m->off + 4 + off, n);
          TRY (gq_wbuf_status (&w));
          TRY (put_record (c, m->epoch, GQ_D12_CT_HANDSHAKE, w.p, w.len));
          off += n;
        }
      while (off < body);
    }
  f->sent_items = f->n_item;
  TRY (flush_dgram (c));
  if (any)
    {
      f->last_tx = c->now;
      f->deadline = f->final ? 0 : c->now + f->rto;
    }
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Engine sink                                                        */
/* ------------------------------------------------------------------ */

static int
sink_send (void *u, const uint8_t *d, size_t n)
{
  gq_dtls12 *c = u;

  return fl_add_msg (c, d, n) != GQ_OK;
}

static int
sink_change_keys (void *u, enum gq_dir dir, enum gq_aead aead,
                  const uint8_t *key, size_t key_len, const uint8_t *iv,
                  size_t iv_len)
{
  gq_dtls12 *c = u;

  if (dir == GQ_DIR_WRITE)
    {
      /* The ChangeCipherSpec goes out under the old epoch, in order with
         the messages before it; what follows is epoch 1.  */
      if (fl_add_ccs (c) != GQ_OK
          || gq_dtls12_epoch_init (&c->wr1, 1, aead, key, key_len, iv, iv_len)
             != GQ_OK)
        return 1;
      c->wr_epoch = 1;
    }
  else if (gq_dtls12_epoch_init (&c->rd1, 1, aead, key, key_len, iv, iv_len)
           != GQ_OK)
    return 1;
  return 0;
}

static int
sink_verify (void *u, const gq_slice *chain, size_t n, const char *name)
{
  gq_dtls12 *c = u;

  return c->ev.verify_peer (c->ev.user, chain, n, name);
}

static int
sink_ticket (void *u, const gq_tls_ticket *t)
{
  gq_dtls12 *c = u;

  return c->ev.ticket ? c->ev.ticket (c->ev.user, t) : 0;
}

static int
sink_complete (void *u, const gq_tls_info *info)
{
  gq_dtls12 *c = u;

  c->connected = 1;
  /* What the peer's Finished answered is done with.  What we sent in this
     very step has no answer: keep it, without a timer, for the peer that
     lost it.  */
  if (c->fl.active)
    {
      if (c->fl.superseded)
        fl_release (c);
      else
        c->fl.final = 1;
    }
  gq_dtls_reasm_trim (&c->reasm);
  return c->ev.connected ? c->ev.connected (c->ev.user, info) : 0;
}

static int
sink_alert (void *u, unsigned code)
{
  gq_dtls12 *c = u;

  send_alert (c, 2, code);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Creation                                                           */
/* ------------------------------------------------------------------ */

static gq_dtls12 *
alloc12 (const gq_dtls_events *ev, const gq_dtls_params *p, int server,
         size_t max_msg)
{
  gq_dtls12 *c;
  unsigned mtu = p && p->mtu ? p->mtu : 1200;

  if (ev == NULL || ev->send == NULL || ev->data == NULL || mtu < 256
      || mtu > 65000)
    return NULL;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return NULL;
  c->dg = malloc (2 * (size_t) mtu);
  if (c->dg == NULL)
    {
      free (c);
      return NULL;
    }
  c->tmp = c->dg + mtu;
  c->mtu = mtu;
  c->server = server;
  c->ev = *ev;
  c->rto0 = p && p->rto_ms ? p->rto_ms : 1000;
  c->max_rto = p && p->max_rto_ms ? p->max_rto_ms : 60000;
  c->max_retx = p && p->max_retransmits ? p->max_retransmits : 6;
  gq_dtls12_epoch_plain (&c->wr0);
  gq_dtls12_epoch_plain (&c->rd0);
  gq_dtls_reasm_init (&c->reasm, (uint32_t) max_msg, 0);
  return c;
}

static gq_tls12_sink
make_sink (gq_dtls12 *c)
{
  gq_tls12_sink s;

  memset (&s, 0, sizeof s);
  s.user = c;
  s.send = sink_send;
  s.change_keys = sink_change_keys;
  s.ticket = sink_ticket;
  s.complete = sink_complete;
  s.alert = sink_alert;
  if (c->ev.verify_peer)
    s.verify_peer = sink_verify;
  return s;
}

int
gq_dtls12_client_new (gq_dtls12 **out, const gq_tls_config *config,
                      const gq_dtls_events *events,
                      const gq_dtls_params *params)
{
  gq_dtls12 *c;
  gq_tls_config cc;
  gq_tls12_sink sink;
  int r;

  if (out == NULL || config == NULL)
    return GQ_ERR_INVAL;
  c = alloc12 (events, params, 0,
               config->max_message_len ? config->max_message_len : 65536);
  if (c == NULL)
    return GQ_ERR_INVAL;
  cc = *config;
  cc.dtls = 1;
  sink = make_sink (c);
  r = gq_tls12_client_new (&c->tls, &cc, &sink);
  if (r != GQ_OK)
    {
      free (c->dg);
      free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

int
gq_dtls12_server_new (gq_dtls12 **out, const gq_tls_server_config *config,
                      const gq_dtls_events *events,
                      const gq_dtls_params *params,
                      const gq_dtls12_prime *prime)
{
  gq_dtls12 *c;
  gq_tls_server_config sc;
  gq_tls12_sink sink;
  int r;

  if (out == NULL || config == NULL)
    return GQ_ERR_INVAL;
  c = alloc12 (events, params, 1,
               config->max_message_len ? config->max_message_len : 65536);
  if (c == NULL)
    return GQ_ERR_INVAL;
  sc = *config;
  sc.dtls = 1;
  sink = make_sink (c);
  r = gq_tls12_server_new (&c->tls, &sc, &sink);
  if (r == GQ_OK && prime)
    {
      /* ClientHello1 and the HelloVerifyRequest were message 0 of each
         side; the HelloVerifyRequest used a record number of its own.  */
      r = gq_tls12_dtls_prime (c->tls, 1, 1);
      c->reasm.next_seq = 1;
      c->tx_seq = 1;
      c->wr0.send_seq = prime->e0_seq;
    }
  if (r != GQ_OK)
    {
      gq_tls12_free (c->tls);
      free (c->dg);
      free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

void
gq_dtls12_free (gq_dtls12 *c)
{
  if (c == NULL)
    return;
  gq_tls12_free (c->tls);
  fl_release (c);
  gq_dtls_reasm_free (&c->reasm);
  gq_dtls12_epoch_wipe (&c->wr1);
  gq_dtls12_epoch_wipe (&c->rd1);
  if (c->rx)
    {
      gq_wipe (c->rx, c->rx_cap);
      free (c->rx);
    }
  free (c->dg);
  gq_wipe (c, sizeof *c);
  free (c);
}

/* ------------------------------------------------------------------ */
/* Receiving                                                          */
/* ------------------------------------------------------------------ */

static void
fail (gq_dtls12 *c, int status, int alert)
{
  finish (c, status, alert);
}

/* A ChangeCipherSpec that came early is taken as soon as the engine can.  */
static int
try_ccs (gq_dtls12 *c)
{
  int r;

  if (!c->ccs_pending || !gq_tls12_expects_ccs (c->tls))
    return GQ_OK;
  c->ccs_pending = 0;
  r = gq_tls12_change_cipher_spec (c->tls);
  if (r != GQ_OK)
    fail (c, r, gq_tls12_alert (c->tls));
  return r;
}

struct rxctx
{
  gq_dtls12 *c;
};

static int
on_msg (void *u, unsigned type, gq_slice msg)
{
  struct rxctx *x = u;
  gq_dtls12 *c = x->c;
  const uint8_t *p = msg.data;
  size_t l = msg.len;
  int r;

  (void) type;
  /* The peer's next message answers our flight (a final one stays).  */
  if (c->fl.active && !c->fl.final)
    c->fl.superseded = 1;
  r = gq_tls12_feed (c->tls, &p, &l);
  if (r != GQ_OK)
    {
      fail (c, r, gq_tls12_alert (c->tls));
      return 1;
    }
  return try_ccs (c) != GQ_OK;
}

static int
on_frag (void *u, const gq_dtls_hs_frag *f)
{
  struct rxctx *x = u;
  gq_dtls12 *c = x->c;
  int d = gq_dtls_reasm_push (&c->reasm, f, on_msg, x);

  if (d == GQ_ERR_HANDLER || c->closed)
    return 1;
  if (d < 0)
    {
      send_alert (c, 2, GQ_ALERT_ILLEGAL_PARAMETER);
      fail (c, d, GQ_ALERT_ILLEGAL_PARAMETER);
      return 1;
    }
  if (d == GQ_DRX_BUFFERED && c->fl.active && !c->fl.final)
    c->fl.superseded = 1;
  if (d == GQ_DRX_DUPLICATE)
    c->d_dup = 1;
  return 0;
}

static void
process_hs (gq_dtls12 *c, gq_slice body)
{
  struct rxctx x;

  x.c = c;
  c->d_hs = 1;
  gq_dtls_hs_parse (body, c->reasm.max_len, on_frag, &x);
}

static void
handle_alert (gq_dtls12 *c, gq_slice a)
{
  if (a.len != 2)
    return;
  if (a.data[1] == GQ_ALERT_CLOSE_NOTIFY)
    finish (c, 0, GQ_ALERT_CLOSE_NOTIFY);
  else
    finish (c, GQ_ERR_PROTOCOL, a.data[1]);
}

static int
on_record (void *u, const gq_d12rec *rec)
{
  gq_dtls12 *c = u;

  if (c->closed)
    return 1;
  if (rec->epoch == 0)
    {
      if (!gq_dtls12_replay_ok (&c->rd0, rec->seq))
        return 0;
      switch (rec->type)
        {
        case GQ_D12_CT_HANDSHAKE:
          gq_dtls12_replay_update (&c->rd0, rec->seq);
          process_hs (c, rec->body);
          break;
        case GQ_D12_CT_CHANGE_CIPHER_SPEC:
          if (rec->body.len != 1 || rec->body.data[0] != 1)
            break;
          gq_dtls12_replay_update (&c->rd0, rec->seq);
          if (!c->rd1.active)
            {
              c->ccs_pending = 1;
              try_ccs (c);
            }
          break;
        case GQ_D12_CT_ALERT:
          /* Unauthenticated: honoured only before anything is protected,
             else anyone who can guess the addresses could end us.  */
          if (!c->rd1.active)
            {
              gq_dtls12_replay_update (&c->rd0, rec->seq);
              handle_alert (c, rec->body);
            }
          break;
        default:
          break;
        }
    }
  else if (rec->epoch == 1 && c->rd1.active)
    {
      size_t len;
      gq_slice pt;

      if (rec->body.len > c->rx_cap)
        {
          uint8_t *nb = malloc (rec->body.len);

          if (nb == NULL)
            return 0;
          if (c->rx)
            {
              gq_wipe (c->rx, c->rx_cap);
              free (c->rx);
            }
          c->rx = nb;
          c->rx_cap = rec->body.len;
        }
      if (gq_dtls12_deprotect (&c->rd1, rec, c->rx, c->rx_cap, &len)
          != GQ_OK)
        return 0;		/* Silently dropped.  */
      pt.data = c->rx;
      pt.len = len;
      switch (rec->type)
        {
        case GQ_D12_CT_HANDSHAKE:
          if (len > 0)
            process_hs (c, pt);
          break;
        case GQ_D12_CT_APPLICATION_DATA:
          /* Not before the peer's Finished has been verified.  */
          if (c->connected && len > 0
              && c->ev.data (c->ev.user, pt.data, pt.len))
            fail (c, GQ_ERR_HANDLER, -1);
          break;
        case GQ_D12_CT_ALERT:
          handle_alert (c, pt);
          break;
        default:
          break;
        }
    }
  return c->closed;
}

int
gq_dtls12_start (gq_dtls12 *c, uint64_t now)
{
  int r;

  if (c == NULL || c->server || c->closed || c->in_receive)
    return GQ_ERR_INVAL;
  c->now = now;
  r = gq_tls12_start (c->tls);
  if (r != GQ_OK)
    {
      fail (c, r, gq_tls12_alert (c->tls));
      return r;
    }
  r = fl_flush (c, 0);
  if (r != GQ_OK)
    fail (c, r, -1);
  return c->status;
}

int
gq_dtls12_client_adopt (gq_dtls12 *c, const uint8_t *hello, size_t len,
                        uint64_t next_seq, uint64_t now)
{
  int r;

  if (c == NULL || c->server || c->closed || c->in_receive)
    return GQ_ERR_INVAL;
  c->now = now;
  r = gq_tls12_client_adopt (c->tls, hello, len);
  if (r == GQ_OK)
    r = fl_add_msg (c, hello, len);
  if (r != GQ_OK)
    {
      fail (c, r, gq_tls12_alert (c->tls));
      return r;
    }
  /* It is on the wire already: note when, and time its retransmission.  */
  c->wr0.send_seq = next_seq;
  c->fl.sent_items = c->fl.n_item;
  c->fl.last_tx = now;
  c->fl.deadline = now + c->fl.rto;
  return GQ_OK;
}

int
gq_dtls12_receive (gq_dtls12 *c, const uint8_t *dgram, size_t len,
                   uint64_t now)
{
  int r;

  if (c == NULL || (dgram == NULL && len > 0) || c->in_receive)
    return GQ_ERR_INVAL;
  if (c->closed)
    return c->status;
  c->in_receive = 1;
  c->now = now;
  c->d_dup = c->d_hs = 0;

  gq_dtls12_records (dgram, len, on_record, c);

  if (!c->closed)
    {
      /* Our answer, if the engine produced one.  */
      r = fl_flush (c, 0);
      if (r != GQ_OK)
        fail (c, r, -1);
    }
  /* The peer repeated a message: our last flight was lost.  */
  if (!c->closed && c->d_dup && c->fl.active
      && now - c->fl.last_tx >= c->fl.rto / 4)
    {
      r = fl_flush (c, 1);
      if (r != GQ_OK)
        fail (c, r, -1);
    }
  c->in_receive = 0;
  return c->status;
}

/* ------------------------------------------------------------------ */
/* Sending, timers                                                    */
/* ------------------------------------------------------------------ */

size_t
gq_dtls12_max_payload (const gq_dtls12 *c)
{
  return c->mtu - GQ_DTLS12_CIPHER_OVERHEAD;
}

int
gq_dtls12_send (gq_dtls12 *c, const uint8_t *data, size_t len)
{
  int r;

  if (c == NULL || (data == NULL && len > 0) || !c->connected || c->closed
      || !c->wr1.active)
    return GQ_ERR_INVAL;
  if (len > gq_dtls12_max_payload (c))
    return GQ_ERR_BUFSIZE;
  r = put_record (c, 1, GQ_D12_CT_APPLICATION_DATA, data, len);
  if (r == GQ_OK)
    r = flush_dgram (c);
  if (r != GQ_OK)
    {
      /* At the AEAD limit there is no rekeying: say goodbye and stop.  */
      if (r == GQ_ERR_RANGE)
        send_alert (c, 1, GQ_ALERT_CLOSE_NOTIFY);
      fail (c, r, -1);
    }
  return r;
}

int
gq_dtls12_close (gq_dtls12 *c)
{
  if (c == NULL || c->closed)
    return GQ_ERR_INVAL;
  send_alert (c, 1, GQ_ALERT_CLOSE_NOTIFY);
  finish (c, 0, GQ_ALERT_CLOSE_NOTIFY);
  return GQ_OK;
}

uint64_t
gq_dtls12_deadline (const gq_dtls12 *c)
{
  if (c == NULL || c->closed || !c->fl.active || c->fl.final)
    return 0;
  return c->fl.deadline;
}

int
gq_dtls12_timeout (gq_dtls12 *c, uint64_t now)
{
  int r;

  if (c == NULL)
    return GQ_ERR_INVAL;
  if (c->closed)
    return c->status;
  c->now = now;
  if (c->fl.active && !c->fl.final && c->fl.deadline && now >= c->fl.deadline)
    {
      if (++c->fl.retries > c->max_retx)
        {
          fail (c, GQ_ERR_TIMEOUT, -1);
          return GQ_ERR_TIMEOUT;
        }
      c->fl.rto = c->fl.rto * 2 > c->max_rto ? c->max_rto : c->fl.rto * 2;
      r = fl_flush (c, 1);
      if (r != GQ_OK)
        fail (c, r, -1);
    }
  return c->status;
}

int
gq_dtls12_is_connected (const gq_dtls12 *c)
{
  return c != NULL && c->connected && !c->closed;
}

int
gq_dtls12_is_closed (const gq_dtls12 *c)
{
  return c == NULL || c->closed;
}

int
gq_dtls12_export (const gq_dtls12 *c, const char *label,
                  const uint8_t *context, size_t context_len, uint8_t *out,
                  size_t out_len)
{
  if (c == NULL)
    return GQ_ERR_INVAL;
  return gq_tls12_export (c->tls, label, context, context_len, out, out_len);
}
