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

/* DTLS 1.3 association: engine, records, reliability.  See dtls.h.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/dtlsrec.h>
#include <gnuquic/dtlshs.h>
#include <gnuquic/dtls.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

#define POOL 4			/* Epoch slots per direction.  */
#define FL_MSGS 12		/* Messages in one flight.  */
#define FL_FRAGS 96		/* Fragments in one flight.  */
#define FL_SENT 64		/* Record numbers remembered for ACKs.  */
#define ACK_RING 8		/* Record numbers we acknowledge.  */
#define PLAIN_HS_OVERHEAD (GQ_DTLS_PLAIN_HEADER + GQ_DTLS_HS_HEADER)
#define CIPHER_HS_OVERHEAD (GQ_DTLS_CIPHER_OVERHEAD + GQ_DTLS_HS_HEADER)

enum { HS_NST = 4, HS_FINISHED = 20, HS_KEY_UPDATE = 24 };

/* ------------------------------------------------------------------ */
/* State                                                              */
/* ------------------------------------------------------------------ */

struct fmsg
{
  uint16_t seq;
  uint8_t type;
  uint64_t epoch;
  size_t off, len;		/* In the buffer; len includes the header.  */
};

struct ffrag
{
  uint8_t msg;
  uint8_t acked, sent;
  uint32_t off, len;		/* Of the message body.  */
};

struct fsent
{
  uint8_t used, frag;
  uint64_t epoch, seq;
};

/* The messages we sent that are not fully acknowledged.  The bytes are
   kept once; the fragments are a fixed plan over them, so a resend puts
   the same bytes in new records (RFC 9147 section 5.5).  */
struct flight
{
  int active;
  uint8_t *buf;
  size_t len, cap;
  struct fmsg msg[FL_MSGS];
  unsigned n_msg;
  struct ffrag frag[FL_FRAGS];
  unsigned n_frag;
  struct fsent sent[FL_SENT];
  unsigned sent_head;
  int explicit_ack;		/* Only an ACK completes it.  */
  int ku;			/* Carries our KeyUpdate.  */
  unsigned rto, retries;
  uint64_t deadline, last_tx;
};

struct gq_dtls
{
  gq_tls *tls;
  int server;
  gq_dtls_events ev;
  unsigned mtu, rto0, max_rto, max_retx;
  uint64_t rekey_after;
  uint64_t now;
  int connected, closed, alert_sent, in_receive;
  int status;

  gq_dtls_epoch wr[POOL], rd[POOL];
  uint64_t wr_app, wr_next, rd_app;	/* 0: none yet.  */
  int have_rd;			/* Any read keys installed.  */
  uint64_t e0_seq;		/* Next epoch 0 record number.  */
  uint16_t tx_seq;		/* Next message_seq.  */

  gq_dtls_reasm reasm;
  gq_dtls_recno ack[ACK_RING];
  unsigned n_ack;
  uint64_t ack_deadline;
  struct flight fl;

  uint8_t *dg, *tmp;		/* Datagram under construction, scratch.  */
  size_t dl;
  uint8_t *rx;			/* Decryption buffer.  */
  size_t rx_cap;

  /* What the datagram being processed did.  */
  int d_hs, d_dup, d_ooo, d_partial, d_was_connected;
};

/* ------------------------------------------------------------------ */
/* Epoch pools                                                        */
/* ------------------------------------------------------------------ */

static gq_dtls_epoch *
pool_find (gq_dtls_epoch *pool, uint64_t epoch)
{
  int i;

  for (i = 0; i < POOL; i++)
    if (pool[i].active && pool[i].epoch == epoch)
      return &pool[i];
  return NULL;
}

/* A slot for EPOCH: the same epoch, a free slot, or the oldest.  */
static gq_dtls_epoch *
pool_slot (gq_dtls_epoch *pool, uint64_t epoch)
{
  gq_dtls_epoch *best = NULL;
  int i;

  if ((best = pool_find (pool, epoch)) != NULL)
    return best;
  for (i = 0; i < POOL; i++)
    if (!pool[i].active)
      return &pool[i];
  for (i = 0; i < POOL; i++)
    if (best == NULL || pool[i].epoch < best->epoch)
      best = &pool[i];
  gq_dtls_epoch_wipe (best);
  return best;
}

/* The epoch we tag our own records with when nothing else is asked:
   application keys if we have them, else handshake keys, else none.  */
static uint64_t
top_epoch (gq_dtls *c)
{
  if (c->wr_app)
    return c->wr_app;
  return pool_find (c->wr, 2) ? 2 : 0;
}

/* Drop write keys nothing needs any more.  */
static void
wr_gc (gq_dtls *c)
{
  int i;
  unsigned m;

  for (i = 0; i < POOL; i++)
    {
      uint64_t e = c->wr[i].epoch;
      int keep = !c->wr[i].active || e == c->wr_app || e == c->wr_next;

      for (m = 0; !keep && c->fl.active && m < c->fl.n_msg; m++)
        keep = c->fl.msg[m].epoch == e;
      if (!keep)
        gq_dtls_epoch_wipe (&c->wr[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Sending records                                                    */
/* ------------------------------------------------------------------ */

static int
flush_dgram (gq_dtls *c)
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

/* Append one record to the datagram being built, sending it first if the
   record does not fit.  */
static int
put_record (gq_dtls *c, uint64_t epoch, unsigned type, const uint8_t *payload,
            size_t plen, uint64_t *seq_used)
{
  size_t need = plen + (epoch ? GQ_DTLS_CIPHER_OVERHEAD : GQ_DTLS_PLAIN_HEADER);
  uint64_t seq = 0;

  if (need > c->mtu)
    return GQ_ERR_BUFSIZE;
  if (c->dl + need > c->mtu)
    TRY (flush_dgram (c));
  if (epoch == 0)
    {
      gq_wbuf w;

      gq_wbuf_init (&w, c->dg + c->dl, c->mtu - c->dl);
      seq = c->e0_seq++;
      gq_dtls_put_plain (&w, type, seq, payload, plen);
      TRY (gq_wbuf_status (&w));
      c->dl += w.len;
    }
  else
    {
      gq_dtls_epoch *e = pool_find (c->wr, epoch);
      size_t n;

      if (e == NULL)
        return GQ_ERR_INVAL;
      TRY (gq_dtls_protect (e, type, payload, plen, c->dg + c->dl,
                            c->mtu - c->dl, &n, &seq));
      c->dl += n;
    }
  if (seq_used)
    *seq_used = seq;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Endings                                                            */
/* ------------------------------------------------------------------ */

static void
finish (gq_dtls *c, int error, int alert)
{
  if (c->closed)
    return;
  c->closed = 1;
  c->status = error < 0 ? error : 0;
  c->ack_deadline = 0;
  c->fl.deadline = 0;
  if (c->ev.closed)
    c->ev.closed (c->ev.user, error, alert);
}

/* Best-effort alert (they are never retransmitted).  */
static void
send_alert (gq_dtls *c, unsigned level, unsigned code)
{
  uint8_t a[2];

  if (c->alert_sent)
    return;
  c->alert_sent = 1;
  a[0] = (uint8_t) level;
  a[1] = (uint8_t) code;
  if (put_record (c, top_epoch (c), GQ_DTLS_CT_ALERT, a, 2, NULL) == GQ_OK)
    flush_dgram (c);
}

/* ------------------------------------------------------------------ */
/* The flight                                                         */
/* ------------------------------------------------------------------ */

static void
fl_release (gq_dtls *c)
{
  struct flight *f = &c->fl;

  if (f->buf)
    {
      gq_wipe (f->buf, f->cap);
      free (f->buf);
    }
  f->buf = NULL;
  f->cap = f->len = 0;
  f->active = 0;
  f->deadline = 0;
}

/* All acknowledged (or implicitly): the flight is over.  A KeyUpdate in
   it now takes effect for our sending (RFC 9147 section 8).  */
static void
fl_complete (gq_dtls *c)
{
  if (c->fl.ku && c->wr_next)
    {
      c->wr_app = c->wr_next;
      c->wr_next = 0;
      gq_tls_set_key_update_busy (c->tls, 0);
    }
  fl_release (c);
  wr_gc (c);
}

/* The peer's answer acknowledges a flight that only needs one.  */
static void
fl_implicit (gq_dtls *c)
{
  if (c->fl.active && !c->fl.explicit_ack)
    fl_complete (c);
}

static void
fl_check_done (gq_dtls *c)
{
  unsigned i;

  if (!c->fl.active)
    return;
  for (i = 0; i < c->fl.n_frag; i++)
    if (!c->fl.frag[i].acked)
      return;
  fl_complete (c);
}

/* Queue a message the engine produced.  Nothing is sent until fl_flush,
   so a flight leaves in as few datagrams as possible.  */
static int
fl_add (gq_dtls *c, uint64_t epoch, const uint8_t *msg, size_t len)
{
  struct flight *f = &c->fl;
  struct fmsg *m;
  size_t body = len - 4, maxfrag, off = 0;
  unsigned mi;

  if (!f->active)
    {
      f->active = 1;
      f->len = 0;
      f->n_msg = f->n_frag = f->sent_head = 0;
      memset (f->sent, 0, sizeof f->sent);
      f->explicit_ack = f->ku = 0;
      f->rto = c->rto0;
      f->retries = 0;
      f->deadline = 0;
    }
  if (f->n_msg == FL_MSGS)
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
  mi = f->n_msg++;
  m = &f->msg[mi];
  m->seq = c->tx_seq++;
  m->type = msg[0];
  m->epoch = epoch;
  m->off = f->len;
  m->len = len;
  memcpy (f->buf + f->len, msg, len);
  f->len += len;
  if (m->type == HS_NST || m->type == HS_KEY_UPDATE
      || (!c->server && m->type == HS_FINISHED))
    f->explicit_ack = 1;
  if (m->type == HS_KEY_UPDATE)
    f->ku = 1;

  /* Fragment plan: as many bytes per record as a datagram holds.  */
  maxfrag = c->mtu - (epoch ? CIPHER_HS_OVERHEAD : PLAIN_HS_OVERHEAD);
  do
    {
      size_t n = body - off < maxfrag ? body - off : maxfrag;
      struct ffrag *fr;

      if (f->n_frag == FL_FRAGS)
        return GQ_ERR_RANGE;
      fr = &f->frag[f->n_frag++];
      fr->msg = (uint8_t) mi;
      fr->off = (uint32_t) off;
      fr->len = (uint32_t) n;
      fr->acked = fr->sent = 0;
      off += n;
    }
  while (off < body);
  return GQ_OK;
}

/* Send the fragments not yet sent (or, on RETRANSMIT, not yet
   acknowledged).  */
static int
fl_flush (gq_dtls *c, int retransmit)
{
  struct flight *f = &c->fl;
  unsigned i;
  int sent_any = 0;

  if (!f->active)
    return GQ_OK;
  for (i = 0; i < f->n_frag; i++)
    {
      struct ffrag *fr = &f->frag[i];
      const struct fmsg *m = &f->msg[fr->msg];
      struct fsent *s;
      uint64_t seq;
      gq_wbuf w;

      if (fr->acked || (fr->sent && !retransmit))
        continue;
      gq_wbuf_init (&w, c->tmp, c->mtu);
      gq_dtls_put_hs_frag (&w, m->type, (uint32_t) (m->len - 4), m->seq,
                           fr->off, f->buf + m->off + 4 + fr->off, fr->len);
      TRY (gq_wbuf_status (&w));
      TRY (put_record (c, m->epoch, GQ_DTLS_CT_HANDSHAKE, w.p, w.len, &seq));
      fr->sent = 1;
      s = &f->sent[f->sent_head++ % FL_SENT];
      s->used = 1;
      s->frag = (uint8_t) i;
      s->epoch = m->epoch;
      s->seq = seq;
      sent_any = 1;
    }
  TRY (flush_dgram (c));
  if (sent_any)
    {
      f->last_tx = c->now;
      f->deadline = c->now + f->rto;
    }
  return GQ_OK;
}

static int
on_ack_rec (void *u, gq_dtls_recno r)
{
  gq_dtls *c = u;
  unsigned i;

  for (i = 0; i < FL_SENT; i++)
    if (c->fl.sent[i].used && c->fl.sent[i].epoch == r.epoch
        && c->fl.sent[i].seq == r.seq)
      c->fl.frag[c->fl.sent[i].frag].acked = 1;
  return 0;
}

static void
process_ack (gq_dtls *c, gq_slice body)
{
  if (!c->fl.active)
    return;
  if (gq_dtls_acks (body, on_ack_rec, c) == GQ_OK)
    fl_check_done (c);
}

/* ------------------------------------------------------------------ */
/* Acknowledging                                                      */
/* ------------------------------------------------------------------ */

static void
ack_add (gq_dtls *c, gq_dtls_recno r)
{
  unsigned i;

  for (i = 0; i < c->n_ack; i++)
    if (c->ack[i].epoch == r.epoch && c->ack[i].seq == r.seq)
      return;
  if (c->n_ack == ACK_RING)
    {
      memmove (c->ack, c->ack + 1, (ACK_RING - 1) * sizeof c->ack[0]);
      c->n_ack--;
    }
  c->ack[c->n_ack++] = r;
}

static int
send_ack (gq_dtls *c)
{
  gq_dtls_recno sorted[ACK_RING];
  unsigned i, j;
  gq_wbuf w;

  c->ack_deadline = 0;
  memcpy (sorted, c->ack, c->n_ack * sizeof sorted[0]);
  /* Numerically increasing order (RFC 9147 section 7).  */
  for (i = 1; i < c->n_ack; i++)
    for (j = i; j > 0
         && (sorted[j - 1].epoch > sorted[j].epoch
             || (sorted[j - 1].epoch == sorted[j].epoch
                 && sorted[j - 1].seq > sorted[j].seq)); j--)
      {
        gq_dtls_recno t = sorted[j];

        sorted[j] = sorted[j - 1];
        sorted[j - 1] = t;
      }
  gq_wbuf_init (&w, c->tmp, c->mtu);
  gq_dtls_put_acks (&w, sorted, c->n_ack);
  TRY (gq_wbuf_status (&w));
  TRY (put_record (c, top_epoch (c), GQ_DTLS_CT_ACK, w.p, w.len, NULL));
  return flush_dgram (c);
}

/* ------------------------------------------------------------------ */
/* Engine sink                                                        */
/* ------------------------------------------------------------------ */

static int
sink_send (void *u, enum gq_level level, const uint8_t *d, size_t n)
{
  gq_dtls *c = u;
  uint64_t epoch;

  switch (level)
    {
    case GQ_LEVEL_INITIAL: epoch = 0; break;
    case GQ_LEVEL_HANDSHAKE: epoch = 2; break;
    case GQ_LEVEL_APPLICATION: epoch = c->wr_app; break;
    default: return 1;
    }
  if (level == GQ_LEVEL_APPLICATION && epoch == 0)
    return 1;			/* No application keys yet.  */
  return fl_add (c, epoch, d, n) != GQ_OK;
}

static int
sink_secret (void *u, const gq_tls_secret *s)
{
  gq_dtls *c = u;
  gq_dtls_epoch tmp;
  uint64_t epoch;
  int i;

  if (s->level == GQ_LEVEL_HANDSHAKE)
    epoch = 2;
  else if (s->level == GQ_LEVEL_APPLICATION)
    epoch = s->dir == GQ_DIR_READ ? (c->rd_app ? c->rd_app + 1 : 3)
                                  : (c->wr_app ? c->wr_app + 1 : 3);
  else
    return 1;			/* No early data over DTLS.  */
  if (gq_dtls_epoch_init (&tmp, epoch, s->aead, s->secret) != GQ_OK)
    return 1;
  if (s->dir == GQ_DIR_READ)
    {
      *pool_slot (c->rd, epoch) = tmp;
      c->have_rd = 1;
      if (s->level == GQ_LEVEL_APPLICATION)
        {
          c->rd_app = epoch;
          /* Keep this and the previous epoch for reordered records.  */
          for (i = 0; i < POOL; i++)
            if (c->rd[i].active && c->rd[i].epoch + 1 < epoch)
              gq_dtls_epoch_wipe (&c->rd[i]);
        }
    }
  else
    {
      *pool_slot (c->wr, epoch) = tmp;
      if (s->level == GQ_LEVEL_APPLICATION)
        {
          if (epoch == 3)
            c->wr_app = 3;
          else
            {
              /* A KeyUpdate of ours: sending under the new epoch waits for
                 the acknowledgement.  */
              c->wr_next = epoch;
              gq_tls_set_key_update_busy (c->tls, 1);
            }
        }
    }
  gq_wipe (&tmp, sizeof tmp);
  return 0;
}

static int
sink_verify (void *u, const gq_slice *chain, size_t n, const char *name)
{
  gq_dtls *c = u;

  return c->ev.verify_peer (c->ev.user, chain, n, name);
}

static int
sink_ticket (void *u, const gq_tls_ticket *t)
{
  gq_dtls *c = u;

  return c->ev.ticket ? c->ev.ticket (c->ev.user, t) : 0;
}

static int
sink_complete (void *u, const gq_tls_info *info)
{
  gq_dtls *c = u;

  c->connected = 1;
  /* Only small post-handshake messages follow; give back the big buffer.  */
  gq_dtls_reasm_trim (&c->reasm);
  return c->ev.connected ? c->ev.connected (c->ev.user, info) : 0;
}

static int
sink_alert (void *u, unsigned code)
{
  gq_dtls *c = u;

  send_alert (c, 2, code);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Creation                                                           */
/* ------------------------------------------------------------------ */

static gq_dtls *
dtls_alloc (const gq_dtls_events *ev, const gq_dtls_params *p, int server,
            size_t max_msg)
{
  gq_dtls *c;
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
  c->rekey_after = p && p->rekey_records ? p->rekey_records
                                         : GQ_DTLS_REKEY_ADVISED;
  gq_dtls_reasm_init (&c->reasm, (uint32_t) max_msg, 0);
  return c;
}

static gq_tls_sink
make_sink (gq_dtls *c)
{
  gq_tls_sink s;

  memset (&s, 0, sizeof s);
  s.user = c;
  s.send = sink_send;
  s.secret = sink_secret;
  s.ticket = sink_ticket;
  s.complete = sink_complete;
  s.alert = sink_alert;
  if (c->ev.verify_peer)
    s.verify_peer = sink_verify;
  return s;
}

int
gq_dtls_client_new (gq_dtls **out, const gq_tls_config *config,
                    const gq_dtls_events *events, const gq_dtls_params *params)
{
  gq_dtls *c;
  gq_tls_config cc;
  gq_tls_sink sink;
  int r;

  if (out == NULL || config == NULL)
    return GQ_ERR_INVAL;
  c = dtls_alloc (events, params, 0,
                  config->max_message_len ? config->max_message_len : 65536);
  if (c == NULL)
    return GQ_ERR_INVAL;
  cc = *config;
  cc.dtls = 1;
  sink = make_sink (c);
  r = gq_tls_client_new (&c->tls, &cc, &sink);
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
gq_dtls_server_new (gq_dtls **out, const gq_tls_server_config *config,
                    const gq_dtls_events *events, const gq_dtls_params *params,
                    const gq_tls_dtls_prime *prime)
{
  gq_dtls *c;
  gq_tls_server_config sc;
  gq_tls_sink sink;
  int r;

  if (out == NULL || config == NULL)
    return GQ_ERR_INVAL;
  c = dtls_alloc (events, params, 1,
                  config->max_message_len ? config->max_message_len : 65536);
  if (c == NULL)
    return GQ_ERR_INVAL;
  sc = *config;
  sc.dtls = 1;
  sink = make_sink (c);
  r = gq_tls_server_new (&c->tls, &sc, &sink);
  if (r == GQ_OK && prime)
    {
      r = gq_tls_server_prime (c->tls, prime);
      /* ClientHello1 and the retry were message 0 of each side, and record
         0 of epoch 0 was the retry.  */
      c->reasm.next_seq = 1;
      c->tx_seq = 1;
      c->e0_seq = 1;
    }
  if (r != GQ_OK)
    {
      gq_tls_free (c->tls);
      free (c->dg);
      free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

void
gq_dtls_free (gq_dtls *c)
{
  int i;

  if (c == NULL)
    return;
  gq_tls_free (c->tls);
  fl_release (c);
  gq_dtls_reasm_free (&c->reasm);
  for (i = 0; i < POOL; i++)
    {
      gq_dtls_epoch_wipe (&c->wr[i]);
      gq_dtls_epoch_wipe (&c->rd[i]);
    }
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

/* A failure of the engine or a protocol error: the alert has been sent by
   the sink (for engine failures); end the association.  */
static void
fail (gq_dtls *c, int status, int alert)
{
  finish (c, status, alert);
}

struct rxctx
{
  gq_dtls *c;
  enum gq_level level;
  gq_dtls_recno rec;
  int acked;
};

static int
on_msg (void *u, unsigned type, gq_slice msg)
{
  struct rxctx *x = u;
  gq_dtls *c = x->c;
  const uint8_t *p = msg.data;
  size_t l = msg.len;
  int r;

  (void) type;
  fl_implicit (c);		/* The peer's next message answers our flight.  */
  r = gq_tls_feed (c->tls, x->level, &p, &l);
  if (r != GQ_OK)
    {
      fail (c, r, gq_tls_alert (c->tls));
      return 1;
    }
  return 0;
}

static int
on_frag (void *u, const gq_dtls_hs_frag *f)
{
  struct rxctx *x = u;
  gq_dtls *c = x->c;
  int d = gq_dtls_reasm_push (&c->reasm, f, on_msg, x), ok = 0;

  if (d == GQ_ERR_HANDLER || c->closed)
    return 1;
  if (d < 0)
    {
      fail (c, d, GQ_ALERT_ILLEGAL_PARAMETER);
      send_alert (c, 2, GQ_ALERT_ILLEGAL_PARAMETER);
      return 1;
    }
  switch (d)
    {
    case GQ_DRX_DELIVERED:
      ok = 1;
      break;
    case GQ_DRX_BUFFERED:
      fl_implicit (c);
      c->d_partial = 1;
      ok = 1;
      break;
    case GQ_DRX_DUPLICATE:
      c->d_dup = 1;
      ok = 1;
      break;
    default:
      c->d_ooo = 1;		/* Not kept, so not acknowledged.  */
      break;
    }
  if (ok && !x->acked)
    {
      ack_add (c, x->rec);
      x->acked = 1;
    }
  return 0;
}

static void
process_hs (gq_dtls *c, enum gq_level level, gq_slice body, gq_dtls_recno rec)
{
  struct rxctx x;

  x.c = c;
  x.level = level;
  x.rec = rec;
  x.acked = 0;
  c->d_hs = 1;
  /* A malformed record is dropped; whatever it completed stays done.  */
  gq_dtls_hs_parse (body, c->reasm.max_len, on_frag, &x);
}

static void
handle_alert (gq_dtls *c, gq_slice a)
{
  if (a.len != 2)
    return;
  if (a.data[1] == GQ_ALERT_CLOSE_NOTIFY)
    finish (c, 0, GQ_ALERT_CLOSE_NOTIFY);
  else
    finish (c, GQ_ERR_PROTOCOL, a.data[1]);
}

static int
on_record (void *u, const gq_drec *rec)
{
  gq_dtls *c = u;
  gq_dtls_recno no;

  if (c->closed)
    return 1;
  if (rec->kind == GQ_DREC_PLAINTEXT)
    {
      if (rec->epoch != 0)
        return 0;
      no.epoch = 0;
      no.seq = rec->seq;
      switch (rec->type)
        {
        case GQ_DTLS_CT_HANDSHAKE:
          process_hs (c, GQ_LEVEL_INITIAL, rec->body, no);
          break;
        case GQ_DTLS_CT_ALERT:
          /* Unauthenticated: honoured only while nothing is protected yet
             (a server refusing our ClientHello), else it could be forged
             by anyone who can guess the addresses.  */
          if (!c->have_rd)
            handle_alert (c, rec->body);
          break;
        case GQ_DTLS_CT_ACK:
          process_ack (c, rec->body);
          break;
        default:
          break;
        }
    }
  else
    {
      gq_dtls_epoch *e = NULL;
      unsigned type;
      size_t len, i;
      uint64_t seq;
      gq_slice pt;
      int r;

      for (i = 0; i < POOL; i++)
        if (c->rd[i].active && (c->rd[i].epoch & 3) == rec->epoch
            && (e == NULL || c->rd[i].epoch > e->epoch))
          e = &c->rd[i];
      if (e == NULL)
        return 0;
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
      r = gq_dtls_deprotect (e, rec, c->rx, c->rx_cap, &type, &len, &seq);
      if (r != GQ_OK)
        return 0;		/* Silently dropped.  */
      pt.data = c->rx;
      pt.len = len;
      no.epoch = e->epoch;
      no.seq = seq;
      switch (type)
        {
        case GQ_DTLS_CT_HANDSHAKE:
          process_hs (c, e->epoch == 2 ? GQ_LEVEL_HANDSHAKE
                                       : GQ_LEVEL_APPLICATION, pt, no);
          break;
        case GQ_DTLS_CT_APPLICATION_DATA:
          /* Not before the peer's Finished has been verified.  */
          if (c->connected && e->epoch >= 3 && len > 0
              && c->ev.data (c->ev.user, pt.data, pt.len))
            fail (c, GQ_ERR_HANDLER, -1);
          break;
        case GQ_DTLS_CT_ALERT:
          handle_alert (c, pt);
          break;
        case GQ_DTLS_CT_ACK:
          process_ack (c, pt);
          break;
        default:
          break;
        }
    }
  return c->closed;
}

int
gq_dtls_start (gq_dtls *c, uint64_t now)
{
  int r;

  if (c == NULL || c->server || c->closed || c->in_receive)
    return GQ_ERR_INVAL;
  c->now = now;
  r = gq_tls_start (c->tls);
  if (r != GQ_OK)
    {
      fail (c, r, gq_tls_alert (c->tls));
      return r;
    }
  r = fl_flush (c, 0);
  if (r != GQ_OK)
    fail (c, r, -1);
  return c->status;
}

int
gq_dtls_receive (gq_dtls *c, const uint8_t *dgram, size_t len, uint64_t now)
{
  int r;

  if (c == NULL || (dgram == NULL && len > 0) || c->in_receive)
    return GQ_ERR_INVAL;
  if (c->closed)
    return c->status;
  c->in_receive = 1;
  c->now = now;
  c->d_hs = c->d_dup = c->d_ooo = c->d_partial = 0;
  c->d_was_connected = c->connected;

  gq_dtls_records (dgram, len, on_record, c);

  if (!c->closed)
    {
      /* What we send in answer, then whether an ACK is still owed: a
         flight of ours implicitly acknowledges theirs, except at the end
         of the handshake (the server acks the client's final flight) and
         after it (every post-handshake message).  */
      r = fl_flush (c, 0);
      if (r != GQ_OK)
        fail (c, r, -1);
    }
  if (!c->closed && c->d_hs)
    {
      int must = c->d_ooo || (c->server ? c->connected : c->d_was_connected);

      if (c->d_dup && c->fl.active
          && now - c->fl.last_tx >= c->fl.rto / 4)
        {
          /* The peer repeated itself: part of our answer was lost.  */
          r = fl_flush (c, 1);
          if (r != GQ_OK)
            fail (c, r, -1);
        }
      else if (c->d_dup && !c->fl.active)
        must = 1;
      if (!c->closed && must)
        {
          r = send_ack (c);
          if (r != GQ_OK)
            fail (c, r, -1);
        }
      else if (!c->closed && c->d_partial && c->ack_deadline == 0)
        c->ack_deadline = now + c->rto0 / 4;
    }
  c->in_receive = 0;
  return c->status;
}

/* ------------------------------------------------------------------ */
/* Sending, updates, timers                                           */
/* ------------------------------------------------------------------ */

size_t
gq_dtls_max_payload (const gq_dtls *c)
{
  return c->mtu - GQ_DTLS_CIPHER_OVERHEAD;
}

int
gq_dtls_key_update (gq_dtls *c, int request_peer)
{
  int r;

  if (c == NULL || !c->connected || c->closed || c->wr_next)
    return GQ_ERR_INVAL;
  r = gq_tls_key_update (c->tls, request_peer);
  if (r == GQ_OK)
    r = fl_flush (c, 0);
  if (r != GQ_OK)
    fail (c, r, -1);
  return r;
}

int
gq_dtls_send (gq_dtls *c, const uint8_t *data, size_t len)
{
  gq_dtls_epoch *e;
  int r;

  if (c == NULL || (data == NULL && len > 0) || !c->connected || c->closed
      || c->wr_app == 0)
    return GQ_ERR_INVAL;
  if (len > gq_dtls_max_payload (c))
    return GQ_ERR_BUFSIZE;
  e = pool_find (c->wr, c->wr_app);
  if (e && e->send_seq >= c->rekey_after && !c->wr_next)
    gq_dtls_key_update (c, 0);		/* Best effort; the limit is firm.  */
  if (c->closed)
    return c->status;
  r = put_record (c, c->wr_app, GQ_DTLS_CT_APPLICATION_DATA, data, len, NULL);
  if (r == GQ_OK)
    r = flush_dgram (c);
  if (r != GQ_OK)
    {
      if (r == GQ_ERR_RANGE)
        send_alert (c, 1, GQ_ALERT_CLOSE_NOTIFY);
      fail (c, r, -1);
    }
  return r;
}

int
gq_dtls_close (gq_dtls *c)
{
  if (c == NULL || c->closed)
    return GQ_ERR_INVAL;
  send_alert (c, 1, GQ_ALERT_CLOSE_NOTIFY);
  finish (c, 0, GQ_ALERT_CLOSE_NOTIFY);
  return GQ_OK;
}

uint64_t
gq_dtls_deadline (const gq_dtls *c)
{
  uint64_t d = 0;

  if (c == NULL || c->closed)
    return 0;
  if (c->fl.active && c->fl.deadline)
    d = c->fl.deadline;
  if (c->ack_deadline && (d == 0 || c->ack_deadline < d))
    d = c->ack_deadline;
  return d;
}

int
gq_dtls_timeout (gq_dtls *c, uint64_t now)
{
  int r;

  if (c == NULL)
    return GQ_ERR_INVAL;
  if (c->closed)
    return c->status;
  c->now = now;
  if (c->ack_deadline && now >= c->ack_deadline)
    {
      r = send_ack (c);
      if (r != GQ_OK)
        fail (c, r, -1);
    }
  if (!c->closed && c->fl.active && c->fl.deadline && now >= c->fl.deadline)
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
gq_dtls_is_connected (const gq_dtls *c)
{
  return c != NULL && c->connected && !c->closed;
}

int
gq_dtls_is_closed (const gq_dtls *c)
{
  return c == NULL || c->closed;
}

int
gq_dtls_export (const gq_dtls *c, const char *label, const uint8_t *context,
                size_t context_len, uint8_t *out, size_t out_len)
{
  if (c == NULL)
    return GQ_ERR_INVAL;
  return gq_tls_export (c->tls, label, context, context_len, out, out_len);
}
