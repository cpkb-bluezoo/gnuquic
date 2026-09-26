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

/* ---- Keys ---- */

static int
derive_next_read (gq_conn *c)
{
  gq_packet_keys *cur = &c->sp[SP_APP].rk;
  int r = gq_packet_keys_update (c->version, cur, c->rsec, c->rsec_len,
                                 c->rsec_next, &c->rk_next);

  c->have_rk_next = r == GQ_OK;
  return r;
}

void
conn_install_keys (gq_conn *c, const gq_tls_secret *s)
{
  int sp = SPACE_OF_LEVEL (s->level);
  gq_packet_keys k;

  if (sp < 0)
    return;			/* 0-RTT is not supported.  */
  if (gq_packet_keys_derive (c->version, s->aead, s->secret, s->len, &k)
      != GQ_OK)
    {
      conn_fail (c, GQ_QERR_INTERNAL, "key derivation failed");
      return;
    }
  if (s->dir == GQ_DIR_READ)
    {
      c->sp[sp].rk = k;
      c->sp[sp].have_rk = 1;
      if (sp == SP_APP)
        {
          memcpy (c->rsec, s->secret, s->len);
          c->rsec_len = s->len;
          derive_next_read (c);
        }
    }
  else
    {
      c->sp[sp].wk = k;
      c->sp[sp].have_wk = 1;
      if (sp == SP_APP)
        {
          memcpy (c->wsec, s->secret, s->len);
          c->wsec_len = s->len;
        }
    }
}

/* Replace our sending keys with the next generation.  */
static int
write_key_update (gq_conn *c)
{
  space *s = &c->sp[SP_APP];
  gq_packet_keys next;
  uint8_t next_secret[GQ_MAX_HASH_LEN];

  if (gq_packet_keys_update (c->version, &s->wk, c->wsec, c->wsec_len,
                             next_secret, &next) != GQ_OK)
    return GQ_ERR_CRYPTO;
  s->wk = next;
  memcpy (c->wsec, next_secret, c->wsec_len);
  c->w_phase ^= 1;
  c->w_first_pn = s->next_pn;
  c->w_phase_acked = 0;
  c->key_updates++;
  memset (next_secret, 0, sizeof next_secret);
  return GQ_OK;
}

int
gq_conn_update_keys (gq_conn *c, uint64_t now_us)
{
  (void) now_us;
  if (!c->handshake_confirmed || !c->sp[SP_APP].have_wk || !c->w_phase_acked
      || c->w_phase != c->r_phase)
    return GQ_ERR_INVAL;
  return write_key_update (c);
}

static void
rotate_read_keys (gq_conn *c, uint64_t pn)
{
  space *s = &c->sp[SP_APP];

  c->rk_prev = s->rk;
  c->have_rk_prev = 1;
  s->rk = c->rk_next;
  memcpy (c->rsec, c->rsec_next, c->rsec_len);
  c->r_phase ^= 1;
  c->r_first_pn = pn;
  derive_next_read (c);
  /* The peer started an update: follow it with our own keys.  */
  if (c->w_phase != c->r_phase)
    write_key_update (c);
}

/* ---- Frame handling ---- */

typedef struct rctx
{
  gq_conn *c;
  int sp;
  int ae;			/* Saw an ack-eliciting frame.  */
  int nonprobing;		/* Saw a frame other than PADDING and the
				   path probing ones.  */
  int closing;			/* Saw CONNECTION_CLOSE.  */
} rctx;

typedef struct crypto_user
{
  gq_conn *c;
  enum gq_level level;
} crypto_user;

static int
crypto_deliver (void *user, uint64_t off, const uint8_t *data, size_t len,
                int fin)
{
  crypto_user *u = user;
  const uint8_t *p = data;
  size_t n = len;
  int r;

  (void) off;
  (void) fin;
  if (n == 0)
    return 0;
  r = gq_tls_feed (u->c->tls, u->level, &p, &n);
  if (r < 0)
    {
      int alert = gq_tls_alert (u->c->tls);

      conn_fail (u->c, alert >= 0 ? GQ_QERR_CRYPTO_BASE + (unsigned) alert
                                  : GQ_QERR_PROTOCOL_VIOLATION,
                 "handshake failed");
      return 1;
    }
  return u->c->state >= GQ_CONN_CLOSING;
}

static int
cid_store (gq_conn *c, const gq_frame *f)
{
#define NC (&f->u.new_connection_id)
  size_t i, active = 0;
  pcid *slot = NULL;

  if (NC->retire_prior_to > NC->seq || NC->cid_len == 0)
    {
      conn_fail (c, GQ_QERR_FRAME_ENCODING, "bad NEW_CONNECTION_ID");
      return 1;
    }
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq == NC->seq)
      {
        if (c->p[i].cid.len != NC->cid_len
            || memcmp (c->p[i].cid.data, NC->cid, NC->cid_len))
          {
            conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "connection ID reused");
            return 1;
          }
        return 0;		/* Retransmission.  */
      }
  for (i = 0; i < MAX_PCID; i++)
    if (!c->p[i].used)
      {
        slot = &c->p[i];
        break;
      }
  if (slot == NULL)
    {
      conn_fail (c, GQ_QERR_CONNECTION_ID_LIMIT, "too many connection IDs");
      return 1;
    }
  memset (slot, 0, sizeof *slot);
  slot->used = 1;
  slot->seq = NC->seq;
  slot->cid.len = NC->cid_len;
  memcpy (slot->cid.data, NC->cid, NC->cid_len);
  memcpy (slot->token, NC->reset_token, GQ_RESET_TOKEN_LEN);
  if (NC->retire_prior_to > c->peer_retire_prior)
    c->peer_retire_prior = NC->retire_prior_to;
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq < c->peer_retire_prior
        && c->p[i].retire == 0)
      c->p[i].retire = 1;
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].retire == 0)
      active++;
  if (active > c->cfg.active_cid_limit)
    {
      conn_fail (c, GQ_QERR_CONNECTION_ID_LIMIT, "too many connection IDs");
      return 1;
    }
  /* If the ID in use was retired, switch to another.  */
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq == c->dcid_seq && c->p[i].retire)
      {
        size_t j;

        for (j = 0; j < MAX_PCID; j++)
          if (c->p[j].used && !c->p[j].retire)
            {
              c->dcid = c->p[j].cid;
              c->dcid_seq = c->p[j].seq;
              conn_path_dcid_changed (c);
              break;
            }
        break;
      }
#undef NC
  return 0;
}

static int
cid_retire (gq_conn *c, uint64_t seq)
{
  size_t i, active = 0;

  if (seq >= c->next_lseq)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "retired unissued ID");
      return 1;
    }
  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].seq == seq)
      {
        c->l[i].used = 0;
        if (c->ev.cid_retired)
          c->ev.cid_retired (c->ev.user, c->l[i].cid.data, c->l[i].cid.len);
        break;
      }
  for (i = 0; i < MAX_LCID; i++)
    active += c->l[i].used;
  if (active < c->peer_cid_limit && active < MAX_LCID)
    conn_new_lcid (c, 0);
  return 0;
}

static int
on_frame (void *user, const gq_frame *f)
{
  rctx *x = user;
  gq_conn *c = x->c;
  int sp = x->sp;

  if (f->type != GQ_FRAME_PADDING && f->type != GQ_FRAME_ACK
      && f->type != GQ_FRAME_CONNECTION_CLOSE)
    x->ae = 1;
  if (f->type != GQ_FRAME_PADDING && f->type != GQ_FRAME_PATH_CHALLENGE
      && f->type != GQ_FRAME_PATH_RESPONSE
      && f->type != GQ_FRAME_NEW_CONNECTION_ID)
    x->nonprobing = 1;
  if (sp != SP_APP && f->type != GQ_FRAME_PADDING && f->type != GQ_FRAME_PING
      && f->type != GQ_FRAME_ACK && f->type != GQ_FRAME_CRYPTO
      && f->type != GQ_FRAME_CONNECTION_CLOSE)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "frame not allowed here");
      return 1;
    }
  switch (f->type)
    {
    case GQ_FRAME_PADDING:
    case GQ_FRAME_PING:
      return 0;
    case GQ_FRAME_PATH_RESPONSE:
      conn_path_on_response (c, f->u.path_challenge.data, c->now);
      return 0;
    case GQ_FRAME_ACK:
      if (f->u.ack.largest >= c->sp[sp].next_pn)
        {
          conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "ACK of unsent packet");
          return 1;
        }
      process_ack (c, sp, f, c->now);
      return 0;
    case GQ_FRAME_CRYPTO:
      {
        crypto_user u;
        int r;

        u.c = c;
        u.level = sp == SP_INITIAL ? GQ_LEVEL_INITIAL
                : sp == SP_HANDSHAKE ? GQ_LEVEL_HANDSHAKE
                : GQ_LEVEL_APPLICATION;
        if (c->sp[sp].discarded || c->tls == NULL)
          return 0;
        r = gq_rstream_push (&c->sp[sp].cr, f->u.crypto.offset,
                             f->u.crypto.data.data, f->u.crypto.data.len, 0,
                             crypto_deliver, &u, NULL);
        if (r == GQ_ERR_FLOW)
          conn_fail (c, GQ_QERR_CRYPTO_BUFFER, "CRYPTO data too far ahead");
        else if (r == GQ_ERR_HANDLER)
          ;			/* crypto_deliver already failed us.  */
        else if (r != GQ_OK)
          conn_fail (c, GQ_QERR_INTERNAL, "CRYPTO frame failed");
        return c->state >= GQ_CONN_CLOSING;
      }
    case GQ_FRAME_NEW_TOKEN:
      if (c->role == GQ_ROLE_SERVER)
        {
          conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "client sent NEW_TOKEN");
          return 1;
        }
      if (c->ev.new_token)
        c->ev.new_token (c->ev.user, f->u.new_token.token.data,
                         f->u.new_token.token.len);
      return 0;
    case GQ_FRAME_HANDSHAKE_DONE:
      if (c->role == GQ_ROLE_SERVER)
        {
          conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION,
                     "client sent HANDSHAKE_DONE");
          return 1;
        }
      conn_maybe_confirm (c);
      return 0;
    case GQ_FRAME_NEW_CONNECTION_ID:
      return cid_store (c, f);
    case GQ_FRAME_RETIRE_CONNECTION_ID:
      return cid_retire (c, f->u.retire_connection_id.seq);
    case GQ_FRAME_PATH_CHALLENGE:
      conn_path_on_challenge (c, f->u.path_challenge.data);
      return 0;
    case GQ_FRAME_CONNECTION_CLOSE:
      {
        gq_conn_close_info info;

        memset (&info, 0, sizeof info);
        info.source = GQ_CLOSE_PEER;
        info.application = f->u.connection_close.application;
        info.error = f->u.connection_close.error;
        info.frame_type = f->u.connection_close.frame_type;
        info.reason = f->u.connection_close.reason.data;
        info.reason_len = f->u.connection_close.reason.len;
        x->closing = 1;
        conn_enter_closing (c, &info, 1);
        return 1;
      }
    case GQ_FRAME_DATAGRAM:
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "unexpected DATAGRAM");
      return 1;
    default:
      return stream_handle_frame (c, f);
    }
}

/* Returns 0 if the connection can go on, -1 if it must stop.  */
static int
process_payload (gq_conn *c, int sp, const uint8_t *p, size_t n, int *ae,
                 int *nonprobing)
{
  rctx x;
  int r;

  x.c = c;
  x.sp = sp;
  x.ae = 0;
  x.nonprobing = 0;
  x.closing = 0;
  if (n == 0)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "empty packet");
      return -1;
    }
  r = gq_frame_parse (&p, &n, on_frame, &x);
  *ae = x.ae;
  if (nonprobing)
    *nonprobing = x.nonprobing;
  if (c->state >= GQ_CONN_CLOSING)
    return -1;
  if (r == GQ_ERR_ENCODING || r == GQ_NEED_MORE)
    {
      conn_fail (c, GQ_QERR_FRAME_ENCODING, "malformed frame");
      return -1;
    }
  if (r != GQ_OK)
    {
      conn_fail (c, GQ_QERR_INTERNAL, "frame handler failed");
      return -1;
    }
  return 0;
}

/* ---- Packet acceptance ---- */

static void
note_received (gq_conn *c, int sp, uint64_t pn, int ae, uint64_t now)
{
  space *s = &c->sp[sp];
  int gap = s->have_recv && pn != s->largest_recv + 1;

  gq_ranges_add (&s->recv, pn, pn + 1, 1);
  if (s->recv.n >= s->recv.max)
    s->recv_floor = s->recv.r[0].lo;
  if (!s->have_recv || pn > s->largest_recv)
    {
      s->largest_recv = pn;
      s->largest_recv_time = now;
      s->have_recv = 1;
    }
  c->st.packets_received++;
  c->idle_send_reset = 0;
  conn_recompute_idle (c, now);
  if (!ae)
    return;
  s->ack_pending = 1;
  s->ae_since_ack++;
  if (sp != SP_APP || gap || s->ae_since_ack >= 2)
    s->ack_now = 1;
  else if (s->ack_deadline == 0)
    s->ack_deadline = now + 25000;
}

static int
is_our_cid (const gq_conn *c, const uint8_t *cid, size_t len)
{
  size_t i;

  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].cid.len == len
        && memcmp (c->l[i].cid.data, cid, len) == 0)
      return 1;
  return 0;
}

static int
stateless_reset_check (gq_conn *c, const uint8_t *data, size_t len)
{
  size_t i;

  if (len < GQ_STATELESS_RESET_MIN_LEN)
    return 0;
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && gq_stateless_reset_match (data, len, c->p[i].token))
      {
        gq_conn_close_info info;

        memset (&info, 0, sizeof info);
        info.source = GQ_CLOSE_RESET;
        conn_enter_closing (c, &info, 1);
        return 1;
      }
  return 0;
}

/* Client: a Retry packet (RFC 9000 section 17.2.5).  Restart the Initial
   flight with the server's token and connection ID.  */
static int
recv_retry (gq_conn *c, const gq_long_header *h, const uint8_t *pkt, size_t len)
{
  space *s = &c->sp[SP_INITIAL];
  gq_packet_keys ck, sk;
  size_t i;

  if (c->role != GQ_ROLE_CLIENT || c->got_peer_packet || c->retried
      || h->version != c->version || h->token.len == 0
      || h->token.len > sizeof c->token || h->scid.len == 0
      || !is_our_cid (c, h->dcid.data, h->dcid.len)
      || s->discarded)
    return 0;
  if (gq_retry_verify (h, pkt, len, c->initial_dcid.data,
                       c->initial_dcid.len) != GQ_OK)
    return 0;
  if (gq_packet_keys_initial (c->version, h->scid.data, h->scid.len, &ck, &sk)
      != GQ_OK)
    return 0;
  c->retried = 1;
  memcpy (c->token, h->token.data, h->token.len);
  c->token_len = h->token.len;
  c->dcid.len = c->retry_scid.len = c->initial_dcid.len = (uint8_t) h->scid.len;
  memcpy (c->dcid.data, h->scid.data, h->scid.len);
  c->retry_scid = c->dcid;
  c->initial_dcid = c->dcid;
  c->p[0].cid = c->dcid;
  s->wk = ck;
  s->rk = sk;
  /* Everything sent so far goes out again under the new keys.  */
  for (i = 0; i < s->n_sent; i++)
    requeue_frames (c, SP_INITIAL, &s->sent[i]);
  sp_sent_clear (c, SP_INITIAL);
  s->probes = 0;
  s->loss_time = 0;
  c->pto_count = 0;
  return 1;
}

/* Client: a Version Negotiation packet (RFC 9000 section 6.2).  Genuine
   ones echo our connection IDs and do not list the version we used.  */
static int
recv_vn (gq_conn *c, const gq_long_header *h)
{
  size_t i, j, n = gq_vn_count (h);
  uint32_t pick = 0;

  if (c->role != GQ_ROLE_CLIENT || c->got_peer_packet || c->vn_received
      || c->retried || h->dcid.len != c->scid_first.len
      || memcmp (h->dcid.data, c->scid_first.data, h->dcid.len)
      || h->scid.len != c->initial_dcid.len
      || memcmp (h->scid.data, c->initial_dcid.data, h->scid.len))
    return 0;
  for (i = 0; i < n; i++)
    if (gq_vn_get (h, i) == c->version)
      return 0;			/* Cannot be a real one.  */
  for (i = 0; i < c->cfg.n_versions && !pick; i++)
    for (j = 0; j < n; j++)
      if (gq_vn_get (h, j) == c->cfg.versions[i]
          && gq_version_supported (c->cfg.versions[i]))
        {
          pick = c->cfg.versions[i];
          break;
        }
  if (pick == 0)
    {
      conn_abandon (c, GQ_QERR_VERSION_NEGOTIATION, "no common version");
      return 1;
    }
  if (conn_client_restart (c, pick) != GQ_OK)
    conn_abandon (c, GQ_QERR_INTERNAL, "cannot restart");
  return 1;
}

/* Handle one long-header packet.  *USED is the number of bytes it took
   (0: stop, the rest of the datagram is unusable).  Returns 1 if a packet
   was processed.  */
static int
recv_long (gq_conn *c, uint64_t now, uint8_t *pkt, size_t rem, size_t dgram,
           size_t *used)
{
  gq_long_header h;
  space *s;
  int sp, r, ae, adopt = 0;
  uint64_t pn;
  size_t poff, plen;
  gq_packet_keys ck, sk;
  const gq_packet_keys *rk = NULL;

  *used = 0;
  r = gq_long_header_parse (pkt, rem, &h);
  if (r != GQ_OK)
    return 0;
  *used = h.packet_len;
  if (h.type == GQ_PKT_VERSION_NEGOTIATION)
    return recv_vn (c, &h);
  if (c->role == GQ_ROLE_SERVER && !c->got_first_initial
      && h.version != c->version && h.type == GQ_PKT_INITIAL
      && gq_version_supported (h.version) && conn_version_listed (c, h.version))
    c->version = c->orig_version = h.version;	/* Serve what was asked.  */
  if (h.version != c->version)
    {
      /* Only Initial packets may differ, and only during a compatible
         version negotiation: a server still hears the client's first
         version until the client has switched, and a client hears the
         server's new one once.  */
      if (h.type != GQ_PKT_INITIAL)
        return 0;
      if (c->role == GQ_ROLE_SERVER)
        {
          if (!c->switched || h.version != c->orig_version
              || !c->have_orig_rk)
            return 0;
          rk = &c->orig_rk;
        }
      else if (c->switched || c->sp[SP_HANDSHAKE].have_rk
               || !conn_version_listed (c, h.version)
               || !conn_version_compatible (c->version, h.version)
               || !gq_version_supported (h.version)
               || gq_packet_keys_initial (h.version, c->initial_dcid.data,
                                          c->initial_dcid.len, &ck, &sk)
                  != GQ_OK)
        return 0;
      else
        {
          rk = &sk;
          adopt = 1;
        }
    }
  if (h.type == GQ_PKT_RETRY)
    return recv_retry (c, &h, pkt, h.packet_len);
  if (h.type != GQ_PKT_INITIAL && h.type != GQ_PKT_HANDSHAKE)
    return 0;			/* 0-RTT.  */
  sp = h.type == GQ_PKT_INITIAL ? SP_INITIAL : SP_HANDSHAKE;
  if (c->role == GQ_ROLE_SERVER && sp == SP_INITIAL && !c->got_first_initial)
    {
      if (dgram < GQ_MIN_INITIAL_DATAGRAM || h.dcid.len < 8)
        return 0;
      if (conn_server_start (c, h.dcid.data, h.dcid.len, h.scid.data,
                             h.scid.len) != GQ_OK)
        {
          conn_fail (c, GQ_QERR_INTERNAL, "cannot start handshake");
          return 0;
        }
    }
  if (c->role == GQ_ROLE_SERVER && !c->got_first_initial)
    return 0;
  s = &c->sp[sp];
  if (s->discarded || !s->have_rk)
    return 0;
  if (!is_our_cid (c, h.dcid.data, h.dcid.len)
      && !(c->role == GQ_ROLE_SERVER && sp == SP_INITIAL
           && h.dcid.len == c->initial_dcid.len
           && memcmp (h.dcid.data, c->initial_dcid.data, h.dcid.len) == 0))
    return 0;
  if (c->dcid_set && (c->role == GQ_ROLE_SERVER || c->got_peer_packet)
      && (h.scid.len != c->dcid.len
          || memcmp (h.scid.data, c->dcid.data, h.scid.len)))
    return 0;
  if (rk == NULL)
    rk = &s->rk;
  r = gq_packet_open (rk, s->have_recv, s->largest_recv, pkt, h.packet_len,
                      h.pn_offset, &pn, &poff, &plen);
  if (r == GQ_ERR_ENCODING)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "reserved bits set");
      return 1;
    }
  if (r != GQ_OK)
    return 0;
  if (pn < s->recv_floor || gq_ranges_contains (&s->recv, pn))
    return 1;			/* Duplicate.  */
  if (adopt)
    {
      /* The server moved us to another compatible version: everything
         from here on uses it.  */
      c->orig_version = c->version;
      c->version = h.version;
      c->switched = 1;
      s->rk = sk;
      s->wk = ck;
    }
  if (c->role == GQ_ROLE_CLIENT && !c->got_peer_packet)
    {
      /* The server picked its own connection ID: use it from now on.  */
      c->dcid.len = (uint8_t) h.scid.len;
      memcpy (c->dcid.data, h.scid.data, h.scid.len);
      c->p[0].cid = c->dcid;
    }
  c->got_peer_packet = 1;
  if (process_payload (c, sp, pkt + poff, plen, &ae, NULL) != 0)
    return 1;
  note_received (c, sp, pn, ae, now);
  if (c->role == GQ_ROLE_SERVER && sp == SP_HANDSHAKE)
    {
      /* The client has proven it can receive at its address, and has
         moved on from Initial keys.  */
      c->peer_addr_validated = 1;
      conn_discard_space (c, SP_INITIAL);
    }
  return 1;
}

static int
recv_short (gq_conn *c, uint64_t now, uint8_t *pkt, size_t rem, size_t *used)
{
  gq_short_header h;
  space *s = &c->sp[SP_APP];
  const gq_packet_keys *keys;
  size_t pn_len, poff, plen, i;
  uint64_t trunc = 0, pn;
  int update = 0, ae, r, highest, nonprobing = 0;

  *used = rem;
  if (!s->have_rk || s->discarded)
    return 0;
  if (gq_short_header_parse (pkt, rem, c->cfg.cid_len, &h) != GQ_OK)
    return 0;
  if (!is_our_cid (c, h.dcid.data, h.dcid.len))
    return 0;
  if (gq_hp_remove (&s->rk, pkt, rem, h.pn_offset, &pn_len) != GQ_OK)
    goto failed;
  for (i = 0; i < pn_len; i++)
    trunc = (trunc << 8) | pkt[h.pn_offset + i];
  pn = gq_pn_decode (s->have_recv, s->largest_recv, trunc, pn_len);
  {
    int phase = (pkt[0] >> 2) & 1;

    if (phase == c->r_phase)
      keys = &s->rk;
    else if (c->have_rk_prev && pn < c->r_first_pn)
      keys = &c->rk_prev;
    else if (c->have_rk_next)
      {
        keys = &c->rk_next;
        update = 1;
      }
    else
      goto failed;
  }
  r = gq_packet_decrypt (keys, pn, pkt, rem, h.pn_offset, pn_len, &poff,
                         &plen);
  if (r == GQ_ERR_ENCODING)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "reserved bits set");
      return 1;
    }
  if (r != GQ_OK)
    goto failed;
  if (pn < s->recv_floor || gq_ranges_contains (&s->recv, pn))
    return 1;
  if (update)
    rotate_read_keys (c, pn);
  c->got_peer_packet = 1;
  if (c->role == GQ_ROLE_SERVER && conn_path_rx_initial (c))
    c->peer_addr_validated = 1;
  highest = !s->have_recv || pn > s->largest_recv;
  if (process_payload (c, SP_APP, pkt + poff, plen, &ae, &nonprobing) != 0)
    return 1;
  note_received (c, SP_APP, pn, ae, now);
  conn_path_after_packet (c, now, nonprobing, highest);
  return 1;
failed:
  stateless_reset_check (c, pkt, rem);
  return 0;
}

int
conn_receive_datagram (gq_conn *c, uint64_t now, uint8_t *data, size_t len)
{
  size_t off = 0;
  int any = 0;

  if (c->state == GQ_CONN_CLOSING)
    {
      /* Answer with the close again, but not for every packet.  */
      if (now - c->last_close_sent >= c->srtt)
        c->close_pending = 1;
      return GQ_OK;
    }
  while (off < len && c->state < GQ_CONN_CLOSING)
    {
      uint8_t *pkt = data + off;
      size_t rem = len - off, used = 0;
      int got;

      if (pkt[0] & 0x80)
        got = recv_long (c, now, pkt, rem, len, &used);
      else
        got = recv_short (c, now, pkt, rem, &used);
      if (got && !any)
        {
          any = 1;
          conn_path_account_recv (c, len);
          c->st.bytes_received += len;
        }
      if (used == 0)
        break;
      off += used;
    }
  return GQ_OK;
}
