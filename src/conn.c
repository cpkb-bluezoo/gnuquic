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

#define DEFAULT_IDLE_MS 30000
#define DEFAULT_MAX_DATA (1u << 20)
#define DEFAULT_STREAM_DATA (256u << 10)
#define DEFAULT_STREAMS 100
#define CRYPTO_BUFFER (1u << 17)

static uint64_t
umax (uint64_t a, uint64_t b)
{
  return a > b ? a : b;
}

size_t
conn_max_datagram (const gq_conn *c)
{
  size_t m = c->cfg.max_udp_payload;

  if (c->have_peer_tp && c->peer_tp.max_udp_payload_size < m)
    m = (size_t) c->peer_tp.max_udp_payload_size;
  return m;
}

/* ---- Timing helpers ---- */

uint64_t
conn_pto_base (const gq_conn *c, int sp)
{
  uint64_t v = 4 * c->rttvar;

  if (v < K_GRANULARITY)
    v = K_GRANULARITY;
  v += c->srtt;
  if (sp == SP_APP)
    v += c->peer_max_ack_delay_us;
  return v;
}

void
conn_recompute_idle (gq_conn *c, uint64_t now)
{
  uint64_t t = c->idle_timeout_us;

  if (t == 0)
    {
      c->idle_deadline = 0;
      return;
    }
  /* At least three probe timeouts, so a lossy path does not kill us.  */
  t = umax (t, 3 * conn_pto_base (c, SP_APP));
  c->idle_deadline = now + t;
}

/* ---- Connection IDs ---- */

int
conn_new_lcid (gq_conn *c, int announced)
{
  size_t i;
  lcid *l = NULL;

  for (i = 0; i < MAX_LCID; i++)
    if (!c->l[i].used)
      {
        l = &c->l[i];
        break;
      }
  if (l == NULL)
    return GQ_ERR_RANGE;
  memset (l, 0, sizeof *l);
  l->used = 1;
  l->seq = c->next_lseq++;
  l->cid.len = (uint8_t) c->cfg.cid_len;
  if (gq_random (l->cid.data, l->cid.len) != GQ_OK
      || gq_random (l->token, sizeof l->token) != GQ_OK)
    {
      l->used = 0;
      return GQ_ERR_CRYPTO;
    }
  l->announced = (uint8_t) announced;
  l->need_send = !announced;
  if (c->ev.cid_issued)
    c->ev.cid_issued (c->ev.user, l->cid.data, l->cid.len, l->token);
  return GQ_OK;
}

/* ---- Failure and closing ---- */

void
conn_enter_closing (gq_conn *c, gq_conn_close_info *info, int draining)
{
  uint64_t pto = 3 * conn_pto_base (c, SP_APP);

  if (c->state >= GQ_CONN_CLOSING)
    return;
  c->state = draining ? GQ_CONN_DRAINING : GQ_CONN_CLOSING;
  c->close_deadline = c->now + pto;
  if (!c->closed_notified)
    {
      c->closed_notified = 1;
      if (c->ev.closed)
        c->ev.closed (c->ev.user, info);
    }
}

void
conn_fail (gq_conn *c, uint64_t code, const char *reason)
{
  gq_conn_close_info info;
  size_t n = reason ? strlen (reason) : 0;

  if (c->state >= GQ_CONN_CLOSING)
    return;
  if (!c->err_set)
    {
      c->err_set = 1;
      c->err_code = code;
    }
  c->close_pending = 1;
  c->close_app = 0;
  c->close_err = c->err_code;
  c->close_frame = 0;
  if (n >= sizeof c->close_reason)
    n = sizeof c->close_reason - 1;
  if (n)
    memcpy (c->close_reason, reason, n);
  c->close_reason_len = n;
  memset (&info, 0, sizeof info);
  info.source = GQ_CLOSE_LOCAL;
  info.error = c->close_err;
  info.reason = (const uint8_t *) c->close_reason;
  info.reason_len = n;
  conn_enter_closing (c, &info, 0);
}

int
gq_conn_close (gq_conn *c, uint64_t now_us, int application, uint64_t error,
               const char *reason)
{
  gq_conn_close_info info;
  size_t n = reason ? strlen (reason) : 0;

  if (c->state >= GQ_CONN_CLOSING)
    return GQ_OK;
  c->now = now_us;
  c->close_pending = 1;
  c->close_app = application != 0;
  c->close_err = error;
  c->close_frame = 0;
  if (n >= sizeof c->close_reason)
    n = sizeof c->close_reason - 1;
  if (n)
    memcpy (c->close_reason, reason, n);
  c->close_reason_len = n;
  memset (&info, 0, sizeof info);
  info.source = GQ_CLOSE_LOCAL;
  info.application = c->close_app;
  info.error = error;
  info.reason = (const uint8_t *) c->close_reason;
  info.reason_len = n;
  conn_enter_closing (c, &info, 0);
  return GQ_OK;
}

/* ---- Spaces ---- */

int
conn_discard_space (gq_conn *c, int sp)
{
  space *s = &c->sp[sp];

  if (s->discarded)
    return GQ_OK;
  s->discarded = 1;
  s->have_rk = s->have_wk = 0;
  gq_packet_keys_wipe (&s->rk);
  gq_packet_keys_wipe (&s->wk);
  sp_sent_clear (c, sp);
  gq_ranges_free (&s->recv);
  gq_ranges_free (&s->acked_pns);
  gq_sstream_free (&s->cs);
  gq_rstream_free (&s->cr);
  s->ack_pending = s->ack_now = 0;
  s->ack_deadline = 0;
  s->loss_time = 0;
  s->probes = 0;
  c->pto_count = 0;
  return GQ_OK;
}

void
conn_maybe_confirm (gq_conn *c)
{
  if (c->handshake_confirmed)
    return;
  c->handshake_confirmed = 1;
  conn_discard_space (c, SP_HANDSHAKE);
}

void
conn_notify_connected (gq_conn *c, const gq_tls_info *info)
{
  if (c->connected_notified)
    return;
  c->connected_notified = 1;
  if (c->state == GQ_CONN_HANDSHAKE)
    c->state = GQ_CONN_ESTABLISHED;
  if (c->ev.connected)
    c->ev.connected (c->ev.user, info);
}

/* ---- Transport parameters ---- */

static void
local_params (gq_conn *c, gq_transport_params *tp)
{
  const gq_conn_config *g = &c->cfg;

  gq_tp_defaults (tp);
  tp->max_idle_timeout = g->idle_timeout_ms;
  gq_tp_set_present (tp, GQ_TP_MAX_IDLE_TIMEOUT);
  tp->initial_max_data = g->initial_max_data;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_DATA);
  tp->initial_max_stream_data_bidi_local = g->initial_max_stream_data;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
  tp->initial_max_stream_data_bidi_remote = g->initial_max_stream_data;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
  tp->initial_max_stream_data_uni = g->initial_max_stream_data;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_UNI);
  tp->initial_max_streams_bidi = g->initial_max_streams_bidi;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAMS_BIDI);
  tp->initial_max_streams_uni = g->initial_max_streams_uni;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAMS_UNI);
  tp->active_connection_id_limit = g->active_cid_limit;
  gq_tp_set_present (tp, GQ_TP_ACTIVE_CONNECTION_ID_LIMIT);
  tp->initial_source_connection_id = c->scid_first;
  gq_tp_set_present (tp, GQ_TP_INITIAL_SOURCE_CONNECTION_ID);
  if (g->disable_active_migration)
    gq_tp_set_present (tp, GQ_TP_DISABLE_ACTIVE_MIGRATION);
  if (c->role == GQ_ROLE_SERVER)
    {
      tp->original_destination_connection_id = c->odcid;
      gq_tp_set_present (tp, GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID);
      memcpy (tp->stateless_reset_token, c->l[0].token, GQ_RESET_TOKEN_LEN);
      gq_tp_set_present (tp, GQ_TP_STATELESS_RESET_TOKEN);
    }
}

static int
cid_equal (const gq_cid *a, const gq_cid *b)
{
  return a->len == b->len && memcmp (a->data, b->data, a->len) == 0;
}

int
conn_apply_peer_params (gq_conn *c)
{
  const gq_transport_params *p = &c->peer_tp;
  uint64_t idle;

  if (!gq_tp_has (p, GQ_TP_INITIAL_SOURCE_CONNECTION_ID)
      || !cid_equal (&p->initial_source_connection_id, &c->dcid))
    return GQ_ERR_PROTOCOL;
  if (c->role == GQ_ROLE_CLIENT
      && (!gq_tp_has (p, GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID)
          || !cid_equal (&p->original_destination_connection_id, &c->odcid)))
    return GQ_ERR_PROTOCOL;
  c->have_peer_tp = 1;
  c->max_data_peer = p->initial_max_data;
  c->max_streams_peer[1] = p->initial_max_streams_bidi;
  c->max_streams_peer[0] = p->initial_max_streams_uni;
  c->peer_ack_delay_exp = (unsigned) p->ack_delay_exponent;
  c->peer_max_ack_delay_us = p->max_ack_delay * 1000;
  c->peer_cid_limit = (size_t) p->active_connection_id_limit;
  if (gq_tp_has (p, GQ_TP_STATELESS_RESET_TOKEN))
    memcpy (c->p[0].token, p->stateless_reset_token, GQ_RESET_TOKEN_LEN);
  idle = p->max_idle_timeout * 1000;
  if (idle && (c->idle_timeout_us == 0 || idle < c->idle_timeout_us))
    c->idle_timeout_us = idle;
  streams_apply_peer_params (c);
  /* Offer the peer spare connection IDs, up to what it will keep.  */
  while (1)
    {
      size_t active = 0, i;

      for (i = 0; i < MAX_LCID; i++)
        active += c->l[i].used;
      if (active >= c->peer_cid_limit || active >= MAX_LCID)
        break;
      if (conn_new_lcid (c, 0) != GQ_OK)
        break;
    }
  return GQ_OK;
}

/* ---- TLS sink ---- */

static int
sink_send (void *user, enum gq_level level, const uint8_t *data, size_t len)
{
  gq_conn *c = user;
  int sp = SPACE_OF_LEVEL (level);
  long w;

  if (sp < 0 || c->sp[sp].discarded)
    return 0;
  w = gq_sstream_write (&c->sp[sp].cs, data, len);
  return w == (long) len ? 0 : 1;
}

static int
sink_secret (void *user, const gq_tls_secret *s)
{
  conn_install_keys (user, s);
  return 0;
}

static int
sink_peer_params (void *user, const uint8_t *data, size_t len)
{
  gq_conn *c = user;
  int r;

  r = gq_tp_decode (data, len,
                    c->role == GQ_ROLE_CLIENT ? GQ_ROLE_SERVER
                                              : GQ_ROLE_CLIENT,
                    &c->peer_tp);
  if (r == GQ_OK)
    r = conn_apply_peer_params (c);
  if (r != GQ_OK)
    {
      conn_fail (c, GQ_QERR_TRANSPORT_PARAMETER, "bad transport parameters");
      return 1;
    }
  return 0;
}

static int
sink_complete (void *user, const gq_tls_info *info)
{
  gq_conn *c = user;

  c->handshake_complete = 1;
  if (c->role == GQ_ROLE_SERVER)
    {
      c->handshake_done_pending = 1;
      conn_maybe_confirm (c);
    }
  conn_notify_connected (c, info);
  return 0;
}

static int
sink_ticket (void *user, const gq_tls_ticket *t)
{
  gq_conn *c = user;

  if (c->ev.ticket)
    c->ev.ticket (c->ev.user, t);
  return 0;
}

static int
sink_alert (void *user, unsigned code)
{
  gq_conn *c = user;

  conn_fail (c, GQ_QERR_CRYPTO_BASE + code, "TLS handshake failed");
  return 0;
}

static void
make_sink (gq_conn *c, gq_tls_sink *k)
{
  memset (k, 0, sizeof *k);
  k->user = c;
  k->send = sink_send;
  k->secret = sink_secret;
  k->peer_params = sink_peer_params;
  k->ticket = sink_ticket;
  k->complete = sink_complete;
  k->alert = sink_alert;
}

/* ---- Creation ---- */

static void
fill_defaults (gq_conn_config *g)
{
  if (g->version == 0)
    g->version = GQ_VERSION_1;
  if (g->idle_timeout_ms == 0)
    g->idle_timeout_ms = DEFAULT_IDLE_MS;
  if (g->initial_max_data == 0)
    g->initial_max_data = DEFAULT_MAX_DATA;
  if (g->initial_max_stream_data == 0)
    g->initial_max_stream_data = DEFAULT_STREAM_DATA;
  if (g->initial_max_streams_bidi == 0)
    g->initial_max_streams_bidi = DEFAULT_STREAMS;
  if (g->initial_max_streams_uni == 0)
    g->initial_max_streams_uni = DEFAULT_STREAMS;
  if (g->send_buffer == 0)
    g->send_buffer = 256u << 10;
  if (g->max_udp_payload == 0)
    g->max_udp_payload = 1200;
  if (g->max_udp_payload > 2048)
    g->max_udp_payload = 2048;
  if (g->max_udp_payload < 1200)
    g->max_udp_payload = 1200;
  if (g->cid_len == 0)
    g->cid_len = 8;
  if (g->cid_len > GQ_MAX_CID_LEN)
    g->cid_len = GQ_MAX_CID_LEN;
  if (g->active_cid_limit < 2)
    g->active_cid_limit = 4;
  if (g->active_cid_limit > MAX_LCID)
    g->active_cid_limit = MAX_LCID;
}

static gq_conn *
conn_alloc (enum gq_role role, const gq_conn_config *config,
            const gq_conn_events *events, uint64_t now)
{
  gq_conn *c = calloc (1, sizeof *c);
  int i;

  if (c == NULL)
    return NULL;
  c->role = role;
  c->state = GQ_CONN_HANDSHAKE;
  if (config)
    c->cfg = *config;
  fill_defaults (&c->cfg);
  if (events)
    c->ev = *events;
  c->version = c->cfg.version;
  c->now = now;
  c->srtt = K_INITIAL_RTT;
  c->rttvar = K_INITIAL_RTT / 2;
  c->peer_max_ack_delay_us = 25000;
  c->peer_ack_delay_exp = 3;
  c->idle_timeout_us = c->cfg.idle_timeout_ms * 1000;
  c->max_data_local = c->max_data_sent = c->cfg.initial_max_data;
  c->max_streams_local[1] = c->max_streams_local_sent[1]
    = c->cfg.initial_max_streams_bidi;
  c->max_streams_local[0] = c->max_streams_local_sent[0]
    = c->cfg.initial_max_streams_uni;
  for (i = 0; i < N_SPACES; i++)
    {
      space *s = &c->sp[i];

      gq_ranges_init (&s->recv, 64);
      gq_ranges_init (&s->acked_pns, 32);
      gq_sstream_init (&s->cs, CRYPTO_BUFFER, UINT64_MAX);
      gq_rstream_init (&s->cr, CRYPTO_BUFFER);
    }
  cc_init (c);
  conn_recompute_idle (c, now);
  /* Our first connection ID.  */
  if (conn_new_lcid (c, 1) != GQ_OK)
    {
      gq_conn_free (c);
      return NULL;
    }
  c->scid_first = c->l[0].cid;
  c->p[0].used = 1;			/* The peer's first ID: set later.  */
  return c;
}

static void
encode_params (gq_conn *c)
{
  gq_transport_params tp;

  local_params (c, &tp);
  c->tp_len = 0;
  gq_tp_encode (&tp, c->role, c->tp_buf, sizeof c->tp_buf, &c->tp_len);
}

int
gq_conn_client_new (gq_conn **out, const gq_conn_config *config,
                    const gq_tls_config *tls, const gq_conn_events *events,
                    uint64_t now_us)
{
  gq_conn *c;
  gq_tls_sink sink;
  gq_packet_keys ck, sk;
  int r;

  if (out == NULL || tls == NULL || tls->n_alpn == 0)
    return GQ_ERR_INVAL;
  *out = NULL;
  c = conn_alloc (GQ_ROLE_CLIENT, config, events, now_us);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  if (!gq_version_supported (c->version))
    {
      gq_conn_free (c);
      return GQ_ERR_UNSUPPORTED;
    }
  /* Random first destination connection ID, at least 8 bytes.  */
  c->odcid.len = 8;
  if (gq_random (c->odcid.data, c->odcid.len) != GQ_OK)
    {
      gq_conn_free (c);
      return GQ_ERR_CRYPTO;
    }
  c->dcid = c->odcid;
  c->dcid_set = 1;
  c->p[0].cid = c->odcid;
  r = gq_packet_keys_initial (c->version, c->odcid.data, c->odcid.len, &ck,
                              &sk);
  if (r != GQ_OK)
    {
      gq_conn_free (c);
      return r;
    }
  c->sp[SP_INITIAL].wk = ck;
  c->sp[SP_INITIAL].rk = sk;
  c->sp[SP_INITIAL].have_wk = c->sp[SP_INITIAL].have_rk = 1;
  encode_params (c);
  c->ctls = *tls;
  c->ctls.quic = 1;
  c->ctls.transport_params = c->tp_buf;
  c->ctls.transport_params_len = c->tp_len;
  make_sink (c, &sink);
  r = gq_tls_client_new (&c->tls, &c->ctls, &sink);
  if (r == GQ_OK)
    r = gq_tls_start (c->tls);
  if (r != GQ_OK)
    {
      gq_conn_free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

int
gq_conn_server_new (gq_conn **out, const gq_conn_config *config,
                    const gq_tls_server_config *tls,
                    const gq_conn_events *events, uint64_t now_us)
{
  gq_conn *c;

  if (out == NULL || tls == NULL || tls->n_alpn == 0)
    return GQ_ERR_INVAL;
  *out = NULL;
  c = conn_alloc (GQ_ROLE_SERVER, config, events, now_us);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  if (!gq_version_supported (c->version))
    {
      gq_conn_free (c);
      return GQ_ERR_UNSUPPORTED;
    }
  c->stls = *tls;
  *out = c;
  return GQ_OK;
}

/* Server: the first Initial arrived.  Derive its keys and start TLS.  */
int
conn_server_start (gq_conn *c, const uint8_t *odcid, size_t odcid_len,
                   const uint8_t *client_scid, size_t client_scid_len)
{
  gq_tls_sink sink;
  gq_packet_keys ck, sk;
  int r;

  c->odcid.len = (uint8_t) odcid_len;
  memcpy (c->odcid.data, odcid, odcid_len);
  c->dcid.len = (uint8_t) client_scid_len;
  memcpy (c->dcid.data, client_scid, client_scid_len);
  c->dcid_set = 1;
  c->p[0].cid = c->dcid;
  r = gq_packet_keys_initial (c->version, odcid, odcid_len, &ck, &sk);
  if (r != GQ_OK)
    return r;
  c->sp[SP_INITIAL].rk = ck;
  c->sp[SP_INITIAL].wk = sk;
  c->sp[SP_INITIAL].have_rk = c->sp[SP_INITIAL].have_wk = 1;
  encode_params (c);
  c->stls.quic = 1;
  c->stls.transport_params = c->tp_buf;
  c->stls.transport_params_len = c->tp_len;
  make_sink (c, &sink);
  r = gq_tls_server_new (&c->tls, &c->stls, &sink);
  if (r != GQ_OK)
    return r;
  c->got_first_initial = 1;
  return GQ_OK;
}

void
gq_conn_free (gq_conn *c)
{
  int i;

  if (c == NULL)
    return;
  gq_tls_free (c->tls);
  for (i = 0; i < N_SPACES; i++)
    {
      space *s = &c->sp[i];

      sp_sent_clear (c, i);
      free (s->sent);
      gq_ranges_free (&s->recv);
      gq_ranges_free (&s->acked_pns);
      gq_sstream_free (&s->cs);
      gq_rstream_free (&s->cr);
      gq_packet_keys_wipe (&s->rk);
      gq_packet_keys_wipe (&s->wk);
    }
  streams_free (c);
  gq_packet_keys_wipe (&c->rk_prev);
  gq_packet_keys_wipe (&c->rk_next);
  memset (c->rsec, 0, sizeof c->rsec);
  memset (c->wsec, 0, sizeof c->wsec);
  free (c);
}

/* ---- Public accessors, datagram entry points, timers ---- */

enum gq_conn_state
gq_conn_state (const gq_conn *c)
{
  return c->state;
}

int
gq_conn_is_established (const gq_conn *c)
{
  return c->state == GQ_CONN_ESTABLISHED;
}

uint32_t
gq_conn_version (const gq_conn *c)
{
  return c->version;
}

const uint8_t *
gq_conn_initial_dcid (const gq_conn *c, size_t *len)
{
  *len = c->odcid.len;
  return c->odcid.data;
}

void
gq_conn_get_stats (const gq_conn *c, gq_conn_stats *st)
{
  *st = c->st;
  st->srtt_us = c->srtt;
  st->min_rtt_us = c->min_rtt;
  st->rttvar_us = c->rttvar;
  st->bytes_in_flight = c->bytes_in_flight;
  st->cwnd = c->cwnd;
  st->ssthresh = c->ssthresh;
  st->congestion_events = c->congestion_events;
  st->pto_count = c->pto_count;
  st->key_updates = c->key_updates;
}

int
gq_conn_recv (gq_conn *c, uint64_t now_us, uint8_t *data, size_t len)
{
  c->now = now_us;
  if (c->state == GQ_CONN_DONE || c->state == GQ_CONN_DRAINING)
    return GQ_OK;
  return conn_receive_datagram (c, now_us, data, len);
}

int
gq_conn_send (gq_conn *c, uint64_t now_us, uint8_t *out, size_t cap,
              size_t *len)
{
  *len = 0;
  c->now = now_us;
  if (c->state == GQ_CONN_DONE || c->state == GQ_CONN_DRAINING)
    return GQ_OK;
  if (cap < conn_max_datagram (c))
    return GQ_ERR_BUFSIZE;
  return conn_build_datagram (c, now_us, out, cap, len);
}

uint64_t
gq_conn_timeout (const gq_conn *c)
{
  uint64_t t = 0;
  int i;

#define EARLIER(v) do { uint64_t v_ = (v); if (v_ && (t == 0 || v_ < t)) t = v_; } while (0)
  if (c->state == GQ_CONN_DONE)
    return 0;
  if (c->state >= GQ_CONN_CLOSING)
    return c->close_deadline;
  EARLIER (c->idle_deadline);
  for (i = 0; i < N_SPACES; i++)
    if (!c->sp[i].discarded)
      EARLIER (c->sp[i].ack_deadline);
  EARLIER (conn_loss_deadline (c));
#undef EARLIER
  return t;
}

void
gq_conn_on_timeout (gq_conn *c, uint64_t now_us)
{
  int i;

  c->now = now_us;
  if (c->state == GQ_CONN_DONE)
    return;
  if (c->state >= GQ_CONN_CLOSING)
    {
      if (c->close_deadline && now_us >= c->close_deadline)
        c->state = GQ_CONN_DONE;
      return;
    }
  if (c->idle_deadline && now_us >= c->idle_deadline)
    {
      gq_conn_close_info info;

      memset (&info, 0, sizeof info);
      info.source = GQ_CLOSE_IDLE;
      c->closed_notified = 1;
      c->state = GQ_CONN_DONE;
      if (c->ev.closed)
        c->ev.closed (c->ev.user, &info);
      return;
    }
  for (i = 0; i < N_SPACES; i++)
    {
      space *s = &c->sp[i];

      if (!s->discarded && s->ack_deadline && now_us >= s->ack_deadline)
        {
          s->ack_now = 1;
          s->ack_deadline = 0;
        }
    }
  on_loss_timeout (c, now_us);
}
