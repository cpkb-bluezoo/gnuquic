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
#include <gnuquic/tlsmsg.h>
#include <gnuquic/tls12conn.h>
#include <gnuquic/tlsauto.h>

#define MAX_FIRST_FLIGHT 70000

struct gq_tlsauto
{
  int server;
  unsigned versions;
  gq_tls_server_config scfg;	/* Kept: the engines point into what we hold.  */
  gq_tls_config ccfg;
  gq_tls_config cfg12;		/* What the TLS 1.2 engine gets: no early data.  */
  gq_tlsconn_events ev;
  gq_tlsconn *c13;
  gq_tls12conn *c12;
  uint8_t *pending;		/* Bytes until the hello of the peer is in.  */
  size_t npending, cap;
  int failed;
  gq_tlsconn_events wev;	/* Client: what the TLS 1.3 engine calls.  */
  uint8_t ch[4096];		/* Client: the hello it sent (a handshake message).  */
  size_t ch_len;
  int have_ch, undecided;
};

static unsigned
norm (unsigned v)
{
  v &= GQ_TLSAUTO_TLS12 | GQ_TLSAUTO_TLS13;
  return v ? v : (GQ_TLSAUTO_TLS12 | GQ_TLSAUTO_TLS13);
}

int
gq_tlsauto_server_new (gq_tlsauto **out, const gq_tls_server_config *config,
                       const gq_tlsconn_events *events, unsigned versions)
{
  gq_tlsauto *c;

  if (out == NULL || config == NULL || events == NULL)
    return GQ_ERR_INVAL;
  *out = NULL;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  c->server = 1;
  c->versions = norm (versions);
  c->scfg = *config;
  c->ev = *events;
  /* A TLS 1.2 server that also serves 1.3 marks its ServerHello.  */
  c->scfg.tls13_sentinel = (c->versions & GQ_TLSAUTO_TLS13) != 0;
  *out = c;
  return GQ_OK;
}

void
gq_tlsauto_free (gq_tlsauto *c)
{
  if (c == NULL)
    return;
  gq_tlsconn_free (c->c13);
  gq_tls12conn_free (c->c12);
  if (c->pending)
    {
      memset (c->pending, 0, c->npending);
      free (c->pending);
    }
  free (c);
}

/* Create the engine for VERSION (0x0304 or 0x0303).  */
static int
make_server_engine (gq_tlsauto *c, unsigned version)
{
  gq_tls_server_config cfg = c->scfg;

  if (version == 0x0304)
    return gq_tlsconn_server_new (&c->c13, &cfg, &c->ev);
  return gq_tls12conn_server_new (&c->c12, &cfg, &c->ev);
}

/* Which engine serves this first flight (the ClientHello, as the handshake
   bytes of the plaintext records so far)?  Returns 0x0304 or 0x0303 when
   decided, 0 if more bytes are needed.  Anything that does not look like a
   ClientHello goes to an engine that will refuse it properly.  */
static unsigned
decide (const gq_tlsauto *c, const uint8_t *d, size_t n)
{
  uint8_t hs[MAX_FIRST_FLIGHT];
  size_t hn = 0, off = 0, bodylen;
  unsigned fallback = (c->versions & GQ_TLSAUTO_TLS13) ? 0x0304 : 0x0303;
  gq_client_hello ch;
  gq_slice v, list, body;
  int has13 = 0, has12 = 0;
  size_t i;

  /* Gather handshake bytes from complete plaintext records.  */
  while (off + 5 <= n)
    {
      size_t len = (size_t) (d[off + 3] << 8 | d[off + 4]);

      if (d[off] != 22 || d[off + 1] != 3)
        return fallback;
      if (off + 5 + len > n)
        break;
      if (hn + len > sizeof hs)
        return fallback;
      memcpy (hs + hn, d + off + 5, len);
      hn += len;
      off += 5 + len;
      if (hn >= 4)
        {
          bodylen = (size_t) (hs[1] << 16 | hs[2] << 8 | hs[3]);
          if (hs[0] != 1 || bodylen > MAX_FIRST_FLIGHT - 4)
            return fallback;
          if (hn >= 4 + bodylen)
            goto complete;
        }
    }
  return n > MAX_FIRST_FLIGHT ? fallback : 0;
complete:
  bodylen = (size_t) (hs[1] << 16 | hs[2] << 8 | hs[3]);
  body.data = hs + 4;
  body.len = bodylen;
  if (gq_client_hello_parse (body, &ch) != GQ_OK)
    return fallback;
  if (gq_ext_find (ch.extensions, GQ_EXT_SUPPORTED_VERSIONS, &v))
    {
      if (gq_list_u16 (v, 1, &list) != GQ_OK)
        return fallback;
      for (i = 0; i < gq_u16_count (list); i++)
        {
          unsigned x = gq_u16_at (list, i);

          has13 |= x == 0x0304;
          has12 |= x == 0x0303;
        }
    }
  else
    has12 = ch.legacy_version >= 0x0303;
  if (has13 && (c->versions & GQ_TLSAUTO_TLS13))
    return 0x0304;
  if (has12 && (c->versions & GQ_TLSAUTO_TLS12))
    return 0x0303;
  return fallback;
}

static int
server_receive (gq_tlsauto *c, const uint8_t *data, size_t len)
{
  unsigned v;
  int r;

  if (c->c13)
    return gq_tlsconn_receive (c->c13, data, len);
  if (c->c12)
    return gq_tls12conn_receive (c->c12, data, len);
  if (c->npending + len > c->cap)
    {
      size_t cap = (c->npending + len) * 2 + 512;
      uint8_t *np = realloc (c->pending, cap);

      if (np == NULL)
        return GQ_ERR_NOMEM;
      c->pending = np;
      c->cap = cap;
    }
  memcpy (c->pending + c->npending, data, len);
  c->npending += len;
  v = decide (c, c->pending, c->npending);
  if (v == 0)
    return GQ_OK;
  r = make_server_engine (c, v);
  if (r != GQ_OK)
    return r;
  data = c->pending;
  len = c->npending;
  r = v == 0x0304 ? gq_tlsconn_receive (c->c13, data, len)
                  : gq_tls12conn_receive (c->c12, data, len);
  memset (c->pending, 0, c->npending);
  free (c->pending);
  c->pending = NULL;
  c->npending = c->cap = 0;
  return r;
}

/* What the TLS 1.3 engine of a negotiating client calls: the first thing
   it writes is the combined ClientHello, which a TLS 1.2 engine may have to
   continue from.  */
static int
w_write (void *u, const uint8_t *d, size_t n)
{
  gq_tlsauto *c = u;

  if (c->undecided && !c->have_ch && n >= 5 && d[0] == 22)
    {
      size_t len = (size_t) (d[3] << 8 | d[4]);

      if (5 + len <= n && len <= sizeof c->ch)
        {
          memcpy (c->ch, d + 5, len);
          c->ch_len = len;
          c->have_ch = 1;
        }
    }
  return c->ev.write (c->ev.user, d, n);
}

static int
w_data (void *u, const uint8_t *d, size_t n)
{
  gq_tlsauto *c = u;

  return c->ev.data (c->ev.user, d, n);
}

static int
w_connected (void *u, const gq_tls_info *i)
{
  gq_tlsauto *c = u;

  return c->ev.connected ? c->ev.connected (c->ev.user, i) : 0;
}

static int
w_ticket (void *u, const gq_tls_ticket *t)
{
  gq_tlsauto *c = u;

  return c->ev.ticket ? c->ev.ticket (c->ev.user, t) : 0;
}

static void
w_early_result (void *u, int accepted)
{
  gq_tlsauto *c = u;

  if (c->ev.early_data_result)
    c->ev.early_data_result (c->ev.user, accepted);
}

static void
w_closed (void *u, int error, int alert)
{
  gq_tlsauto *c = u;

  if (c->ev.closed)
    c->ev.closed (c->ev.user, error, alert);
}

int
gq_tlsauto_client_new (gq_tlsauto **out, const gq_tls_config *config,
                       const gq_tlsconn_events *events, unsigned versions)
{
  gq_tlsauto *c;
  int r;

  if (out == NULL || config == NULL || events == NULL || config->quic
      || config->transport_params)
    return GQ_ERR_INVAL;	/* QUIC is TLS 1.3 only: no negotiating.  */
  *out = NULL;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  c->versions = norm (versions);
  c->ccfg = *config;
  c->cfg12 = *config;
  c->cfg12.early_data = 0;	/* TLS 1.2 has no 0-RTT.  */
  c->cfg12.also_tls12 = 0;
  c->ev = *events;
  if (c->versions == GQ_TLSAUTO_TLS13)
    r = gq_tlsconn_client_new (&c->c13, &c->ccfg, &c->ev);
  else if (c->versions == GQ_TLSAUTO_TLS12)
    r = gq_tls12conn_client_new (&c->c12, &c->cfg12, &c->ev);
  else
    {
      /* Both: the TLS 1.3 engine sends a hello that offers both.  */
      c->ccfg.also_tls12 = 1;
      c->wev = *events;
      c->wev.user = c;
      c->wev.write = w_write;
      c->wev.data = w_data;
      c->wev.connected = events->connected ? w_connected : NULL;
      c->wev.ticket = events->ticket ? w_ticket : NULL;
      c->wev.early_data_result = events->early_data_result ? w_early_result
                                                          : NULL;
      c->wev.closed = w_closed;
      c->undecided = 1;
      r = gq_tlsconn_client_new (&c->c13, &c->ccfg, &c->wev);
    }
  if (r != GQ_OK)
    {
      free (c);
      return r;
    }
  *out = c;
  return GQ_OK;
}

/* Client: which engine does the server's first flight belong to?  Returns
   0x0304 or 0x0303 when decided, 0 if more bytes are needed.  */
static unsigned
client_decide (const uint8_t *d, size_t n)
{
  uint8_t hs[MAX_FIRST_FLIGHT];
  size_t hn = 0, off = 0, bodylen;
  gq_server_hello sh;
  gq_slice body, v;

  while (off + 5 <= n)
    {
      size_t len = (size_t) (d[off + 3] << 8 | d[off + 4]);

      if (d[off] != 22 || d[off + 1] != 3)
        return 0x0304;		/* An alert or junk: the engine deals.  */
      if (off + 5 + len > n)
        return 0;
      if (hn + len > sizeof hs)
        return 0x0304;
      memcpy (hs + hn, d + off + 5, len);
      hn += len;
      off += 5 + len;
      if (hn >= 4)
        {
          bodylen = (size_t) (hs[1] << 16 | hs[2] << 8 | hs[3]);
          if (hs[0] != 2 || bodylen > MAX_FIRST_FLIGHT - 4)
            return 0x0304;
          if (hn >= 4 + bodylen)
            {
              body.data = hs + 4;
              body.len = bodylen;
              if (gq_server_hello_parse (body, &sh) != GQ_OK
                  || sh.is_hello_retry_request
                  || gq_ext_find (sh.extensions, GQ_EXT_SUPPORTED_VERSIONS, &v))
                return 0x0304;
              return sh.legacy_version == 0x0303 ? 0x0303 : 0x0304;
            }
        }
    }
  return 0;
}

static int
client_receive (gq_tlsauto *c, const uint8_t *data, size_t len)
{
  unsigned v;
  int r;

  if (!c->undecided)
    return c->c13 ? gq_tlsconn_receive (c->c13, data, len)
                  : gq_tls12conn_receive (c->c12, data, len);
  if (c->npending + len > c->cap)
    {
      size_t cap = (c->npending + len) * 2 + 512;
      uint8_t *np = realloc (c->pending, cap);

      if (np == NULL)
        return GQ_ERR_NOMEM;
      c->pending = np;
      c->cap = cap;
    }
  memcpy (c->pending + c->npending, data, len);
  c->npending += len;
  v = client_decide (c->pending, c->npending);
  if (v == 0)
    return c->npending > MAX_FIRST_FLIGHT ? GQ_ERR_PROTOCOL : GQ_OK;
  c->undecided = 0;
  data = c->pending;
  len = c->npending;
  if (v == 0x0303)
    {
      /* The server chose TLS 1.2: a TLS 1.2 engine continues from the hello
         we sent.  Its transcript, randoms and session ID are that hello's.  */
      gq_tlsconn_free (c->c13);
      c->c13 = NULL;
      r = c->have_ch ? gq_tls12conn_client_new (&c->c12, &c->cfg12, &c->ev)
                     : GQ_ERR_INVAL;
      if (r == GQ_OK)
        r = gq_tls12conn_client_adopt (c->c12, c->ch, c->ch_len);
      if (r == GQ_OK)
        r = gq_tls12conn_receive (c->c12, data, len);
    }
  else
    r = gq_tlsconn_receive (c->c13, data, len);
  memset (c->pending, 0, c->npending);
  free (c->pending);
  c->pending = NULL;
  c->npending = c->cap = 0;
  return r;
}

int
gq_tlsauto_start (gq_tlsauto *c)
{
  if (c->server)
    return GQ_OK;
  if (c->c13)
    return gq_tlsconn_start (c->c13);
  return gq_tls12conn_start (c->c12);
}

int
gq_tlsauto_receive (gq_tlsauto *c, const uint8_t *data, size_t len)
{
  if (c->server)
    return server_receive (c, data, len);
  return client_receive (c, data, len);
}

int
gq_tlsauto_send (gq_tlsauto *c, const uint8_t *data, size_t len)
{
  if (c->c13)
    return gq_tlsconn_send (c->c13, data, len);
  if (c->c12)
    return gq_tls12conn_send (c->c12, data, len);
  return GQ_ERR_INVAL;
}

int
gq_tlsauto_close (gq_tlsauto *c)
{
  if (c->c13)
    return gq_tlsconn_close (c->c13);
  if (c->c12)
    return gq_tls12conn_close (c->c12);
  return GQ_ERR_INVAL;
}

int
gq_tlsauto_key_update (gq_tlsauto *c, int request_peer)
{
  if (c->c13 && !c->undecided)
    return gq_tlsconn_key_update (c->c13, request_peer);
  return GQ_ERR_UNSUPPORTED;
}

int
gq_tlsauto_is_connected (const gq_tlsauto *c)
{
  return c->c13 ? gq_tlsconn_is_connected (c->c13)
                : c->c12 ? gq_tls12conn_is_connected (c->c12) : 0;
}

int
gq_tlsauto_is_closed (const gq_tlsauto *c)
{
  return c->c13 ? gq_tlsconn_is_closed (c->c13)
                : c->c12 ? gq_tls12conn_is_closed (c->c12) : 0;
}

int
gq_tlsauto_export (const gq_tlsauto *c, const char *label,
                   const uint8_t *context, size_t context_len, uint8_t *out,
                   size_t out_len)
{
  if (c->c12)
    return gq_tls12conn_export (c->c12, label, context, context_len, out,
                                out_len);
  return GQ_ERR_UNSUPPORTED;
}

unsigned
gq_tlsauto_version (const gq_tlsauto *c)
{
  return c->c13 ? 0x0304 : c->c12 ? 0x0303 : 0;
}
