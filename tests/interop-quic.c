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

/* A small QUIC client and server over real UDP sockets, speaking the
   HTTP/0.9 style "hq-interop" protocol (one request "GET /path" per
   bidirectional stream, answered with the file), for testing GNU QUIC
   against independent implementations.  A test tool, not part of the
   library.

   interop-quic client HOST PORT --ca FILE --out DIR PATH... [options]
   interop-quic server PORT --cert FILE --key FILE --root DIR [options]

   Options: --sni NAME, --alpn NAME, --v2, --loss PERCENT, --seed N,
   --timeout SECONDS, --connections N (server), --key-update.
   Exit status: 0 success, 1 usage or I/O error, 2 QUIC failure.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <gnuquic/status.h>
#include <gnuquic/conn.h>
#include <gnuquic/listen.h>
#include <gnuquic/endpoint.h>

#include "interop-util.h"

struct xfer
{
  uint64_t id;
  char path[256];
  uint8_t *data;		/* Server: the response; client: unused.  */
  size_t len, off;
  int have_req, fin_wanted, fin_done;
  char req[300];
  size_t req_len;
  FILE *out;			/* Client: where the response goes.  */
  size_t got;
  int done;
};

struct app
{
  int fd, server;
  int fds[2], nfds;		/* Sockets; fds[0] is fd.  */
  gq_addr laddr[2];		/* Their local addresses, as paths.  */
  int migrate, mig_done;
  const char *root, *outdir;
  struct sockaddr_storage peer;
  socklen_t plen;
  int have_peer;
  gq_conn *c;
  struct xfer *x;
  size_t nx, capx;
  int connected, closed, key_update, v2;
  int loss;
  uint32_t rng;
  int completed;
  size_t expected;
  gq_conn_events ev;
  gq_conn_config cfg;
  int retry;
  gq_token_keys keys;
  int dgram, dgram_left, dgram_recv;	/* DATAGRAM: enabled, to send.  */
  int early;				/* 0-RTT: server accepts, client uses.  */
  const char *session_file;		/* Client: where the session is kept.  */
  int saved_session;
  struct app *next;			/* Server: connections in a list.  */
};

static uint64_t
now_us (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

static struct xfer *
xfer_get (struct app *a, uint64_t id, int create)
{
  size_t i;

  for (i = 0; i < a->nx; i++)
    if (a->x[i].id == id)
      return &a->x[i];
  if (!create)
    return NULL;
  if (a->nx == a->capx)
    {
      a->capx = a->capx ? a->capx * 2 : 16;
      a->x = realloc (a->x, a->capx * sizeof *a->x);
    }
  memset (&a->x[a->nx], 0, sizeof a->x[0]);
  a->x[a->nx].id = id;
  return &a->x[a->nx++];
}

/* ---- Server side ---- */

static void
serve_request (struct app *a, struct xfer *x)
{
  char *p = x->req, *e;
  char full[1024];
  FILE *f;
  struct stat st;

  x->req[x->req_len] = 0;
  if (strncmp (p, "GET ", 4))
    return;
  p += 4;
  e = strpbrk (p, "\r\n ");
  if (e)
    *e = 0;
  if (strstr (p, ".."))
    return;
  snprintf (full, sizeof full, "%s/%s", a->root, p);
  f = fopen (full, "rb");
  if (f == NULL || fstat (fileno (f), &st) != 0)
    {
      if (f)
        fclose (f);
      x->data = (uint8_t *) strdup ("404\n");
      x->len = 4;
    }
  else
    {
      x->data = malloc ((size_t) st.st_size + 1);
      x->len = fread (x->data, 1, (size_t) st.st_size, f);
      fclose (f);
    }
  x->fin_wanted = 1;
  x->have_req = 1;
  printf ("REQUEST stream=%llu path=%s bytes=%zu\n", (unsigned long long) x->id,
          p, x->len);
  fflush (stdout);
}

static void
pump (struct app *a)
{
  size_t i;

  if (a->c == NULL || gq_conn_state (a->c) >= GQ_CONN_CLOSING)
    return;
  while (a->dgram_left > 0 && a->connected
         && gq_conn_datagram_send (a->c, (const uint8_t *) "brrr", 4, NULL)
            == GQ_OK)
    a->dgram_left--;
  for (i = 0; i < a->nx; i++)
    {
      struct xfer *x = &a->x[i];

      if (!a->server)
        {
          /* Client: send the request when the stream exists.  */
          if (x->req_len && !x->have_req)
            {
              long w = gq_conn_stream_write (a->c, x->id,
                                             (const uint8_t *) x->req,
                                             x->req_len);

              if (w == (long) x->req_len)
                {
                  gq_conn_stream_finish (a->c, x->id);
                  x->have_req = 1;
                }
            }
          continue;
        }
      while (x->have_req && x->off < x->len)
        {
          long w = gq_conn_stream_write (a->c, x->id, x->data + x->off,
                                         x->len - x->off);

          if (w <= 0)
            break;
          x->off += (size_t) w;
        }
      if (x->have_req && x->off == x->len && !x->fin_done)
        {
          gq_conn_stream_finish (a->c, x->id);
          x->fin_done = 1;
        }
    }
}

/* ---- Events ---- */

static void
ev_connected (void *u, const gq_tls_info *info)
{
  struct app *a = u;

  a->connected = 1;
  printf ("CONNECTED alpn=%.*s%s%s\n", (int) info->alpn_len, info->alpn,
          info->resumed ? " resumed" : "",
          info->early_data_accepted ? " early" : "");
  fflush (stdout);
}

static int
ev_data (void *u, uint64_t id, const uint8_t *d, size_t n, int fin)
{
  struct app *a = u;
  struct xfer *x = xfer_get (a, id, 1);

  if (a->server)
    {
      if (a->c && gq_conn_early_data_active (a->c))
        {
          printf ("EARLY_DATA stream=%llu bytes=%zu\n", (unsigned long long) id, n);
          fflush (stdout);
        }
      if (x->req_len + n < sizeof x->req)
        {
          memcpy (x->req + x->req_len, d, n);
          x->req_len += n;
        }
      if (fin && !x->have_req)
        serve_request (a, x);
    }
  else
    {
      if (x->out && n)
        fwrite (d, 1, n, x->out);
      x->got += n;
      if (fin)
        {
          if (x->out)
            fclose (x->out);
          x->out = NULL;
          x->done = 1;
          a->completed++;
          printf ("RECEIVED stream=%llu path=%s bytes=%zu\n",
                  (unsigned long long) id, x->path, x->got);
          fflush (stdout);
        }
    }
  return 0;
}

static void
ev_writable (void *u, uint64_t id)
{
  (void) u;
  (void) id;
}

static void
ev_closed (void *u, const gq_conn_close_info *i)
{
  struct app *a = u;

  a->closed = 1;
  printf ("CLOSED source=%d application=%d error=%llu reason=%.*s\n", i->source,
          i->application, (unsigned long long) i->error, (int) i->reason_len,
          i->reason ? (const char *) i->reason : "");
  fflush (stdout);
}

static void
ev_datagram (void *u, const uint8_t *d, size_t n)
{
  struct app *a = u;

  (void) d;
  a->dgram_recv++;
  printf ("DATAGRAM bytes=%zu\n", n);
  fflush (stdout);
}

static void
ev_path_validated (void *u, const gq_path *p)
{
  (void) u;
  (void) p;
  printf ("PATH_VALIDATED\n");
  fflush (stdout);
}

static void
ev_path_failed (void *u, const gq_path *p)
{
  (void) u;
  (void) p;
  printf ("PATH_FAILED\n");
  fflush (stdout);
}

static void
ev_migrated (void *u, const gq_path *p)
{
  (void) u;
  (void) p;
  printf ("MIGRATED\n");
  fflush (stdout);
}

static void
ev_ticket (void *u, const gq_tls_ticket *t, uint32_t version)
{
  struct app *a = u;
  gq_tls_session sess;
  uint8_t blob[4096], params[512];
  size_t bl = 0, pl = 0;
  uint32_t v32[3];
  FILE *f;

  /* Keep the first ticket, with what 0-RTT needs alongside it: the server's
     transport parameters and the QUIC version.  */
  if (a->server || a->session_file == NULL || a->saved_session)
    return;
  if (gq_tls_session_store (&sess, t) != GQ_OK
      || gq_tls_session_serialize (&sess, blob, sizeof blob, &bl) != GQ_OK
      || gq_conn_get_peer_params (a->c, params, sizeof params, &pl) != GQ_OK)
    return;
  f = fopen (a->session_file, "wb");
  if (f == NULL)
    return;
  v32[0] = version;
  v32[1] = (uint32_t) bl;
  v32[2] = (uint32_t) pl;
  fwrite (v32, sizeof v32, 1, f);
  fwrite (blob, 1, bl, f);
  fwrite (params, 1, pl, f);
  fclose (f);
  a->saved_session = 1;
  printf ("SESSION saved\n");
  fflush (stdout);
}

static void
ev_early_result (void *u, int accepted)
{
  (void) u;
  printf ("EARLY accepted=%d\n", accepted);
  fflush (stdout);
}

/* ---- I/O ---- */

static int
lose (struct app *a)
{
  a->rng = a->rng * 1664525u + 1013904223u;
  return a->loss > 0 && (int) ((a->rng >> 12) % 100) < a->loss;
}

/* IPv4 socket addresses as opaque path addresses: address, then port.  */
static void
to_addr (const struct sockaddr_storage *ss, gq_addr *a)
{
  const struct sockaddr_in *sin = (const struct sockaddr_in *) ss;

  memset (a, 0, sizeof *a);
  a->len = 6;
  memcpy (a->data, &sin->sin_addr, 4);
  memcpy (a->data + 4, &sin->sin_port, 2);
}

static void
from_addr (const gq_addr *a, struct sockaddr_storage *ss, socklen_t *len)
{
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;

  memset (ss, 0, sizeof *ss);
  sin->sin_family = AF_INET;
  memcpy (&sin->sin_addr, a->data, 4);
  memcpy (&sin->sin_port, a->data + 4, 2);
  *len = sizeof *sin;
}

static int
open_socket (struct app *a, int bind_port)
{
  struct sockaddr_in sin;
  socklen_t sl = sizeof sin;
  int fd = socket (AF_INET, SOCK_DGRAM, 0);

  if (fd < 0)
    return -1;
  if (!a->server)
    {
      memset (&sin, 0, sizeof sin);
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = htonl (INADDR_ANY);
      sin.sin_port = htons ((uint16_t) bind_port);
      if (bind (fd, (struct sockaddr *) &sin, sizeof sin) != 0)
        return -1;
    }
  a->fds[a->nfds] = fd;
  memset (&sin, 0, sizeof sin);
  if (getsockname (fd, (struct sockaddr *) &sin, &sl) == 0)
    to_addr ((struct sockaddr_storage *) &sin, &a->laddr[a->nfds]);
  a->nfds++;
  return fd;
}

/* Wait up to MS for a datagram on any socket.  Returns its size (0: none)
   and the path it arrived on.  */
static ssize_t
wait_datagram (struct app *a, int ms, uint8_t *buf, size_t cap,
               struct sockaddr_storage *from, socklen_t *fl, gq_path *path)
{
  struct pollfd pfd[2];
  int i;

  for (i = 0; i < a->nfds; i++)
    {
      pfd[i].fd = a->fds[i];
      pfd[i].events = POLLIN;
      pfd[i].revents = 0;
    }
  if (poll (pfd, (nfds_t) a->nfds, ms) <= 0)
    return 0;
  for (i = 0; i < a->nfds; i++)
    if (pfd[i].revents & POLLIN)
      {
        ssize_t n;

        *fl = sizeof *from;
        n = recvfrom (a->fds[i], buf, cap, 0, (struct sockaddr *) from, fl);
        if (n <= 0)
          return 0;
        path->local = a->laddr[i];
        to_addr (from, &path->remote);
        return n;
      }
  return 0;
}

static void
flush_out (struct app *a)
{
  uint8_t buf[2048];
  size_t len;
  int guard = 0;

  if (a->c == NULL || !a->have_peer)
    return;
  while (guard++ < 1000)
    {
      gq_path to;
      struct sockaddr_storage dest;
      socklen_t dl;
      int i, fd = a->fds[0];

      memset (&to, 0, sizeof to);
      if (gq_conn_send_path (a->c, now_us (), buf, sizeof buf, &len, &to)
          != GQ_OK || len == 0)
        break;
      if (lose (a))
        continue;
      for (i = 0; i < a->nfds; i++)
        if (to.local.len == a->laddr[i].len
            && !memcmp (to.local.data, a->laddr[i].data, to.local.len))
          fd = a->fds[i];
      if (to.remote.len == 6)
        from_addr (&to.remote, &dest, &dl);
      else
        {
          dest = a->peer;
          dl = a->plen;
        }
      if (sendto (fd, buf, len, 0, (struct sockaddr *) &dest, dl) < 0
          && errno != EAGAIN && errno != ENOBUFS)
        break;
    }
}

/* Client: once the handshake is confirmed, move to a new socket (a new
   source port).  Retried each round until it is accepted.  */
static void
try_migrate (struct app *a)
{
  gq_path np;

  if (!a->migrate || a->mig_done || a->server || !a->connected
      || a->nfds != 1)
    return;
  if (open_socket (a, 0) < 0)
    return;
  np.local = a->laddr[1];
  to_addr (&a->peer, &np.remote);
  if (gq_conn_migrate (a->c, now_us (), &np) == GQ_OK)
    a->mig_done = 1;
  else
    {
      close (a->fds[1]);
      a->nfds = 1;
    }
}

struct cfgs
{
  gq_tls_session sess;
  gq_tls_config cc;
  gq_tls_server_config sc;
  gq_slice alpn[1];
  gq_slice *chain;
  size_t n_chain;
  gq_privkey *key;
  gq_trust *trust;
  const char *sni;
};

static int
new_conn (struct app *a, struct cfgs *g)
{
  if (a->server)
    return gq_conn_server_new (&a->c, &a->cfg, &g->sc, &a->ev, now_us ());
  return gq_conn_client_new (&a->c, &a->cfg, &g->cc, &a->ev, now_us ());
}

/* Run until the connection is done or something completes.  */
static int
loop (struct app *a, struct cfgs *g, int timeout_s, int one_shot)
{
  (void) g;
  (void) one_shot;
  uint64_t start = now_us ();
  uint8_t buf[65536];

  for (;;)
    {
      uint64_t t = 0, now = now_us ();
      int wait_ms = 100;

      if (a->c)
        {
          try_migrate (a);
          pump (a);
          flush_out (a);
          t = gq_conn_timeout (a->c);
          if (t)
            wait_ms = t > now ? (int) ((t - now + 999) / 1000) : 0;
          if (wait_ms > 100)
            wait_ms = 100;
          if (gq_conn_state (a->c) == GQ_CONN_DONE)
            return a->connected ? 0 : 2;
        }
      if (!a->server && a->completed >= (int) a->expected && a->expected)
        {
          /* Everything arrived: close politely and let the peer see it.  */
          if (a->c && gq_conn_state (a->c) < GQ_CONN_CLOSING)
            gq_conn_close (a->c, now, 1, 0, "done");
          flush_out (a);
          return 0;
        }
      if (now - start > (uint64_t) timeout_s * 1000000)
        {
          fprintf (stderr, "timeout\n");
          if (a->c && getenv ("GQ_STATS"))
            {
              gq_conn_stats st;

              gq_conn_get_stats (a->c, &st);
              fprintf (stderr, "sent=%llu recv=%llu lost=%llu cwnd=%llu inflight=%llu pto=%u srtt=%llu\n",
                       (unsigned long long) st.packets_sent, (unsigned long long) st.packets_received,
                       (unsigned long long) st.packets_lost, (unsigned long long) st.cwnd,
                       (unsigned long long) st.bytes_in_flight, st.pto_count,
                       (unsigned long long) st.srtt_us);
            }
          return 2;
        }
      {
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        gq_path rpath;
        ssize_t n = wait_datagram (a, wait_ms, buf, sizeof buf, &from, &fl,
                                   &rpath);

          if (n > 0 && !lose (a))
            {
              if (a->c)
                {
                  gq_conn_stats st;

                  gq_conn_recv_path (a->c, now_us (), &rpath, buf, (size_t) n);
                  if (getenv ("GQ_DEBUG"))
                    {
                      gq_conn_get_stats (a->c, &st);
                      fprintf (stderr, "recv %zd: first=%02x pkts=%llu state=%d\n", n, buf[0], (unsigned long long) st.packets_received, (int) gq_conn_state (a->c));
                    }
                }
            }
        }
      if (a->c)
        gq_conn_on_timeout (a->c, now_us ());
      if (a->closed && a->c && gq_conn_state (a->c) == GQ_CONN_DONE)
        return one_shot ? 0 : 0;
    }
}

/* ---- Server on an endpoint: any number of connections at once ---- */

struct server
{
  struct app *tmpl;		/* Settings; its list holds the connections.  */
  struct app *conns;
  struct app *pending;
  int accepted, finished;
};

static int
srv_accept (void *u, const gq_path *from, gq_conn_events *ev)
{
  struct server *sv = u;
  struct app *ca = calloc (1, sizeof *ca);

  (void) from;
  *ca = *sv->tmpl;
  ca->c = NULL;
  ca->x = NULL;
  ca->nx = ca->capx = 0;
  ca->connected = ca->closed = 0;
  ca->next = sv->conns;
  sv->conns = ca;
  sv->pending = ca;
  *ev = sv->tmpl->ev;
  ev->user = ca;
  sv->accepted++;
  return 0;
}

static void
srv_connection (void *u, gq_conn *c)
{
  struct server *sv = u;

  if (sv->pending)
    sv->pending->c = c;
  sv->pending = NULL;
}

static void
srv_done (void *u, gq_conn *c)
{
  struct server *sv = u;
  struct app **pp, *ca;
  size_t k;

  for (pp = &sv->conns; *pp; pp = &(*pp)->next)
    if ((*pp)->c == c)
      {
        ca = *pp;
        *pp = ca->next;
        for (k = 0; k < ca->nx; k++)
          free (ca->x[k].data);
        free (ca->x);
        free (ca);
        break;
      }
  sv->finished++;
}

static int
serve (struct app *tmpl, struct cfgs *g, int timeout_s, int max_conns)
{
  struct server sv;
  gq_endpoint_config ec;
  gq_endpoint_events ee;
  gq_endpoint *ep;
  uint64_t start = now_us ();
  uint8_t buf[65536];

  memset (&sv, 0, sizeof sv);
  sv.tmpl = tmpl;
  memset (&ec, 0, sizeof ec);
  ec.conn = tmpl->cfg;
  ec.server = &g->sc;
  ec.admit.require_retry = tmpl->retry;
  ec.tickets = tmpl->early;
  ec.early_data = tmpl->early;
  memset (&ee, 0, sizeof ee);
  ee.user = &sv;
  ee.accept = srv_accept;
  ee.connection = srv_connection;
  ee.done = srv_done;
  if (gq_endpoint_new (&ep, &ec, &ee) != GQ_OK)
    return 1;
  for (;;)
    {
      uint64_t now = now_us (), t;
      struct app *ca;
      uint8_t out[2048];
      size_t len;
      gq_path to;
      int wait_ms = 100;
      struct sockaddr_storage from;
      socklen_t fl;
      gq_path rp;
      ssize_t n;

      for (ca = sv.conns; ca; ca = ca->next)
        pump (ca);
      while (gq_endpoint_send (ep, now, out, sizeof out, &len, &to) == GQ_OK
             && len)
        {
          struct sockaddr_storage dest;
          socklen_t dl;

          if (lose (tmpl) || to.remote.len != 6)
            continue;
          from_addr (&to.remote, &dest, &dl);
          sendto (tmpl->fds[0], out, len, 0, (struct sockaddr *) &dest, dl);
        }
      if (max_conns && sv.finished >= max_conns)
        break;
      if (now - start > (uint64_t) timeout_s * 1000000)
        {
          fprintf (stderr, "timeout\n");
          gq_endpoint_free (ep);
          return 2;
        }
      t = gq_endpoint_timeout (ep);
      if (t)
        wait_ms = t > now ? (int) ((t - now + 999) / 1000) : 0;
      if (wait_ms > 50)
        wait_ms = 50;
      n = wait_datagram (tmpl, wait_ms, buf, sizeof buf, &from, &fl, &rp);
      if (n > 0 && !lose (tmpl))
        gq_endpoint_recv (ep, now_us (), &rp, buf, (size_t) n);
      if ((t = gq_endpoint_timeout (ep)) != 0 && t <= now_us ())
        gq_endpoint_on_timeout (ep, now_us ());
    }
  gq_endpoint_free (ep);
  return 0;
}

int
main (int argc, char **argv)
{
  struct app a;
  struct cfgs g;
  const char *host = NULL, *port = NULL, *ca = NULL, *cert = NULL, *key = NULL;
  const char *alpn = "hq-interop", *sni = "example.test";
  int timeout = 30, connections = 1, i, r = 0;
  const char *paths[64];
  size_t npaths = 0;

  memset (&a, 0, sizeof a);
  memset (&g, 0, sizeof g);
  if (argc < 3)
    {
      fprintf (stderr, "usage: see the source\n");
      return 1;
    }
  gq_crypto_init ();
  a.server = !strcmp (argv[1], "server");
  if (a.server)
    port = argv[2];
  else if (argc >= 4)
    {
      host = argv[2];
      port = argv[3];
    }
  for (i = a.server ? 3 : 4; i < argc; i++)
    {
      const char *o = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;

      if (!strcmp (o, "--ca") && v) ca = v, i++;
      else if (!strcmp (o, "--cert") && v) cert = v, i++;
      else if (!strcmp (o, "--key") && v) key = v, i++;
      else if (!strcmp (o, "--root") && v) a.root = v, i++;
      else if (!strcmp (o, "--out") && v) a.outdir = v, i++;
      else if (!strcmp (o, "--sni") && v) sni = v, i++;
      else if (!strcmp (o, "--alpn") && v) alpn = v, i++;
      else if (!strcmp (o, "--loss") && v) a.loss = atoi (v), i++;
      else if (!strcmp (o, "--seed") && v) a.rng = (uint32_t) atoi (v), i++;
      else if (!strcmp (o, "--timeout") && v) timeout = atoi (v), i++;
      else if (!strcmp (o, "--connections") && v) connections = atoi (v), i++;
      else if (!strcmp (o, "--v2")) a.v2 = 1;
      else if (!strcmp (o, "--retry")) a.retry = 1;
      else if (!strcmp (o, "--migrate")) a.migrate = 1;
      else if (!strcmp (o, "--early")) a.early = 1;
      else if (!strcmp (o, "--session-file") && v) a.session_file = v, i++;
      else if (!strcmp (o, "--dgram") && v)
        {
          a.dgram = 1;
          a.dgram_left = atoi (v);
          i++;
        }
      else if (!strcmp (o, "--versions") && v)
        {
          /* Comma separated list of 1 and 2, most preferred first.  */
          const char *q;

          for (q = v; *q && a.cfg.n_versions < GQ_TP_MAX_VERSIONS; q++)
            if (*q == '1' || *q == '2')
              a.cfg.versions[a.cfg.n_versions++]
                = *q == '1' ? GQ_VERSION_1 : GQ_VERSION_2;
          i++;
        }
      else if (!strcmp (o, "--key-update")) a.key_update = 1;
      else if (o[0] != '-' && npaths < 64) paths[npaths++] = o;
      else
        {
          fprintf (stderr, "bad option %s\n", o);
          return 1;
        }
    }
  signal (SIGPIPE, SIG_IGN);
  gq_token_keys_init (&a.keys);
  a.cfg.version = a.v2 ? GQ_VERSION_2 : 0;
  a.ev.user = &a;
  a.ev.connected = ev_connected;
  a.ev.stream_data = ev_data;
  a.ev.stream_writable = ev_writable;
  a.ev.closed = ev_closed;
  a.ev.ticket = ev_ticket;
  a.ev.early_data_result = ev_early_result;
  a.ev.datagram = ev_datagram;
  a.ev.path_validated = ev_path_validated;
  a.ev.path_failed = ev_path_failed;
  a.ev.migrated = ev_migrated;
  if (a.dgram)
    a.cfg.max_datagram_frame_size = 1200;
  g.alpn[0].data = (const uint8_t *) alpn;
  g.alpn[0].len = strlen (alpn);

  if (a.server)
    {
      struct addrinfo hints, *ai;

      if (!cert || !key || !a.root)
        {
          fprintf (stderr, "--cert, --key and --root are required\n");
          return 1;
        }
      if (load_chain (cert, &g.chain, &g.n_chain) != 0
          || gq_privkey_from_pem_file (&g.key, key) != GQ_OK)
        {
          fprintf (stderr, "cannot load credentials\n");
          return 1;
        }
      g.sc.credentials.chain = g.chain;
      g.sc.credentials.n_chain = g.n_chain;
      g.sc.credentials.key = g.key;
      g.sc.alpn = g.alpn;
      g.sc.n_alpn = 1;
      memset (&hints, 0, sizeof hints);
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_flags = AI_PASSIVE;
      if (getaddrinfo (NULL, port, &hints, &ai) != 0)
        return 1;
      a.fd = socket (ai->ai_family, SOCK_DGRAM, 0);
      if (a.fd < 0 || bind (a.fd, ai->ai_addr, ai->ai_addrlen) != 0)
        {
          perror ("bind");
          return 1;
        }
      freeaddrinfo (ai);
      {
        struct sockaddr_in sin;
        socklen_t sl = sizeof sin;

        a.fds[0] = a.fd;
        a.nfds = 1;
        memset (&sin, 0, sizeof sin);
        if (getsockname (a.fd, (struct sockaddr *) &sin, &sl) == 0)
          to_addr ((struct sockaddr_storage *) &sin, &a.laddr[0]);
      }
      printf ("LISTENING\n");
      fflush (stdout);
      r = serve (&a, &g, timeout, connections);
      return r ? 2 : 0;
    }
  else
    {
      struct addrinfo hints, *ai;
      size_t k;

      if (!host || !ca || !a.outdir || npaths == 0)
        {
          fprintf (stderr, "HOST PORT, --ca, --out and paths are required\n");
          return 1;
        }
      if (gq_trust_new (&g.trust) != GQ_OK
          || gq_trust_add_pem_file (g.trust, ca) != GQ_OK)
        {
          fprintf (stderr, "cannot load CA\n");
          return 1;
        }
      g.cc.server_name = sni;
      g.cc.trust = g.trust;
      g.cc.alpn = g.alpn;
      g.cc.n_alpn = 1;
      /* A saved session from an earlier run, offered with early data.  */
      if (a.early && a.session_file)
        {
          FILE *sf = fopen (a.session_file, "rb");
          uint32_t v32[3];
          static uint8_t blob[4096], params[512];

          if (sf && fread (v32, sizeof v32, 1, sf) == 1 && v32[1] <= sizeof blob
              && v32[2] <= sizeof params
              && fread (blob, 1, v32[1], sf) == v32[1]
              && fread (params, 1, v32[2], sf) == v32[2]
              && gq_tls_session_deserialize (&g.sess, blob, v32[1]) == GQ_OK)
            {
              g.cc.resume = &g.sess;
              g.cc.early_data = 1;
              a.cfg.resume_params = params;
              a.cfg.resume_params_len = v32[2];
              /* The session's version, and only that.  */
              a.cfg.version = a.cfg.versions[0] = v32[0];
              a.cfg.n_versions = 1;
              printf ("RESUMING\n");
              fflush (stdout);
            }
          if (sf)
            fclose (sf);
        }
      memset (&hints, 0, sizeof hints);
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_DGRAM;
      if (getaddrinfo (host, port, &hints, &ai) != 0)
        return 1;
      a.fd = open_socket (&a, 0);
      if (a.fd < 0)
        return 1;
      memcpy (&a.peer, ai->ai_addr, ai->ai_addrlen);
      a.plen = ai->ai_addrlen;
      a.have_peer = 1;
      freeaddrinfo (ai);
      a.cfg.path.local = a.laddr[0];
      to_addr (&a.peer, &a.cfg.path.remote);
      if (new_conn (&a, &g) != GQ_OK)
        return 1;
      a.expected = npaths;
      /* Open the streams as soon as the connection allows it.  */
      {
        size_t opened = 0;
        uint64_t start = now_us ();

        while (opened < npaths && now_us () - start < (uint64_t) timeout
                                                    * 1000000)
          {
            uint8_t buf[65536];
            uint64_t id;

            pump (&a);
            flush_out (&a);
            if (gq_conn_stream_open (a.c, 1, &id) == GQ_OK)
              {
                struct xfer *x = xfer_get (&a, id, 1);
                char op[1024];
                const char *base = strrchr (paths[opened], '/');

                snprintf (x->path, sizeof x->path, "%s", paths[opened]);
                x->req_len = (size_t) snprintf (x->req, sizeof x->req,
                                                "GET %s\r\n", paths[opened]);
                snprintf (op, sizeof op, "%s/%s", a.outdir,
                          base ? base + 1 : paths[opened]);
                x->out = fopen (op, "wb");
                opened++;
                if (a.key_update && opened == npaths / 2 + 1)
                  gq_conn_update_keys (a.c, now_us ());
                continue;
              }
            try_migrate (&a);
            {
              struct sockaddr_storage from;
              socklen_t fl;
              gq_path rp;
              ssize_t n = wait_datagram (&a, 5, buf, sizeof buf, &from, &fl,
                                         &rp);

              if (n > 0 && !lose (&a))
                gq_conn_recv_path (a.c, now_us (), &rp, buf, (size_t) n);
            }
            gq_conn_on_timeout (a.c, now_us ());
            if (gq_conn_state (a.c) >= GQ_CONN_CLOSING)
              break;
          }
      }
      r = loop (&a, &g, timeout, 0);
      /* Give the close a moment to reach the peer.  */
      if (a.c)
        {
          uint64_t t0 = now_us ();

          while (now_us () - t0 < 300000 && gq_conn_state (a.c)
                                            < GQ_CONN_DONE)
            {
              flush_out (&a);
              usleep (10000);
              gq_conn_on_timeout (a.c, now_us ());
            }
        }
      for (k = 0; k < a.nx; k++)
        if (a.x[k].out)
          fclose (a.x[k].out);
      printf ("COMPLETED %d of %zu\n", a.completed, npaths);
      gq_conn_free (a.c);
      return a.completed == (int) npaths && r == 0 ? 0 : 2;
    }
}
