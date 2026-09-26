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
  printf ("CONNECTED alpn=%.*s\n", (int) info->alpn_len, info->alpn);
  fflush (stdout);
}

static int
ev_data (void *u, uint64_t id, const uint8_t *d, size_t n, int fin)
{
  struct app *a = u;
  struct xfer *x = xfer_get (a, id, 1);

  if (a->server)
    {
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
ev_ticket (void *u, const gq_tls_ticket *t, uint32_t version)
{
  (void) u;
  (void) t;
  (void) version;
}

/* ---- I/O ---- */

static int
lose (struct app *a)
{
  a->rng = a->rng * 1664525u + 1013904223u;
  return a->loss > 0 && (int) ((a->rng >> 12) % 100) < a->loss;
}

static void
flush_out (struct app *a)
{
  uint8_t buf[2048];
  size_t len;
  int guard = 0;

  if (a->c == NULL || !a->have_peer)
    return;
  while (guard++ < 1000 && gq_conn_send (a->c, now_us (), buf, sizeof buf, &len)
         == GQ_OK && len)
    {
      if (lose (a))
        continue;
      if (sendto (a->fd, buf, len, 0, (struct sockaddr *) &a->peer, a->plen)
          < 0 && errno != EAGAIN && errno != ENOBUFS)
        break;
    }
}

struct cfgs
{
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
  uint64_t start = now_us ();
  uint8_t buf[65536];

  for (;;)
    {
      uint64_t t = 0, now = now_us ();
      int wait_ms = 100;
      struct pollfd pfd;

      if (a->c)
        {
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
          return 2;
        }
      pfd.fd = a->fd;
      pfd.events = POLLIN;
      if (poll (&pfd, 1, wait_ms) > 0 && (pfd.revents & POLLIN))
        {
          struct sockaddr_storage from;
          socklen_t fl = sizeof from;
          ssize_t n = recvfrom (a->fd, buf, sizeof buf, 0,
                                (struct sockaddr *) &from, &fl);

          if (n > 0 && !lose (a))
            {
              if (a->server && a->c == NULL)
                {
                  gq_admit_config ac;
                  gq_conn_accept acc;
                  uint8_t reply[1500], key[20];
                  size_t rl = 0, kl = 0;
                  int act;
                  struct sockaddr_in *sin = (struct sockaddr_in *) &from;

                  memset (&ac, 0, sizeof ac);
                  ac.require_retry = a->retry;
                  memcpy (ac.versions, a->cfg.versions, sizeof ac.versions);
                  ac.n_versions = a->cfg.n_versions;
                  memcpy (key, &sin->sin_addr, 4);
                  memcpy (key + 4, &sin->sin_port, 2);
                  kl = 6;
                  act = gq_quic_admit (&a->keys, &ac, key, kl, buf, (size_t) n,
                                       (uint64_t) time (NULL), reply,
                                       sizeof reply, &rl, &acc);
                  if (act == GQ_ADMIT_REPLY)
                    {
                      sendto (a->fd, reply, rl, 0, (struct sockaddr *) &from,
                              fl);
                      continue;
                    }
                  if (act != GQ_ADMIT_ACCEPT)
                    continue;
                  a->peer = from;
                  a->plen = fl;
                  a->have_peer = 1;
                  if (gq_conn_server_accept (&a->c, &a->cfg, &g->sc, &a->ev,
                                             now_us (), &acc) != GQ_OK)
                    return 1;
                }
              if (a->c)
                {
                  gq_conn_stats st;

                  gq_conn_recv (a->c, now_us (), buf, (size_t) n);
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
      printf ("LISTENING\n");
      fflush (stdout);
      while (connections-- > 0)
        {
          size_t k;

          r = loop (&a, &g, timeout, 1);
          for (k = 0; k < a.nx; k++)
            free (a.x[k].data);
          free (a.x);
          a.x = NULL;
          a.nx = a.capx = 0;
          gq_conn_free (a.c);
          a.c = NULL;
          a.have_peer = 0;
          a.closed = 0;
          if (r)
            break;
        }
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
      memset (&hints, 0, sizeof hints);
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_DGRAM;
      if (getaddrinfo (host, port, &hints, &ai) != 0)
        return 1;
      a.fd = socket (ai->ai_family, SOCK_DGRAM, 0);
      memcpy (&a.peer, ai->ai_addr, ai->ai_addrlen);
      a.plen = ai->ai_addrlen;
      a.have_peer = 1;
      freeaddrinfo (ai);
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
            struct pollfd pfd;
            uint8_t buf[65536];
            uint64_t id;

            pump (&a);
            flush_out (&a);
            if (a.connected && gq_conn_stream_open (a.c, 1, &id) == GQ_OK)
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
            pfd.fd = a.fd;
            pfd.events = POLLIN;
            if (poll (&pfd, 1, 5) > 0)
              {
                ssize_t n = recv (a.fd, buf, sizeof buf, 0);

                if (n > 0 && !lose (&a))
                  gq_conn_recv (a.c, now_us (), buf, (size_t) n);
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
