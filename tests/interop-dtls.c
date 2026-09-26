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

/* A small DTLS 1.3 (or, with --dtls12, DTLS 1.2) client and server over
   real UDP sockets, built on gq_dtls or gq_dtls12, for testing GNU QUIC against an independent implementation
   (tests/wolf-dtls.c, wolfSSL).  A test tool, not part of the library.

   interop-dtls client HOST PORT --ca FILE [options]
   interop-dtls server PORT --cert FILE --key FILE [options]

   Prints machine-readable lines that tests/interop-dtls.sh checks.  Exit
   status: 0 success, 1 usage or I/O error, 2 DTLS failure.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/dtls.h>
#include <gnuquic/dtls12.h>
#include <gnuquic/dtls12cookie.h>
#include <gnuquic/dtlsauto.h>
#include <gnuquic/dtlscookie.h>

#include "interop-util.h"

struct opts
{
  int server;
  unsigned versions;		/* GQ_DTLSAUTO_* pin; 0 negotiates.  */
  const char *host, *port, *sni, *ca, *cert, *key;
  const char *alpn[4];
  size_t n_alpn;
  uint16_t groups[8], suites[4];
  size_t n_groups, n_suites;
  unsigned mtu;
  int loss;			/* Percent of datagrams dropped each way.  */
  int loss_hs;			/* ...but only until the handshake is done.  */
  unsigned seed;
  int twice, messages, key_update, timeout, http, rev;
  int cookie, connections;
  size_t max_bytes;		/* Server: close after echoing this much.  */
  const char *client_auth;
  unsigned long rekey;
};

struct state
{
  int fd;
  struct opts *o;
  struct sockaddr_storage peer;
  socklen_t plen;
  int have_peer;
  gq_dtlsauto *d;		/* Negotiating, or pinned by --dtls12/--dtls13.  */
  int connected, closed, close_error, close_alert, tickets;
  gq_tls_info info;
  gq_tls_session saved;
  int have_saved;
  int echoed;			/* Client: replies received.  Server: sent.  */
  size_t bytes;
  char last[64];
  int got_new;			/* A datagram of application data arrived.  */
  uint32_t rng;
};

#define D_START(s, now) gq_dtlsauto_start ((s)->d, now)
#define D_RECEIVE(s, b, n, now) gq_dtlsauto_receive ((s)->d, b, n, now)
#define D_SEND(s, b, n) gq_dtlsauto_send ((s)->d, b, n)
#define D_CLOSE(s) gq_dtlsauto_close ((s)->d)
#define D_FREE(s) gq_dtlsauto_free ((s)->d)
#define D_DEADLINE(s) gq_dtlsauto_deadline ((s)->d)
#define D_TIMEOUT(s, now) gq_dtlsauto_timeout ((s)->d, now)

static uint64_t
now_ms (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

/* Deterministic loss.  */
static int
lose (struct state *s)
{
  s->rng = s->rng * 1664525u + 1013904223u;
  if (s->o->loss_hs && s->connected && s->got_new + s->tickets >= 0
      && s->o->loss_hs > 1)
    return 0;
  return s->o->loss > 0 && (int) ((s->rng >> 12) % 100) < s->o->loss;
}

static int
xsend (void *u, const uint8_t *d, size_t n)
{
  struct state *s = u;

  if (getenv ("GQ_DUMP"))
    {
      size_t i;

      fprintf (stderr, "send %zu:", n);
      for (i = 0; i < n && i < 120; i++)
        fprintf (stderr, "%02x", d[i]);
      fprintf (stderr, "\n");
    }
  if (lose (s))
    {
      if (getenv ("GQ_DUMP"))
        fprintf (stderr, "  (dropped)\n");
      return 0;
    }
  if (s->o->server)
    sendto (s->fd, d, n, 0, (struct sockaddr *) &s->peer, s->plen);
  else
    send (s->fd, d, n, 0);
  return 0;
}

static int
xdata (void *u, const uint8_t *d, size_t n)
{
  struct state *s = u;

  if (n < sizeof s->last)
    {
      memcpy (s->last, d, n);
      s->last[n] = 0;
    }
  s->got_new++;
  if (s->o->server)
    {
      /* Echo it.  */
      if (D_SEND (s, d, n) == GQ_OK)
        s->echoed++;
      s->bytes += n;
      if (s->o->max_bytes && s->bytes >= s->o->max_bytes)
        D_CLOSE (s);
    }
  else
    s->echoed++;
  return 0;
}

static int
xconnected (void *u, const gq_tls_info *i)
{
  struct state *s = u;

  s->connected = 1;
  s->info = *i;
  printf ("connected suite=0x%04x group=0x%04x hrr=%d alpn=%.*s sni=%s "
          "client_auth_requested=%d client_auth=%d resumed=%d\n",
          i->cipher_suite, i->group, i->hello_retry, (int) i->alpn_len,
          (const char *) i->alpn, i->server_name, i->client_auth_requested,
          i->client_auth_sent, i->resumed);
  fflush (stdout);
  return 0;
}

static int
xticket (void *u, const gq_tls_ticket *t)
{
  struct state *s = u;

  s->tickets++;
  if (gq_tls_session_store (&s->saved, t) == GQ_OK)
    s->have_saved = 1;
  return 0;
}

static void
xclosed (void *u, int error, int alert)
{
  struct state *s = u;

  s->closed = 1;
  s->close_error = error;
  s->close_alert = alert;
}

static uint16_t
group_code (const char *n)
{
  if (!strcmp (n, "x25519")) return GQ_GROUP_X25519;
  if (!strcmp (n, "p256")) return GQ_GROUP_SECP256R1;
  if (!strcmp (n, "p384")) return GQ_GROUP_SECP384R1;
  if (!strcmp (n, "x25519mlkem768")) return GQ_GROUP_X25519_MLKEM768;
  if (!strcmp (n, "p256mlkem768")) return GQ_GROUP_SECP256R1_MLKEM768;
  return 0;
}

static uint16_t
suite_code (const char *n)
{
  if (!strcmp (n, "aes128")) return GQ_TLS_AES_128_GCM_SHA256;
  if (!strcmp (n, "aes256")) return GQ_TLS_AES_256_GCM_SHA384;
  if (!strcmp (n, "chacha")) return GQ_TLS_CHACHA20_POLY1305_SHA256;
  if (!strcmp (n, "ecdsa-aes128")) return GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
  if (!strcmp (n, "ecdsa-aes256")) return GQ_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
  if (!strcmp (n, "ecdsa-chacha")) return GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305;
  if (!strcmp (n, "rsa-aes128")) return GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
  if (!strcmp (n, "rsa-aes256")) return GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
  if (!strcmp (n, "rsa-chacha")) return GQ_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305;
  return 0;
}

static void
alarm_handler (int sig)
{
  static const char m[] = "result=fail reason=timeout\n";

  (void) sig;
  (void) write (1, m, sizeof m - 1);
  _exit (1);
}

static void
set_events (gq_dtls_events *ev, struct state *s)
{
  memset (ev, 0, sizeof *ev);
  ev->user = s;
  ev->send = xsend;
  ev->data = xdata;
  ev->connected = xconnected;
  ev->ticket = xticket;
  ev->closed = xclosed;
}

/* Wait for input or the association's timer.  Returns bytes read, 0 for a
   timeout (already handled), -1 for an error.  */
static ssize_t
wait_and_read (struct state *s, uint8_t *buf, size_t cap, int max_ms,
               struct sockaddr_storage *from, socklen_t *fl)
{
  uint64_t now = now_ms (), dl = s->d ? D_DEADLINE (s) : 0;
  int ms = max_ms;
  struct pollfd p;
  int r;

  if (dl)
    {
      int until = dl > now ? (int) (dl - now) : 0;

      if (until < ms)
        ms = until;
    }
  p.fd = s->fd;
  p.events = POLLIN;
  r = poll (&p, 1, ms);
  now = now_ms ();
  if (r > 0 && (p.revents & POLLIN))
    {
      ssize_t n;

      *fl = sizeof *from;
      n = recvfrom (s->fd, buf, cap, 0, (struct sockaddr *) from, fl);
      return n < 0 ? -1 : n;
    }
  if (s->d && dl && now >= dl)
    D_TIMEOUT (s, now);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Client                                                             */
/* ------------------------------------------------------------------ */

static int
connect_udp (const char *host, const char *port)
{
  struct addrinfo hints, *res, *a;
  int fd = -1;

  memset (&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo (host, port, &hints, &res) != 0)
    return -1;
  for (a = res; a; a = a->ai_next)
    {
      fd = socket (a->ai_family, a->ai_socktype, a->ai_protocol);
      if (fd < 0)
        continue;
      if (connect (fd, a->ai_addr, a->ai_addrlen) == 0)
        break;
      close (fd);
      fd = -1;
    }
  freeaddrinfo (res);
  return fd;
}

static int
run_client (struct opts *o, const gq_tls_config *cfg, gq_tls_session *save,
            int *have_save)
{
  struct state st;
  gq_dtls_events ev;
  gq_dtls_params params;
  uint8_t buf[2048];
  int r, k = 0, tries = 0;
  uint64_t last_send = 0, close_after = 0;
  char m[32];

  memset (&st, 0, sizeof st);
  st.o = o;
  st.rng = o->seed ? o->seed : 1;
  st.fd = connect_udp (o->host, o->port);
  if (st.fd < 0)
    {
      printf ("result=fail reason=connect\n");
      return 1;
    }
  set_events (&ev, &st);
  memset (&params, 0, sizeof params);
  params.mtu = o->mtu;
  params.rekey_records = o->rekey;
  r = gq_dtlsauto_client_new (&st.d, cfg, &ev, &params, o->versions);
  if (r != GQ_OK)
    {
      printf ("result=fail reason=new status=%d\n", r);
      return 1;
    }
  D_START (&st, now_ms ());

  while (!st.closed)
    {
      ssize_t n = wait_and_read (&st, buf, sizeof buf, 200, &st.peer, &st.plen);
      uint64_t now = now_ms ();

      if (n < 0)
        break;
      if (n > 0 && getenv ("GQ_DUMP"))
        fprintf (stderr, "recv %zd: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", n,
                 buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6],
                 buf[7], buf[8], buf[9], buf[10], buf[11], buf[12]);
      if (n > 0 && !lose (&st))
        D_RECEIVE (&st, buf, (size_t) n, now);
      if (!st.connected || st.closed)
        continue;
      /* Stop and wait: one numbered message, resent if unanswered.  */
      if (k < o->messages)
        {
          if (st.echoed > k)
            {
              k = st.echoed;
              tries = 0;
              last_send = 0;
              if (k == o->messages / 2 && o->key_update)
                {
                  gq_dtlsauto_key_update (st.d, 1);
                }
            }
          if (k < o->messages && (last_send == 0 || now - last_send > 600))
            {
              snprintf (m, sizeof m, "hello-%d", k);
              if (tries++ > 12)
                break;
              D_SEND (&st, (const uint8_t *) m, strlen (m));
              last_send = now;
            }
        }
      else
        {
          /* Done.  If we will resume, wait a moment for the ticket, which
             arrives after the handshake and needs its ACK.  */
          if (close_after == 0)
            close_after = now + (o->twice ? 2500 : 100);
          if (now >= close_after || (o->twice && st.have_saved))
            {
              D_CLOSE (&st);
              break;
            }
        }
    }
  if (save && st.have_saved)
    {
      *save = st.saved;
      if (have_save)
        *have_save = 1;
    }
  printf ("version=%x\n", gq_dtlsauto_version (st.d));
  printf ("tickets=%d\n", st.tickets);
  printf ("echoed=%d\n", st.echoed);
  if (st.connected && st.echoed >= o->messages && st.close_error == 0)
    {
      printf ("result=ok\n");
      D_FREE (&st);
      return 0;
    }
  printf ("result=fail status=%d alert=%d closed=%d\n", st.close_error,
          st.close_alert, st.closed);
  D_FREE (&st);
  return 2;
}

/* ------------------------------------------------------------------ */
/* Server                                                             */
/* ------------------------------------------------------------------ */

static int
same_peer (const struct state *s, const struct sockaddr_storage *a,
           socklen_t al)
{
  return s->have_peer && al == s->plen && memcmp (&s->peer, a, al) == 0;
}

static int
run_server (struct opts *o, gq_tls_server_config *cfg, int fd)
{
  struct state st;
  gq_dtls_events ev;
  gq_dtls_params params;
  gq_dtls_cookies *ck = NULL;
  uint8_t buf[2048], reply[GQ_DTLS_LISTEN_REPLY_MAX];
  int ok = 1;
  int idle_after_close = 0;

  memset (&st, 0, sizeof st);
  st.o = o;
  st.fd = fd;
  st.rng = o->seed ? o->seed : 7;
  set_events (&ev, &st);
  memset (&params, 0, sizeof params);
  params.mtu = o->mtu;
  params.rekey_records = o->rekey;
  if (o->cookie && gq_dtls_cookies_new (&ck) != GQ_OK)
    return 1;

  while (!st.closed)
    {
      struct sockaddr_storage from;
      socklen_t fl = sizeof from;
      ssize_t n = wait_and_read (&st, buf, sizeof buf, 200, &from, &fl);
      uint64_t now = now_ms ();

      if (n < 0)
        {
          ok = 0;
          break;
        }
      if (n == 0)
        {
          /* An association whose peer went quiet after connecting.  */
          if (st.d && st.connected && ++idle_after_close > 60)
            break;
          continue;
        }
      idle_after_close = 0;
      if (lose (&st))
        continue;
      if (st.d && same_peer (&st, &from, fl))
        {
          D_RECEIVE (&st, buf, (size_t) n, now);
          continue;
        }
      if (st.d)
        continue;			/* Another source: not served.  */
      if (ck)
        {
          gq_dtlsauto_prime prime;
          size_t rl;
          int r;

          r = gq_dtlsauto_listen (ck, cfg, o->versions,
                                  (const uint8_t *) &from, fl, buf,
                                  (size_t) n, reply, sizeof reply, &rl,
                                  &prime);
          if (r == GQ_DTLS_LISTEN_REPLY)
            {
              if (!lose (&st))
                sendto (fd, reply, rl, 0, (struct sockaddr *) &from, fl);
              printf ("cookie-sent\n");
              fflush (stdout);
            }
          else if (r == GQ_DTLS_LISTEN_ACCEPT)
            {
              st.peer = from;
              st.plen = fl;
              st.have_peer = 1;
              if (gq_dtlsauto_server_new (&st.d, cfg, &ev, &params,
                                          o->versions, &prime) != GQ_OK)
                {
                  ok = 0;
                  break;
                }
              printf ("cookie-verified\n");
              D_RECEIVE (&st, buf, (size_t) n, now);
            }
        }
      else
        {
          st.peer = from;
          st.plen = fl;
          st.have_peer = 1;
          if (gq_dtlsauto_server_new (&st.d, cfg, &ev, &params, o->versions,
                                      NULL) != GQ_OK)
            {
              ok = 0;
              break;
            }
          D_RECEIVE (&st, buf, (size_t) n, now);
        }
    }
  printf ("version=%x\n", st.d ? gq_dtlsauto_version (st.d) : 0);
  printf ("echoed=%d\n", st.echoed);
  if (!(ok && st.connected && st.close_error == 0))
    {
      printf ("connection-failed status=%d alert=%d\n", st.close_error,
              st.close_alert);
      ok = 0;
    }
  fflush (stdout);
  D_FREE (&st);
  gq_dtls_cookies_free (ck);
  printf (ok ? "result=ok\n" : "result=fail\n");
  return ok ? 0 : 2;
}

int
main (int argc, char **argv)
{
  struct opts o;
  int ia;
  gq_trust *trust = NULL;
  gq_privkey *key = NULL;
  gq_slice chain_slices[4], *chain = NULL, alpn[4];
  size_t chain_n = 0, i;

  memset (&o, 0, sizeof o);
  o.timeout = 30;
  o.messages = 3;
  o.connections = 1;
  if (argc < 3)
    {
      fprintf (stderr, "usage: interop-dtls client HOST PORT | server PORT\n");
      return 1;
    }
  o.server = !strcmp (argv[1], "server");
  if (o.server)
    {
      o.port = argv[2];
      ia = 3;
    }
  else
    {
      if (argc < 4)
        return 1;
      o.host = argv[2];
      o.port = argv[3];
      ia = 4;
    }
  for (; ia < argc; ia++)
    {
      const char *a = argv[ia];
      const char *v = ia + 1 < argc ? argv[ia + 1] : NULL;

#define OPT(name) (!strcmp (a, name) && v && (ia++, 1))
      if (OPT ("--sni")) o.sni = v;
      else if (OPT ("--ca")) o.ca = v;
      else if (OPT ("--cert")) o.cert = v;
      else if (OPT ("--key")) o.key = v;
      else if (OPT ("--alpn") && o.n_alpn < 4) o.alpn[o.n_alpn++] = v;
      else if (OPT ("--groups"))
        {
          char *l = strdup (v), *tok, *sv = NULL;

          for (tok = strtok_r (l, ",", &sv); tok && o.n_groups < 8;
               tok = strtok_r (NULL, ",", &sv))
            o.groups[o.n_groups++] = group_code (tok);
        }
      else if (OPT ("--suites"))
        {
          char *l = strdup (v), *tok, *sv = NULL;

          for (tok = strtok_r (l, ",", &sv); tok && o.n_suites < 4;
               tok = strtok_r (NULL, ",", &sv))
            o.suites[o.n_suites++] = suite_code (tok);
        }
      else if (OPT ("--mtu")) o.mtu = (unsigned) atoi (v);
      else if (OPT ("--loss")) o.loss = atoi (v);
      else if (OPT ("--seed")) o.seed = (unsigned) atoi (v);
      else if (OPT ("--messages")) o.messages = atoi (v);
      else if (OPT ("--timeout")) o.timeout = atoi (v);
      else if (OPT ("--connections")) o.connections = atoi (v);
      else if (OPT ("--max-bytes")) o.max_bytes = (size_t) atol (v);
      else if (OPT ("--client-auth")) o.client_auth = v;
      else if (OPT ("--rekey")) o.rekey = (unsigned long) atol (v);
      else if (!strcmp (a, "--loss-handshake")) o.loss_hs = 2;
      else if (!strcmp (a, "--dtls12")) o.versions = GQ_DTLSAUTO_DTLS12;
      else if (!strcmp (a, "--dtls13")) o.versions = GQ_DTLSAUTO_DTLS13;
      else if (!strcmp (a, "--http")) { o.http = 1; o.messages = 1; }
      else if (!strcmp (a, "--rev")) { o.rev = 1; o.messages = 1; }
      else if (!strcmp (a, "--twice")) o.twice = 1;
      else if (!strcmp (a, "--key-update")) o.key_update = 1;
      else if (!strcmp (a, "--cookie")) o.cookie = 1;
      else
        {
          fprintf (stderr, "unknown option %s\n", a);
          return 1;
        }
    }
  signal (SIGALRM, alarm_handler);
  signal (SIGPIPE, SIG_IGN);
  alarm ((unsigned) o.timeout);

  if (o.ca)
    {
      if (gq_trust_new (&trust) != GQ_OK || gq_trust_add_pem_file (trust, o.ca))
        {
          fprintf (stderr, "cannot load CA %s\n", o.ca);
          return 1;
        }
    }
  if (o.cert && o.key)
    {
      if (load_chain (o.cert, &chain, &chain_n) != 0
          || gq_privkey_from_pem_file (&key, o.key) != GQ_OK)
        {
          fprintf (stderr, "cannot load certificate/key\n");
          return 1;
        }
      for (i = 0; i < chain_n && i < 4; i++)
        chain_slices[i] = chain[i];
    }
  for (i = 0; i < o.n_alpn; i++)
    {
      alpn[i].data = (const uint8_t *) o.alpn[i];
      alpn[i].len = strlen (o.alpn[i]);
    }

  if (!o.server)
    {
      gq_tls_config cfg;
      gq_tls_session first;
      int have_first = 0, rc;

      if (trust == NULL)
        {
          fprintf (stderr, "--ca is required\n");
          return 1;
        }
      memset (&cfg, 0, sizeof cfg);
      cfg.server_name = o.sni;
      cfg.trust = trust;
      cfg.alpn = alpn;
      cfg.n_alpn = o.n_alpn;
      if (o.n_groups) { cfg.groups = o.groups; cfg.n_groups = o.n_groups; }
      if (o.n_suites) { cfg.suites = o.suites; cfg.n_suites = o.n_suites; }
      if (key)
        {
          cfg.client_chain = chain_slices;
          cfg.n_client_chain = chain_n < 4 ? chain_n : 4;
          cfg.client_key = key;
        }
      memset (&first, 0, sizeof first);
      rc = run_client (&o, &cfg, &first, &have_first);
      if (rc != 0 || !o.twice)
        return rc;
      if (!have_first)
        {
          printf ("result=fail reason=no-ticket\n");
          return 2;
        }
      cfg.resume = &first;
      return run_client (&o, &cfg, NULL, NULL);
    }
  else
    {
      gq_tls_server_config cfg;
      gq_ticket_keys *keys;
      struct sockaddr_in addr;
      int fd, one = 1, rc = 0, c;

      if (!key)
        {
          fprintf (stderr, "--cert and --key are required\n");
          return 1;
        }
      memset (&cfg, 0, sizeof cfg);
      cfg.credentials.chain = chain_slices;
      cfg.credentials.n_chain = chain_n < 4 ? chain_n : 4;
      cfg.credentials.key = key;
      cfg.alpn = alpn;
      cfg.n_alpn = o.n_alpn;
      if (o.n_groups) { cfg.groups = o.groups; cfg.n_groups = o.n_groups; }
      if (o.n_suites) { cfg.suites = o.suites; cfg.n_suites = o.n_suites; }
      if (o.client_auth)
        {
          cfg.client_auth = !strcmp (o.client_auth, "required")
            ? GQ_CLIENT_AUTH_REQUIRED : GQ_CLIENT_AUTH_OPTIONAL;
          cfg.client_trust = trust;
        }
      if (gq_ticket_keys_new (&keys) != GQ_OK)
        return 1;
      cfg.ticket_keys = keys;

      fd = socket (AF_INET, SOCK_DGRAM, 0);
      setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
      memset (&addr, 0, sizeof addr);
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
      addr.sin_port = htons ((uint16_t) atoi (o.port));
      if (bind (fd, (struct sockaddr *) &addr, sizeof addr) != 0)
        {
          perror ("bind");
          return 1;
        }
      printf ("listening\n");
      fflush (stdout);
      for (c = 0; c < o.connections; c++)
        {
          int r = run_server (&o, &cfg, fd);

          if (r)
            rc = r;
        }
      return rc;
    }
}
