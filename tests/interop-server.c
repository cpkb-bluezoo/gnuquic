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

/* A small TLS 1.3 server used to test GNU QUIC against independent
   clients (openssl s_client, gnutls-cli).  It is a test tool: it accepts
   one connection, echoes what it receives, and prints machine-readable
   lines for tests/interop.sh.

   Usage: interop-server PORT --cert FILE --key FILE [options]
   Exit status: 0 orderly, 2 TLS failure, 1 usage or I/O error.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/tlsconn.h>

#include "interop-util.h"

struct named
{
  const char *name;
  gq_tls_credentials creds;
};

struct state
{
  int fd;
  struct named named[4];
  size_t n_named;
  gq_tls_credentials def;
  int connected, closed, close_error, close_alert;
  size_t echoed, max_bytes;
  int resumed;
  int key_update_after, chunks;
  gq_tlsconn *conn;
  int done;
};

static int
xwrite (void *u, const uint8_t *d, size_t n)
{
  struct state *s = u;

  while (n > 0)
    {
      ssize_t k = send (s->fd, d, n, 0);

      if (k < 0)
        {
          if (errno == EINTR)
            continue;
          return 1;
        }
      d += k;
      n -= (size_t) k;
    }
  return 0;
}

static int
xdata (void *u, const uint8_t *d, size_t n)
{
  struct state *s = u;

  s->chunks++;
  if (gq_tlsconn_send (s->conn, d, n) != GQ_OK)
    return 1;
  s->echoed += n;
  if (s->key_update_after && s->chunks == s->key_update_after)
    gq_tlsconn_key_update (s->conn, 1);
  if (s->max_bytes && s->echoed >= s->max_bytes)
    {
      gq_tlsconn_close (s->conn);
      s->done = 1;
    }
  return 0;
}

static int
xconnected (void *u, const gq_tls_info *i)
{
  struct state *s = u;

  s->connected = 1;
  printf ("connected suite=0x%04x group=0x%04x hrr=%d alpn=%.*s sni=%s "
          "client_auth_requested=%d client_auth=%d resumed=%d\n",
          i->cipher_suite, i->group, i->hello_retry, (int) i->alpn_len,
          (const char *) i->alpn, i->server_name, i->client_auth_requested,
          i->client_auth_sent, i->resumed);
  fflush (stdout);
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

static const gq_tls_credentials *
select_creds (void *u, const char *name)
{
  struct state *s = u;
  size_t i;

  if (name == NULL)
    return &s->def;
  for (i = 0; i < s->n_named; i++)
    if (strcmp (s->named[i].name, name) == 0)
      return &s->named[i].creds;
  return NULL;
}

static uint16_t
group_code (const char *n)
{
  if (!strcmp (n, "x25519")) return GQ_GROUP_X25519;
  if (!strcmp (n, "p256")) return GQ_GROUP_SECP256R1;
  if (!strcmp (n, "p384")) return GQ_GROUP_SECP384R1;
  if (!strcmp (n, "x25519mlkem768")) return GQ_GROUP_X25519_MLKEM768;
  if (!strcmp (n, "p256mlkem768")) return GQ_GROUP_SECP256R1_MLKEM768;
  if (!strcmp (n, "p384mlkem1024")) return GQ_GROUP_SECP384R1_MLKEM1024;
  return 0;
}

static uint16_t
suite_code (const char *n)
{
  if (!strcmp (n, "aes128")) return GQ_TLS_AES_128_GCM_SHA256;
  if (!strcmp (n, "aes256")) return GQ_TLS_AES_256_GCM_SHA384;
  if (!strcmp (n, "chacha")) return GQ_TLS_CHACHA20_POLY1305_SHA256;
  return 0;
}

static int
load_creds (const char *cert, const char *key, gq_tls_credentials *out)
{
  gq_slice *chain;
  gq_privkey *k;
  size_t n;

  if (load_chain (cert, &chain, &n) != 0
      || gq_privkey_from_pem_file (&k, key) != GQ_OK)
    return -1;
  out->key = k;
  out->chain = chain;
  out->n_chain = n;
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

int
main (int argc, char **argv)
{
  struct state st;
  gq_tls_server_config cfg;
  gq_tlsconn_events ev;
  uint16_t groups[8], suites[4];
  size_t n_groups = 0, n_suites = 0, i;
  gq_slice alpn[4];
  const char *alpn_names[4];
  size_t n_alpn = 0;
  const char *cert = NULL, *key = NULL, *ca = NULL;
  int timeout = 20, i_arg, listen_fd, one = 1, r = GQ_OK;
  int connections = 1, conn_no, tickets = 1, all_ok = 1;
  gq_ticket_keys *keys = NULL;
  unsigned long rekey = 0;
  gq_trust *trust = NULL;
  struct sockaddr_in addr;
  uint8_t buf[16384];

  memset (&st, 0, sizeof st);
  memset (&cfg, 0, sizeof cfg);
  if (argc < 2)
    {
      fprintf (stderr, "usage: interop-server PORT --cert F --key F [opts]\n");
      return 1;
    }
  for (i_arg = 2; i_arg < argc; i_arg++)
    {
      const char *a = argv[i_arg];
      const char *v = i_arg + 1 < argc ? argv[i_arg + 1] : NULL;

#define OPT(name) (!strcmp (a, name) && v && (i_arg++, 1))
      if (OPT ("--cert")) cert = v;
      else if (OPT ("--key")) key = v;
      else if (OPT ("--ca")) ca = v;
      else if (OPT ("--alpn") && n_alpn < 4) alpn_names[n_alpn++] = v;
      else if (OPT ("--groups"))
        {
          char *l = strdup (v), *tok, *save = NULL;

          for (tok = strtok_r (l, ",", &save); tok && n_groups < 8;
               tok = strtok_r (NULL, ",", &save))
            groups[n_groups++] = group_code (tok);
        }
      else if (OPT ("--suites"))
        {
          char *l = strdup (v), *tok, *save = NULL;

          for (tok = strtok_r (l, ",", &save); tok && n_suites < 4;
               tok = strtok_r (NULL, ",", &save))
            suites[n_suites++] = suite_code (tok);
        }
      else if (OPT ("--sni") && st.n_named < 4)
        {
          /* NAME=CERT:KEY */
          char *spec = strdup (v), *eq = strchr (spec, '='),
            *colon = eq ? strchr (eq, ':') : NULL;

          if (!eq || !colon)
            {
              fprintf (stderr, "bad --sni %s\n", v);
              return 1;
            }
          *eq = 0;
          *colon = 0;
          st.named[st.n_named].name = spec;
          if (load_creds (eq + 1, colon + 1, &st.named[st.n_named].creds))
            {
              fprintf (stderr, "cannot load credentials for %s\n", spec);
              return 1;
            }
          st.n_named++;
        }
      else if (OPT ("--client-auth"))
        cfg.client_auth = !strcmp (v, "required") ? GQ_CLIENT_AUTH_REQUIRED
          : !strcmp (v, "optional") ? GQ_CLIENT_AUTH_OPTIONAL
          : GQ_CLIENT_AUTH_NONE;
      else if (!strcmp (a, "--hrr-cookie")) cfg.hello_retry_cookie = 1;
      else if (OPT ("--max-bytes")) st.max_bytes = (size_t) atol (v);
      else if (OPT ("--key-update")) st.key_update_after = atoi (v);
      else if (OPT ("--rekey")) rekey = (unsigned long) atol (v);
      else if (OPT ("--timeout")) timeout = atoi (v);
      else if (OPT ("--connections")) connections = atoi (v);
      else if (!strcmp (a, "--no-tickets")) tickets = 0;
      else
        {
          fprintf (stderr, "unknown option %s\n", a);
          return 1;
        }
    }
  if (cert == NULL || key == NULL)
    {
      fprintf (stderr, "--cert and --key are required\n");
      return 1;
    }
  if (load_creds (cert, key, &st.def))
    {
      fprintf (stderr, "cannot load %s / %s\n", cert, key);
      return 1;
    }
  if (ca)
    {
      if (gq_trust_new (&trust) != GQ_OK || gq_trust_add_pem_file (trust, ca))
        {
          fprintf (stderr, "cannot load CA %s\n", ca);
          return 1;
        }
      cfg.client_trust = trust;
    }
  cfg.credentials = st.def;
  if (tickets)
    {
      if (gq_ticket_keys_new (&keys) != GQ_OK)
        return 1;
      cfg.ticket_keys = keys;
    }
  if (st.n_named)
    {
      cfg.select_credentials = select_creds;
      cfg.select_user = &st;
    }
  for (i = 0; i < n_alpn; i++)
    {
      alpn[i].data = (const uint8_t *) alpn_names[i];
      alpn[i].len = strlen (alpn_names[i]);
    }
  cfg.alpn = alpn;
  cfg.n_alpn = n_alpn;
  if (n_groups)
    {
      cfg.groups = groups;
      cfg.n_groups = n_groups;
    }
  if (n_suites)
    {
      cfg.suites = suites;
      cfg.n_suites = n_suites;
    }

  signal (SIGALRM, alarm_handler);
  signal (SIGPIPE, SIG_IGN);
  alarm ((unsigned) timeout);

  listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  setsockopt (listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  memset (&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = htons ((uint16_t) atoi (argv[1]));
  if (bind (listen_fd, (struct sockaddr *) &addr, sizeof addr) != 0
      || listen (listen_fd, 1) != 0)
    {
      perror ("bind/listen");
      return 1;
    }
  printf ("listening\n");
  fflush (stdout);
  for (conn_no = 0; conn_no < connections; conn_no++)
    {
      st.connected = st.closed = st.close_error = st.close_alert = 0;
      st.echoed = 0;
      st.chunks = 0;
      st.done = 0;
      r = GQ_OK;
      st.fd = accept (listen_fd, NULL, NULL);
      if (st.fd < 0)
        return 1;

      memset (&ev, 0, sizeof ev);
      ev.user = &st;
      ev.write = xwrite;
      ev.data = xdata;
      ev.connected = xconnected;
      ev.closed = xclosed;
      ev.rekey_records = rekey;
      if (gq_tlsconn_server_new (&st.conn, &cfg, &ev) != GQ_OK)
        {
          printf ("result=fail reason=new\n");
          return 1;
        }
      while (r == GQ_OK && !st.closed)
        {
          ssize_t n = recv (st.fd, buf, sizeof buf, 0);

          if (n < 0 && errno == EINTR)
            continue;
          if (n <= 0)
            {
              if (st.done)
                break;
              st.closed = 1;
              st.close_error = st.connected ? 0 : GQ_ERR_PROTOCOL;
              break;
            }
          r = gq_tlsconn_receive (st.conn, buf, (size_t) n);
        }
      printf ("echoed=%zu\n", st.echoed);
      if (!(r == GQ_OK && st.close_error == 0 && (st.connected || st.done)))
        {
          printf ("connection-failed status=%d alert=%d\n",
                  r != GQ_OK ? r : st.close_error, st.close_alert);
          all_ok = 0;
        }
      fflush (stdout);
      gq_tlsconn_free (st.conn);
      close (st.fd);
    }
  if (all_ok)
    {
      printf ("result=ok\n");
      return 0;
    }
  printf ("result=fail\n");
  return 2;
}
