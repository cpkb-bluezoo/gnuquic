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

/* A small TLS 1.3 (or, with --tls12, TLS 1.2) client used to test GNU QUIC
   against independent servers (OpenSSL, GnuTLS).  It is a test tool, not
   part of the library: it does blocking socket I/O around gq_tlsconn or
   gq_tls12conn.

   Usage: interop-client HOST PORT [options]

   Prints machine-readable lines (connected, tickets, received, result)
   that tests/interop.sh checks.  Exit status: 0 success, 1 usage or I/O
   error, 2 TLS failure.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/tlsconn.h>
#include <gnuquic/tls12conn.h>
#include <gnuquic/tlsauto.h>

#include "interop-util.h"

struct opts
{
  const char *host, *port, *sni, *ca, *cert, *key;
  const char *alpn[4];
  size_t n_alpn;
  uint16_t groups[8];
  size_t n_groups;
  uint16_t suites[8];
  size_t n_suites;
  int tls12, tls13;
  const char *send;		/* Request text, escapes decoded.  */
  const char *expect;
  const char *out;
  size_t min_bytes;
  int key_update;
  unsigned long rekey;
  int lines;
  int timeout;
  int insecure;
  int twice;			/* Connect again and resume.  */
};

struct state
{
  int fd;
  struct opts *o;
  uint8_t *rx;
  size_t rx_len, rx_cap;
  int connected, closed, close_error, close_alert, tickets;
  gq_tls_info info;
  gq_tls_session saved;		/* Last ticket, for resumption.  */
  int have_saved;
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

  if (s->rx_len + n > s->rx_cap)
    {
      s->rx_cap = (s->rx_len + n) * 2 + 4096;
      s->rx = realloc (s->rx, s->rx_cap);
      if (s->rx == NULL)
        return 1;
    }
  memcpy (s->rx + s->rx_len, d, n);
  s->rx_len += n;
  return 0;
}

static int
xconnected (void *u, const gq_tls_info *i)
{
  struct state *s = u;

  s->connected = 1;
  s->info = *i;
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
  if (!strcmp (n, "p384mlkem1024")) return GQ_GROUP_SECP384R1_MLKEM1024;
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

/* Decode \r, \n and \\ in an argument.  */
static char *
unescape (const char *s)
{
  char *out = malloc (strlen (s) + 1), *o = out;

  for (; *s; s++)
    if (*s == '\\' && s[1] == 'r') { *o++ = '\r'; s++; }
    else if (*s == '\\' && s[1] == 'n') { *o++ = '\n'; s++; }
    else if (*s == '\\' && s[1] == '\\') { *o++ = '\\'; s++; }
    else *o++ = *s;
  *o = 0;
  return out;
}

static int
connect_to (const char *host, const char *port)
{
  struct addrinfo hints, *res, *a;
  int fd = -1;

  memset (&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_STREAM;
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

static void
alarm_handler (int sig)
{
  (void) sig;
  static const char m[] = "result=fail reason=timeout\n";

  (void) write (1, m, sizeof m - 1);
  _exit (1);
}

/* One connection, negotiating its version unless told otherwise.  */
struct conn
{
  gq_tlsauto *u;
};

#define C_START(c) gq_tlsauto_start ((c).u)
#define C_RECV(c, d, n) gq_tlsauto_receive ((c).u, d, n)
#define C_SEND(c, d, n) gq_tlsauto_send ((c).u, d, n)
#define C_CLOSE(c) gq_tlsauto_close ((c).u)

/* One connection: connect, handshake, exchange, close.  Returns 0 for
   success, 2 for a TLS failure, 1 for I/O errors.  */
static int
run_once (struct opts *o_, const gq_tls_config *cfg, const gq_tls_session *resume,
          gq_tls_session *save, int *have_save)
{
  struct opts o = *o_;
  struct state st;
  gq_tlsconn_events ev;
  struct conn c;
  uint8_t buf[16384];
  int sent_request = 0, r = 0, done = 0;

  (void) resume;
  memset (&st, 0, sizeof st);
  st.o = &o;
  st.fd = connect_to (o.host, o.port);
  if (st.fd < 0)
    {
      printf ("result=fail reason=connect\n");
      return 1;
    }
  memset (&ev, 0, sizeof ev);
  ev.user = &st;
  ev.write = xwrite;
  ev.data = xdata;
  ev.connected = xconnected;
  ev.ticket = xticket;
  ev.closed = xclosed;
  ev.rekey_records = o.rekey;
  memset (&c, 0, sizeof c);
  r = gq_tlsauto_client_new (&c.u, cfg, &ev,
                             o.tls12 ? GQ_TLSAUTO_TLS12
                             : o.tls13 ? GQ_TLSAUTO_TLS13 : 0);
  if (r != GQ_OK)
    {
      printf ("result=fail reason=new status=%d\n", r);
      return 1;
    }
  r = C_START (c);

  while (r == GQ_OK && !st.closed && !done)
    {
      ssize_t n = recv (st.fd, buf, sizeof buf, 0);

      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0)
        {
          st.closed = 1;
          if (st.close_alert == 0 && st.close_error == 0)
            st.close_alert = -1;
          break;
        }
      r = C_RECV (c, buf, (size_t) n);
      if (r != GQ_OK)
        break;

      if (st.connected && !sent_request)
        {
          sent_request = 1;
          printf ("connected suite=0x%04x group=0x%04x hrr=%d alpn=%.*s "
                  "client_auth_requested=%d client_auth_sent=%d resumed=%d\n",
                  st.info.cipher_suite, st.info.group, st.info.hello_retry,
                  (int) st.info.alpn_len, (const char *) st.info.alpn,
                  st.info.client_auth_requested, st.info.client_auth_sent,
                  st.info.resumed);
          if (o.key_update && gq_tlsauto_key_update (c.u, 1) != GQ_OK)
            break;
          if (o.lines > 0)
            {
              int k;
              char line[64];

              for (k = 0; k < o.lines; k++)
                {
                  int m = snprintf (line, sizeof line, "line-%d\n", k);

                  if (C_SEND (c, (const uint8_t *) line, (size_t) m) != GQ_OK)
                    break;
                }
            }
          else if (C_SEND (c, (const uint8_t *) o.send, strlen (o.send))
                   != GQ_OK)
            break;
        }
      if (sent_request && o.expect && st.rx_len >= o.min_bytes
          && memmem (st.rx, st.rx_len, o.expect, strlen (o.expect)))
        done = 1;
      if (sent_request && !o.expect && o.min_bytes && st.rx_len >= o.min_bytes)
        done = 1;
    }

  if (save && st.have_saved)
    {
      *save = st.saved;
      if (have_save)
        *have_save = 1;
    }
  printf ("tickets=%d\n", st.tickets);
  printf ("received=%zu\n", st.rx_len);
  if (o.out && st.rx)
    {
      FILE *f = fopen (o.out, "wb");

      if (f)
        {
          fwrite (st.rx, 1, st.rx_len, f);
          fclose (f);
        }
    }
  if (done && !st.closed)
    C_CLOSE (c);

  if (done)
    {
      printf ("version=%x\n", gq_tlsauto_version (c.u));
      printf ("result=ok\n");
      return 0;
    }
  if (st.connected && !o.expect && !o.min_bytes && o.lines == 0
      && st.close_error == 0)
    {
      printf ("version=%x\n", gq_tlsauto_version (c.u));
      printf ("result=ok\n");
      return 0;
    }
  printf ("result=fail status=%d alert=%d closed=%d\n",
          r != GQ_OK ? r : st.close_error, st.close_alert, st.closed);
  return 2;
}

int
main (int argc, char **argv)
{
  struct opts o;
  gq_tls_config cfg;
  gq_trust *trust = NULL;
  gq_privkey *key = NULL;
  gq_slice chain_slices[4], *chain = NULL, alpn[4];
  size_t chain_n = 0, i;
  int i_arg;

  memset (&o, 0, sizeof o);
  o.timeout = 20;
  o.send = "GET / HTTP/1.0\r\n\r\n";
  if (argc < 3)
    {
      fprintf (stderr, "usage: interop-client HOST PORT [options]\n");
      return 1;
    }
  o.host = argv[1];
  o.port = argv[2];
  for (i_arg = 3; i_arg < argc; i_arg++)
    {
      const char *a = argv[i_arg];
      const char *v = i_arg + 1 < argc ? argv[i_arg + 1] : NULL;

#define OPT(name) (!strcmp (a, name) && v && (i_arg++, 1))
      if (OPT ("--sni")) o.sni = v;
      else if (OPT ("--ca")) o.ca = v;
      else if (OPT ("--cert")) o.cert = v;
      else if (OPT ("--key")) o.key = v;
      else if (OPT ("--alpn") && o.n_alpn < 4) o.alpn[o.n_alpn++] = v;
      else if (OPT ("--groups"))
        {
          char *list = strdup (v), *tok, *save = NULL;

          for (tok = strtok_r (list, ",", &save); tok && o.n_groups < 8;
               tok = strtok_r (NULL, ",", &save))
            o.groups[o.n_groups++] = group_code (tok);
        }
      else if (OPT ("--suites"))
        {
          char *list = strdup (v), *tok, *save = NULL;

          for (tok = strtok_r (list, ",", &save); tok && o.n_suites < 8;
               tok = strtok_r (NULL, ",", &save))
            o.suites[o.n_suites++] = suite_code (tok);
        }
      else if (OPT ("--send")) o.send = unescape (v);
      else if (OPT ("--path"))
        {
          size_t n = strlen (v) + 32;
          char *req = malloc (n);

          snprintf (req, n, "GET %s HTTP/1.0\r\n\r\n", v);
          o.send = req;
        }
      else if (OPT ("--expect")) o.expect = unescape (v);
      else if (OPT ("--out")) o.out = v;
      else if (OPT ("--min-bytes")) o.min_bytes = (size_t) atol (v);
      else if (OPT ("--rekey")) o.rekey = (unsigned long) atol (v);
      else if (OPT ("--lines")) o.lines = atoi (v);
      else if (OPT ("--timeout")) o.timeout = atoi (v);
      else if (!strcmp (a, "--key-update")) o.key_update = 1;
      else if (!strcmp (a, "--twice")) o.twice = 1;
      else if (!strcmp (a, "--tls12")) o.tls12 = 1;
      else if (!strcmp (a, "--tls13")) o.tls13 = 1;
      else
        {
          fprintf (stderr, "unknown option %s\n", a);
          return 1;
        }
    }
  if (o.ca == NULL)
    {
      fprintf (stderr, "--ca is required\n");
      return 1;
    }

  signal (SIGALRM, alarm_handler);
  signal (SIGPIPE, SIG_IGN);
  alarm ((unsigned) o.timeout);

  if (gq_trust_new (&trust) != GQ_OK || gq_trust_add_pem_file (trust, o.ca))
    {
      fprintf (stderr, "cannot load CA %s\n", o.ca);
      return 1;
    }
  if (o.cert && o.key)
    {
      if (load_chain (o.cert, &chain, &chain_n) != 0
          || gq_privkey_from_pem_file (&key, o.key) != GQ_OK)
        {
          fprintf (stderr, "cannot load client certificate/key\n");
          return 1;
        }
      for (i = 0; i < chain_n && i < 4; i++)
        chain_slices[i] = chain[i];
    }

  memset (&cfg, 0, sizeof cfg);
  cfg.server_name = o.sni;
  cfg.trust = trust;
  for (i = 0; i < o.n_alpn; i++)
    {
      alpn[i].data = (const uint8_t *) o.alpn[i];
      alpn[i].len = strlen (o.alpn[i]);
    }
  cfg.alpn = alpn;
  cfg.n_alpn = o.n_alpn;
  if (o.n_groups && !o.tls12)
    {
      cfg.groups = o.groups;
      cfg.n_groups = o.n_groups;
    }
  if (o.n_suites)
    {
      cfg.suites = o.suites;
      cfg.n_suites = o.n_suites;
    }
  if (key)
    {
      cfg.client_chain = chain_slices;
      cfg.n_client_chain = chain_n < 4 ? chain_n : 4;
      cfg.client_key = key;
    }

  {
    gq_tls_session first;
    int have_first = 0, rc;

    memset (&first, 0, sizeof first);
    rc = run_once (&o, &cfg, NULL, &first, &have_first);
    if (rc != 0 || !o.twice)
      return rc;
    /* Second connection: offer the ticket from the first.  */
    if (!have_first)
      {
        printf ("result=fail reason=no-ticket\n");
        return 2;
      }
    cfg.resume = &first;
    return run_once (&o, &cfg, &first, NULL, NULL);
  }
}
