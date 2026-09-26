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

/* A DTLS 1.3 (or, with --dtls12, DTLS 1.2) client and server built on
   wolfSSL: the independent peer for tests/interop-dtls.sh and
   tests/interop-dtls12.sh.  A test tool, not part of the library, and only
   built when wolfSSL with DTLS 1.3 is available.

   wolf-dtls client HOST PORT --ca FILE [--sni NAME] [--cert F --key F]
                              [--twice] [--messages N] [--group NAME]
                              [--cipher NAME]
   wolf-dtls server PORT --cert FILE --key FILE [--cookie|--stateless]
                         [--client-auth CAFILE] [--connections N]
                         [--mtu N] [--group NAME] [--cipher NAME]

   Output lines are the ones interop-dtls prints, where they apply.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#ifndef WOLFSSL_DTLS13

int
main (void)
{
  return 77;
}

#else

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>

struct opts
{
  int server;
  const char *host, *port, *ca, *cert, *key, *sni, *client_auth, *group, *cipher;
  int twice, messages, cookie, stateless, connections, timeout, ch_frag, v12;
  unsigned mtu;
};

static int
group_id (const char *n)
{
  if (!n) return 0;
  if (!strcmp (n, "x25519")) return WOLFSSL_ECC_X25519;
  if (!strcmp (n, "p256")) return WOLFSSL_ECC_SECP256R1;
  if (!strcmp (n, "p384")) return WOLFSSL_ECC_SECP384R1;
  if (!strcmp (n, "x25519mlkem768")) return WOLFSSL_X25519MLKEM768;
  if (!strcmp (n, "p256mlkem768")) return WOLFSSL_SECP256R1MLKEM768;
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
set_timeout (int fd, int secs)
{
  struct timeval tv;

  tv.tv_sec = secs;
  tv.tv_usec = 0;
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

/* Run a handshake function until it finishes, retransmitting on timeouts.  */
static int
drive (WOLFSSL *ssl, int (*fn) (WOLFSSL *))
{
  int tries = 0;

  for (;;)
    {
      int r = fn (ssl), err;

      if (r == WOLFSSL_SUCCESS)
        return 0;
      err = wolfSSL_get_error (ssl, r);
      if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
        {
          if (++tries > 40)
            return -1;
          wolfSSL_dtls_got_timeout (ssl);
          continue;
        }
      fprintf (stderr, "handshake error %d (%s)\n", err,
               wolfSSL_ERR_reason_error_string (err));
      return -1;
    }
}

static void
report (WOLFSSL *ssl)
{
  printf ("connected version=%s cipher=%s resumed=%d\n",
          wolfSSL_get_version (ssl), wolfSSL_get_cipher_name (ssl),
          wolfSSL_session_reused (ssl));
  fflush (stdout);
}

/* ------------------------------------------------------------------ */

static int
run_client (struct opts *o, WOLFSSL_SESSION **session, int have_session)
{
  WOLFSSL_CTX *ctx = wolfSSL_CTX_new (o->v12 ? wolfDTLSv1_2_client_method ()
                                         : wolfDTLSv1_3_client_method ());
  WOLFSSL *ssl;
  struct addrinfo hints, *res, *a;
  struct sockaddr_storage srv;
  socklen_t srvlen = 0;
  int fd = -1, echoed = 0, k, ok = 0;
  char m[32], buf[128];

  if (!ctx)
    return 1;
  memset (&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo (o->host, o->port, &hints, &res) != 0)
    return 1;
  for (a = res; a; a = a->ai_next)
    {
      fd = socket (a->ai_family, a->ai_socktype, a->ai_protocol);
      if (fd >= 0)
        {
          /* Unconnected: wolfSSL sends with an explicit peer address, which
             a connected UDP socket refuses on some systems.  */
          memcpy (&srv, a->ai_addr, a->ai_addrlen);
          srvlen = a->ai_addrlen;
          break;
        }
    }
  freeaddrinfo (res);
  if (fd < 0)
    return 1;
  set_timeout (fd, 1);

  if (wolfSSL_CTX_load_verify_locations (ctx, o->ca, NULL) != WOLFSSL_SUCCESS)
    return 1;
  wolfSSL_CTX_set_verify (ctx, WOLFSSL_VERIFY_PEER, NULL);
  if (o->cert && o->key
      && (wolfSSL_CTX_use_certificate_chain_file (ctx, o->cert) != WOLFSSL_SUCCESS
          || wolfSSL_CTX_use_PrivateKey_file (ctx, o->key, WOLFSSL_FILETYPE_PEM)
             != WOLFSSL_SUCCESS))
    return 1;
  if (o->cipher)
    wolfSSL_CTX_set_cipher_list (ctx, o->cipher);
  ssl = wolfSSL_new (ctx);
  wolfSSL_set_fd (ssl, fd);
  wolfSSL_dtls_set_peer (ssl, &srv, srvlen);
  if (o->mtu)
    wolfSSL_dtls_set_mtu (ssl, (unsigned short) o->mtu);
  if (o->sni)
    {
      wolfSSL_UseSNI (ssl, WOLFSSL_SNI_HOST_NAME, o->sni, (unsigned short) strlen (o->sni));
      wolfSSL_check_domain_name (ssl, o->sni);
    }
  if (o->group && group_id (o->group))
    wolfSSL_UseKeyShare (ssl, (word16) group_id (o->group));
  if (have_session && *session)
    wolfSSL_set_session (ssl, *session);

  if (drive (ssl, wolfSSL_connect) == 0)
    {
      report (ssl);
      for (k = 0; k < o->messages; k++)
        {
          int n, tries = 0;

          snprintf (m, sizeof m, "hello-%d", k);
          do
            {
              wolfSSL_write (ssl, m, (int) strlen (m));
              n = wolfSSL_read (ssl, buf, sizeof buf);
            }
          while (n <= 0 && ++tries < 5);
          if (n > 0 && (size_t) n == strlen (m) && memcmp (buf, m, (size_t) n) == 0)
            echoed++;
        }
      ok = echoed == o->messages;
      if (o->twice && session)
        *session = wolfSSL_get1_session (ssl);
      wolfSSL_shutdown (ssl);
    }
  printf ("echoed=%d\n", echoed);
  printf (ok ? "result=ok\n" : "result=fail\n");
  fflush (stdout);
  wolfSSL_free (ssl);
  wolfSSL_CTX_free (ctx);
  close (fd);
  return ok ? 0 : 2;
}

static int
run_server (struct opts *o, WOLFSSL_CTX *ctx, int fd)
{
  struct sockaddr_storage peer;
  socklen_t pl = sizeof peer;
  uint8_t buf[2048];
  WOLFSSL *ssl;
  int echoed = 0, ok = 0;
  ssize_t n;

  /* Peek to learn the peer.  */
  set_timeout (fd, 0);
  n = recvfrom (fd, buf, sizeof buf, MSG_PEEK, (struct sockaddr *) &peer, &pl);
  if (n < 0)
    return 1;
  ssl = wolfSSL_new (ctx);
  if (o->cookie || o->stateless)
    wolfSSL_send_hrr_cookie (ssl, NULL, 0);
  if (o->mtu)
    wolfSSL_dtls_set_mtu (ssl, (unsigned short) o->mtu);
  if (o->group && group_id (o->group))
    wolfSSL_UseKeyShare (ssl, (word16) group_id (o->group));
  if (o->ch_frag)
    wolfSSL_dtls13_allow_ch_frag (ssl, 1);
  if (o->stateless)
    {
      /* Unconnected socket: the stateless step reads and answers itself.  */
      wolfSSL_set_fd (ssl, fd);
      wolfSSL_dtls_set_peer (ssl, &peer, pl);
      for (;;)
        {
          int r = wolfDTLS_accept_stateless (ssl);

          if (r == WOLFSSL_SUCCESS)
            break;
          if (r != WOLFSSL_FATAL_ERROR
              || wolfSSL_get_error (ssl, r) != WOLFSSL_ERROR_WANT_READ)
            {
              fprintf (stderr, "stateless error\n");
              return 2;
            }
        }
      printf ("cookie-verified\n");
    }
  wolfSSL_set_fd (ssl, fd);
  wolfSSL_dtls_set_peer (ssl, &peer, pl);
  set_timeout (fd, 1);
  if (drive (ssl, wolfSSL_accept) == 0)
    {
      report (ssl);
      for (;;)
        {
          char b[256];
          int r = wolfSSL_read (ssl, b, sizeof b);

          if (r > 0)
            {
              wolfSSL_write (ssl, b, r);
              echoed++;
              continue;
            }
          if (wolfSSL_get_error (ssl, r) == WOLFSSL_ERROR_WANT_READ
              && echoed < 1000 && errno != 0)
            {
              /* Timeout while idle: done once we echoed something.  */
              if (echoed > 0)
                break;
              continue;
            }
          break;
        }
      ok = echoed > 0;
    }
  printf ("echoed=%d\n", echoed);
  printf (ok ? "result=ok\n" : "result=fail\n");
  fflush (stdout);
  wolfSSL_shutdown (ssl);
  wolfSSL_free (ssl);
  return ok ? 0 : 2;
}

int
main (int argc, char **argv)
{
  struct opts o;
  int ia;

  memset (&o, 0, sizeof o);
  o.messages = 3;
  o.connections = 1;
  o.timeout = 40;
  if (argc < 3)
    return 1;
  o.server = !strcmp (argv[1], "server");
  if (o.server)
    {
      o.port = argv[2];
      ia = 3;
    }
  else
    {
      o.host = argv[2];
      o.port = argv[3];
      ia = 4;
    }
  for (; ia < argc; ia++)
    {
      const char *a = argv[ia];
      const char *v = ia + 1 < argc ? argv[ia + 1] : NULL;

#define OPT(name) (!strcmp (a, name) && v && (ia++, 1))
      if (OPT ("--ca")) o.ca = v;
      else if (OPT ("--cert")) o.cert = v;
      else if (OPT ("--key")) o.key = v;
      else if (OPT ("--sni")) o.sni = v;
      else if (OPT ("--client-auth")) o.client_auth = v;
      else if (OPT ("--group")) o.group = v;
      else if (OPT ("--cipher")) o.cipher = v;
      else if (OPT ("--messages")) o.messages = atoi (v);
      else if (OPT ("--connections")) o.connections = atoi (v);
      else if (OPT ("--mtu")) o.mtu = (unsigned) atoi (v);
      else if (OPT ("--timeout")) o.timeout = atoi (v);
      else if (!strcmp (a, "--twice")) o.twice = 1;
      else if (!strcmp (a, "--cookie")) o.cookie = 1;
      else if (!strcmp (a, "--stateless")) o.stateless = 1;
      else if (!strcmp (a, "--ch-frag")) o.ch_frag = 1;
      else if (!strcmp (a, "--dtls12")) o.v12 = 1;
      else
        {
          fprintf (stderr, "unknown option %s\n", a);
          return 1;
        }
    }
  signal (SIGALRM, alarm_handler);
  signal (SIGPIPE, SIG_IGN);
  alarm ((unsigned) o.timeout);
  wolfSSL_Init ();

  if (!o.server)
    {
      WOLFSSL_SESSION *sess = NULL;
      int rc = run_client (&o, &sess, 0);

      if (rc == 0 && o.twice)
        {
          if (!sess)
            {
              printf ("result=fail reason=no-session\n");
              return 2;
            }
          rc = run_client (&o, &sess, 1);
        }
      return rc;
    }
  else
    {
      WOLFSSL_CTX *ctx = wolfSSL_CTX_new (o.v12 ? wolfDTLSv1_2_server_method ()
                                      : wolfDTLSv1_3_server_method ());
      struct sockaddr_in addr;
      int fd, one = 1, rc = 0, c;

      if (!ctx || !o.cert || !o.key
          || wolfSSL_CTX_use_certificate_chain_file (ctx, o.cert) != WOLFSSL_SUCCESS
          || wolfSSL_CTX_use_PrivateKey_file (ctx, o.key, WOLFSSL_FILETYPE_PEM)
             != WOLFSSL_SUCCESS)
        {
          fprintf (stderr, "cannot load certificate/key\n");
          return 1;
        }
      if (o.cipher)
        wolfSSL_CTX_set_cipher_list (ctx, o.cipher);
      if (o.client_auth)
        {
          wolfSSL_CTX_load_verify_locations (ctx, o.client_auth, NULL);
          wolfSSL_CTX_set_verify (ctx, WOLFSSL_VERIFY_PEER
                                       | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }
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
          int r = run_server (&o, ctx, fd);

          if (r)
            rc = r;
        }
      return rc;
    }
}

#endif
