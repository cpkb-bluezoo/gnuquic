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

#include <time.h>

#include <gnuquic/status.h>
#include <gnuquic/trust.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  gq_trust *t;

  CHECK_EQ (gq_trust_new (&t), GQ_ERR_UNAVAILABLE);
  TST_DONE ();
}

#else

#include "tst-x509.h"

static int
make_cert (struct tst_cert *out, const char *cn, const char *san,
           const struct tst_cert *issuer, long nb, long na,
           gnutls_digest_algorithm_t dig)
{
  return tst_make_cert (out, TST_ECDSA256, cn, san, issuer, nb, na, dig);
}

static gq_slice
der (const struct tst_cert *c, gnutls_datum_t *d)
{
  gq_slice s;

  gnutls_x509_crt_export2 (c->crt, GNUTLS_X509_FMT_DER, d);
  s.data = d->data;
  s.len = d->size;
  return s;
}

static gq_trust *
trust_for (const struct tst_cert *ca)
{
  gnutls_datum_t pem;
  gq_trust *t = NULL;

  CHECK_EQ (gq_trust_new (&t), GQ_OK);
  if (ca)
    {
      gnutls_x509_crt_export2 (ca->crt, GNUTLS_X509_FMT_PEM, &pem);
      CHECK_EQ (gq_trust_add_pem (t, pem.data, pem.size), GQ_OK);
      gnutls_free (pem.data);
    }
  return t;
}

static int
verify (gq_trust *t, const struct tst_cert *leaf, const char *host,
        enum gq_cert_error *why)
{
  gnutls_datum_t d;
  gq_slice s = der (leaf, &d);
  int r = gq_trust_verify_chain (t, &s, 1, host, why);

  gnutls_free (d.data);
  return r;
}

int
main (void)
{
  struct tst_cert ca, leaf, expired, sha1leaf;
  gq_trust *t, *empty;
  enum gq_cert_error why;
  gq_slice junk = { (const uint8_t *) "not a certificate", 17 };
  size_t count = 0;
  int r;

  CHECK_EQ (make_cert (&ca, "Test CA", NULL, NULL, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (make_cert (&leaf, "example.test", "example.test", &ca, -3600,
                       86400, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (make_cert (&expired, "example.test", "example.test", &ca, -7200,
                       -3600, GNUTLS_DIG_SHA256), 0);

  t = trust_for (&ca);
  empty = trust_for (NULL);

  CHECK_EQ (verify (t, &leaf, "example.test", &why), GQ_OK);
  CHECK_EQ (why, GQ_CERT_OK);
  CHECK_EQ (verify (t, &leaf, NULL, &why), GQ_OK);

  CHECK_EQ (verify (t, &leaf, "other.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_HOSTNAME);

  CHECK_EQ (verify (empty, &leaf, "example.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_UNTRUSTED);

  CHECK_EQ (verify (t, &expired, "example.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_EXPIRED);

  CHECK_EQ (gq_trust_verify_chain (t, &junk, 1, NULL, &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_MALFORMED);

  CHECK_EQ (gq_trust_verify_chain (t, NULL, 0, NULL, &why), GQ_ERR_INVAL);

  /* SHA-1 signatures must be refused.  Some GnuTLS builds refuse to even
     create one; then there is nothing to test.  */
  r = make_cert (&sha1leaf, "example.test", "example.test", &ca, -3600,
                 86400, GNUTLS_DIG_SHA1);
  if (r == 0)
    {
      CHECK_EQ (verify (t, &sha1leaf, "example.test", &why), GQ_ERR_CERT);
      CHECK_EQ (why, GQ_CERT_WEAK_ALGORITHM);
      tst_free_cert (&sha1leaf);
    }
  else
    fprintf (stderr, "note: cannot sign with SHA-1 here; skipped\n");

  /* RSA below 2048 bits is refused even with a modern signature hash.  */
  {
    struct tst_cert weak;

    if (tst_make_cert (&weak, TST_RSA1024, "example.test", "example.test",
                       &ca, -3600, 86400, GNUTLS_DIG_SHA256) == 0)
      {
        CHECK_EQ (verify (t, &weak, "example.test", &why), GQ_ERR_CERT);
        CHECK_EQ (why, GQ_CERT_WEAK_ALGORITHM);
        tst_free_cert (&weak);
      }
    else
      fprintf (stderr, "note: cannot generate RSA-1024 here; skipped\n");
  }

  /* The system store loads without error (contents vary by host).  */
  CHECK_EQ (gq_trust_add_system (empty, &count), GQ_OK);

  gq_trust_free (t);
  gq_trust_free (empty);
  tst_free_cert (&ca);
  tst_free_cert (&leaf);
  tst_free_cert (&expired);
  TST_DONE ();
}

#endif
