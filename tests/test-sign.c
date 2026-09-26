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

#include <unistd.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/sign.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  gq_privkey *k;

  CHECK_EQ (gq_privkey_from_pem (&k, "x", 1), GQ_ERR_UNAVAILABLE);
  TST_DONE ();
}

#else

#include "tst-x509.h"

static const unsigned all_schemes[] = {
  GQ_SIG_ECDSA_SECP256R1_SHA256, GQ_SIG_ECDSA_SECP384R1_SHA384,
  GQ_SIG_RSA_PSS_RSAE_SHA256, GQ_SIG_RSA_PSS_RSAE_SHA384,
  GQ_SIG_RSA_PSS_RSAE_SHA512, GQ_SIG_ED25519,
  GQ_SIG_RSA_PKCS1_SHA256, GQ_SIG_RSA_PKCS1_SHA384, GQ_SIG_RSA_PKCS1_SHA512
};

static const char message[] = "TLS 1.3, server CertificateVerify";

/* Load KIND's key and certificate through our own API.  */
static void
load (enum tst_key kind, struct tst_cert *c, gq_privkey **priv,
      gq_pubkey **pub)
{
  gnutls_datum_t pem, der;
  int r = tst_make_cert (c, kind, "example.test", "example.test", NULL,
                         -3600, 86400, GNUTLS_DIG_SHA256);

  *priv = NULL;
  *pub = NULL;
  CHECK_EQ (r, 0);
  if (r != 0)
    return;
  CHECK_EQ (gnutls_x509_privkey_export2_pkcs8 (c->key, GNUTLS_X509_FMT_PEM, NULL,
                                            GNUTLS_PKCS_PLAIN, &pem), 0);
  CHECK_EQ (gnutls_x509_crt_export2 (c->crt, GNUTLS_X509_FMT_DER, &der), 0);
  CHECK_EQ (gq_privkey_from_pem (priv, pem.data, pem.size), GQ_OK);
  CHECK_EQ (gq_pubkey_from_cert (pub, der.data, der.size), GQ_OK);
  gnutls_free (pem.data);
  gnutls_free (der.data);
}

static void
test_key (enum tst_key kind, const unsigned *fit, size_t nfit)
{
  struct tst_cert c;
  gq_privkey *priv;
  gq_pubkey *pub;
  uint8_t sig[GQ_SIGNATURE_MAX], bad[GQ_SIGNATURE_MAX];
  size_t n, i, j;

  load (kind, &c, &priv, &pub);
  if (priv == NULL || pub == NULL)
    return;

  for (j = 0; j < sizeof all_schemes / sizeof all_schemes[0]; j++)
    {
      unsigned s = all_schemes[j];
      int fits = 0;

      for (i = 0; i < nfit; i++)
        fits |= fit[i] == s;
      CHECK_EQ (gq_privkey_supports (priv, s), fits);

      if (!fits)
        {
          /* A scheme that does not fit the key is refused on both sides.  */
          CHECK_EQ (gq_privkey_sign (priv, s, message, sizeof message, sig,
                                     sizeof sig, &n), GQ_ERR_CRYPTO);
          CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message, sig, 64),
                    GQ_ERR_CRYPTO);
          continue;
        }

      CHECK_EQ (gq_privkey_sign (priv, s, message, sizeof message, sig,
                                 sizeof sig, &n), GQ_OK);
      CHECK (n > 0 && n <= GQ_SIGNATURE_MAX);
      CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message, sig, n),
                GQ_OK);

      /* Any change to message or signature, or truncation, is refused.  */
      CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message - 1, sig, n),
                GQ_ERR_CRYPTO);
      memcpy (bad, sig, n);
      bad[n / 2] ^= 1;
      CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message, bad, n),
                GQ_ERR_CRYPTO);
      CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message, sig, n - 1),
                GQ_ERR_CRYPTO);

      /* Output buffer too small.  */
      CHECK_EQ (gq_privkey_sign (priv, s, message, sizeof message, sig, 8, &n),
                GQ_ERR_BUFSIZE);
    }

  /* A signature made under one RSA-PSS hash does not verify as another.  */
  if (kind == TST_RSA2048)
    {
      CHECK_EQ (gq_privkey_sign (priv, GQ_SIG_RSA_PKCS1_SHA256, message,
                                 sizeof message, sig, sizeof sig, &n), GQ_OK);
      CHECK_EQ (gq_pubkey_verify (pub, GQ_SIG_RSA_PKCS1_SHA384, message,
                                  sizeof message, sig, n), GQ_ERR_CRYPTO);
      CHECK_EQ (gq_privkey_sign (priv, GQ_SIG_RSA_PSS_RSAE_SHA256, message,
                                 sizeof message, sig, sizeof sig, &n), GQ_OK);
      CHECK_EQ (gq_pubkey_verify (pub, GQ_SIG_RSA_PSS_RSAE_SHA384, message,
                                  sizeof message, sig, n), GQ_ERR_CRYPTO);
    }

  gq_privkey_free (priv);
  gq_pubkey_free (pub);
  tst_free_cert (&c);
}

static void
test_policy_and_errors (void)
{
  struct tst_cert c;
  gq_privkey *priv, *k;
  gq_pubkey *pub, *p;
  uint8_t sig[GQ_SIGNATURE_MAX];
  size_t n;

  load (TST_ECDSA256, &c, &priv, &pub);
  if (priv == NULL || pub == NULL)
    return;

  /* Schemes outside the policy.  */
  CHECK_EQ (gq_privkey_sign (priv, 0x0201, message, 4, sig, sizeof sig, &n),
            GQ_ERR_UNSUPPORTED);		/* RSA PKCS#1 SHA-1 */
  CHECK_EQ (gq_privkey_sign (priv, 0x0203, message, 4, sig, sizeof sig, &n),
            GQ_ERR_UNSUPPORTED);		/* ECDSA SHA-1 */
  CHECK_EQ (gq_pubkey_verify (pub, 0x0201, message, 4, sig, 64),
            GQ_ERR_UNSUPPORTED);
  CHECK (!gq_privkey_supports (priv, 0x0203));

  /* An ML-DSA scheme cannot be used with a classical key.  */
  CHECK_EQ (gq_privkey_sign (priv, GQ_SIG_MLDSA65, message, 4, sig,
                             sizeof sig, &n), GQ_ERR_CRYPTO);

  /* Garbage input.  */
  CHECK_EQ (gq_privkey_from_pem (&k, "not a key", 9), GQ_ERR_CERT);
  CHECK_EQ (gq_pubkey_from_cert (&p, (const uint8_t *) "junk", 4),
            GQ_ERR_CERT);
  CHECK_EQ (gq_privkey_from_pem_file (&k, "/nonexistent/key.pem"),
            GQ_ERR_INVAL);

  /* Load from a file.  */
  {
    char path[] = "/tmp/gq-key-XXXXXX";
    int fd = mkstemp (path);
    gnutls_datum_t pem;

    CHECK (fd >= 0);
    if (fd >= 0)
      {
        CHECK_EQ (gnutls_x509_privkey_export2_pkcs8 (c.key, GNUTLS_X509_FMT_PEM,
                                                        NULL, GNUTLS_PKCS_PLAIN,
                                                        &pem), 0);
        CHECK_EQ ((size_t) write (fd, pem.data, pem.size), (size_t) pem.size);
        close (fd);
        CHECK_EQ (gq_privkey_from_pem_file (&k, path), GQ_OK);
        CHECK (gq_privkey_supports (k, GQ_SIG_ECDSA_SECP256R1_SHA256));
        gq_privkey_free (k);
        gnutls_free (pem.data);
        unlink (path);
      }
  }

  gq_privkey_free (priv);
  gq_pubkey_free (pub);
  tst_free_cert (&c);
}

static void
test_weak_rsa (void)
{
  struct tst_cert c;
  gnutls_datum_t pem, der;
  gq_privkey *k;
  gq_pubkey *p;

  if (tst_make_cert (&c, TST_RSA1024, "example.test", "example.test", NULL,
                     -3600, 86400, GNUTLS_DIG_SHA256) != 0)
    {
      fprintf (stderr, "note: cannot generate RSA-1024 here; skipped\n");
      return;
    }
  CHECK_EQ (gnutls_x509_privkey_export2_pkcs8 (c.key, GNUTLS_X509_FMT_PEM, NULL,
                                            GNUTLS_PKCS_PLAIN, &pem), 0);
  CHECK_EQ (gnutls_x509_crt_export2 (c.crt, GNUTLS_X509_FMT_DER, &der), 0);
  CHECK_EQ (gq_privkey_from_pem (&k, pem.data, pem.size), GQ_ERR_CERT);
  CHECK_EQ (gq_pubkey_from_cert (&p, der.data, der.size), GQ_ERR_CERT);
  gnutls_free (pem.data);
  gnutls_free (der.data);
  tst_free_cert (&c);
}

int
main (void)
{
  static const unsigned p256[] = { GQ_SIG_ECDSA_SECP256R1_SHA256 };
  static const unsigned p384[] = { GQ_SIG_ECDSA_SECP384R1_SHA384 };
  static const unsigned ed[] = { GQ_SIG_ED25519 };
  static const unsigned rsa[] = { GQ_SIG_RSA_PSS_RSAE_SHA256,
                                  GQ_SIG_RSA_PSS_RSAE_SHA384,
                                  GQ_SIG_RSA_PSS_RSAE_SHA512,
                                  GQ_SIG_RSA_PKCS1_SHA256,
                                  GQ_SIG_RSA_PKCS1_SHA384,
                                  GQ_SIG_RSA_PKCS1_SHA512 };

  test_key (TST_ECDSA256, p256, 1);
  test_key (TST_ECDSA384, p384, 1);
  test_key (TST_ED25519, ed, 1);
  test_key (TST_RSA2048, rsa, 6);
  test_policy_and_errors ();
  test_weak_rsa ();
  TST_DONE ();
}

#endif
