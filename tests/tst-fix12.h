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

/* Certificate fixtures for the TLS 1.2 tests: one CA that signs an ECDSA
   and an RSA server identity and client identities, all generated at run
   time so nothing expires.  Needs GnuTLS.  */

#ifndef GQ_TST_FIX12_H
#define GQ_TST_FIX12_H

#include <gnuquic/sign.h>
#include <gnuquic/trust.h>
#include <gnuquic/tls.h>

#include "tst-x509.h"

struct ident
{
  struct tst_cert c;
  gq_privkey *key;
  uint8_t der[4096];
  size_t der_len;
  gq_slice chain[1];
};

static struct tst_cert fx_ca;
static gq_trust *fx_trust;
static struct ident fx_ec, fx_ec384, fx_rsa, fx_cli_ec, fx_cli_rsa;

static void
make_ident (struct ident *id, enum tst_key kind, const char *cn,
            const char *san, const char *eku)
{
  gnutls_datum_t pem, d;

  CHECK_EQ (tst_make_cert_eku (&id->c, kind, cn, san, &fx_ca, -3600, 86400,
                               GNUTLS_DIG_SHA256, eku), 0);
  gnutls_x509_crt_export2 (id->c.crt, GNUTLS_X509_FMT_DER, &d);
  id->der_len = d.size;
  memcpy (id->der, d.data, d.size);
  gnutls_free (d.data);
  gnutls_x509_privkey_export2_pkcs8 (id->c.key, GNUTLS_X509_FMT_PEM, NULL,
                                     GNUTLS_PKCS_PLAIN, &pem);
  CHECK_EQ (gq_privkey_from_pem (&id->key, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
  id->chain[0].data = id->der;
  id->chain[0].len = id->der_len;
}

static void
fx_setup (void)
{
  gnutls_datum_t pem;

  CHECK_EQ (tst_make_cert (&fx_ca, TST_ECDSA256, "Test CA", NULL, NULL, -3600,
                           86400, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (gq_trust_new (&fx_trust), GQ_OK);
  gnutls_x509_crt_export2 (fx_ca.crt, GNUTLS_X509_FMT_PEM, &pem);
  CHECK_EQ (gq_trust_add_pem (fx_trust, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
  make_ident (&fx_ec, TST_ECDSA256, "ec", "example.test",
              GNUTLS_KP_TLS_WWW_SERVER);
  make_ident (&fx_ec384, TST_ECDSA384, "ec384", "example.test",
              GNUTLS_KP_TLS_WWW_SERVER);
  make_ident (&fx_rsa, TST_RSA2048, "rsa", "example.test",
              GNUTLS_KP_TLS_WWW_SERVER);
  make_ident (&fx_cli_ec, TST_ECDSA256, "cli", "client.test",
              GNUTLS_KP_TLS_WWW_CLIENT);
  make_ident (&fx_cli_rsa, TST_RSA2048, "clirsa", "client.test",
              GNUTLS_KP_TLS_WWW_CLIENT);
}

#endif
