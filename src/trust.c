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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/trust.h>

#ifdef HAVE_GNUTLS

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* GnuTLS takes non-const pointers for input it never modifies.  */
static unsigned char *
unconst (const void *p)
{
  return (unsigned char *) (uintptr_t) p;
}

struct gq_trust
{
  gnutls_x509_trust_list_t list;
};

int
gq_trust_new (gq_trust **out)
{
  gq_trust *t;

  if (out == NULL)
    return GQ_ERR_INVAL;
  t = calloc (1, sizeof *t);
  if (t == NULL)
    return GQ_ERR_NOMEM;
  if (gnutls_x509_trust_list_init (&t->list, 0) < 0)
    {
      free (t);
      return GQ_ERR_NOMEM;
    }
  *out = t;
  return GQ_OK;
}

void
gq_trust_free (gq_trust *t)
{
  if (t == NULL)
    return;
  gnutls_x509_trust_list_deinit (t->list, 1);
  free (t);
}

int
gq_trust_add_system (gq_trust *t, size_t *count)
{
  int n;

  if (t == NULL)
    return GQ_ERR_INVAL;
  n = gnutls_x509_trust_list_add_system_trust (t->list, 0, 0);
  if (n < 0)
    return GQ_ERR_CERT;
  if (count)
    *count = (size_t) n;
  return GQ_OK;
}

int
gq_trust_add_pem_file (gq_trust *t, const char *path)
{
  if (t == NULL || path == NULL)
    return GQ_ERR_INVAL;
  return gnutls_x509_trust_list_add_trust_file (t->list, path, NULL,
                                                GNUTLS_X509_FMT_PEM, 0, 0)
    < 0 ? GQ_ERR_CERT : GQ_OK;
}

int
gq_trust_add_pem (gq_trust *t, const void *pem, size_t len)
{
  gnutls_datum_t d;

  if (t == NULL || pem == NULL || len > (unsigned) -1)
    return GQ_ERR_INVAL;
  d.data = unconst (pem);
  d.size = (unsigned) len;
  return gnutls_x509_trust_list_add_trust_mem (t->list, &d, NULL,
                                               GNUTLS_X509_FMT_PEM, 0, 0)
    < 0 ? GQ_ERR_CERT : GQ_OK;
}

/* Map GnuTLS verification status bits to our reasons, most specific
   first.  */
static enum gq_cert_error
map_status (unsigned int st)
{
  if (st & GNUTLS_CERT_REVOKED)
    return GQ_CERT_REVOKED;
  if (st & (GNUTLS_CERT_EXPIRED | GNUTLS_CERT_NOT_ACTIVATED))
    return GQ_CERT_EXPIRED;
  if (st & GNUTLS_CERT_UNEXPECTED_OWNER)
    return GQ_CERT_HOSTNAME;
  if (st & GNUTLS_CERT_INSECURE_ALGORITHM)
    return GQ_CERT_WEAK_ALGORITHM;
  if (st & (GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_SIGNER_NOT_CA))
    return GQ_CERT_UNTRUSTED;
  return GQ_CERT_OTHER;
}

int
gq_trust_verify_chain_for (const gq_trust *t, const gq_slice *chain, size_t n,
                           const char *hostname, enum gq_cert_purpose purpose,
                           enum gq_cert_error *why)
{
  gnutls_x509_crt_t *crts = NULL;
  gnutls_typed_vdata_st vdata[2];
  unsigned nv = 0, status = 0, i, imported = 0;
  int r = GQ_ERR_CERT;
  enum gq_cert_error reason = GQ_CERT_OTHER;

  if (why)
    *why = GQ_CERT_OTHER;
  if (t == NULL || chain == NULL || n == 0 || n > 32)
    return GQ_ERR_INVAL;

  crts = calloc (n, sizeof *crts);
  if (crts == NULL)
    return GQ_ERR_NOMEM;

  for (i = 0; i < n; i++)
    {
      gnutls_datum_t d;

      if (chain[i].len > (unsigned) -1
          || gnutls_x509_crt_init (&crts[i]) < 0)
        {
          reason = GQ_CERT_MALFORMED;
          goto out;
        }
      imported = i + 1;
      d.data = unconst (chain[i].data);
      d.size = (unsigned) chain[i].len;
      if (gnutls_x509_crt_import (crts[i], &d, GNUTLS_X509_FMT_DER) < 0)
        {
          reason = GQ_CERT_MALFORMED;
          goto out;
        }
    }

  vdata[nv].type = GNUTLS_DT_KEY_PURPOSE_OID;
  {
    const char *oid = purpose == GQ_PURPOSE_CLIENT ? GNUTLS_KP_TLS_WWW_CLIENT
                                                   : GNUTLS_KP_TLS_WWW_SERVER;

    vdata[nv].data = unconst (oid);
    vdata[nv].size = (unsigned) strlen (oid);
  }
  nv++;
  if (hostname != NULL && purpose != GQ_PURPOSE_CLIENT)
    {
      vdata[nv].type = GNUTLS_DT_DNS_HOSTNAME;
      vdata[nv].data = unconst (hostname);
      vdata[nv].size = (unsigned) strlen (hostname);
      nv++;
    }

  /* No relaxing flags: time errors are fatal, and the MEDIUM profile
     (112-bit security) refuses SHA-1/MD5 signatures and RSA under 2048
     bits anywhere in the chain.  */
  if (gnutls_x509_trust_list_verify_crt2 (t->list, crts, (unsigned) n,
                                          vdata, nv,
                                          GNUTLS_PROFILE_TO_VFLAGS
                                          (GNUTLS_PROFILE_MEDIUM),
                                          &status, NULL) < 0)
    goto out;

  if (status == 0)
    {
      r = GQ_OK;
      reason = GQ_CERT_OK;
    }
  else
    reason = map_status (status);

out:
  for (i = 0; i < imported; i++)
    gnutls_x509_crt_deinit (crts[i]);
  free (crts);
  if (why)
    *why = reason;
  return r;
}

int
gq_trust_verify_chain (const gq_trust *t, const gq_slice *chain, size_t n,
                       const char *hostname, enum gq_cert_error *why)
{
  return gq_trust_verify_chain_for (t, chain, n, hostname, GQ_PURPOSE_SERVER,
                                    why);
}

#else /* !HAVE_GNUTLS */

int
gq_trust_verify_chain_for (const gq_trust *t, const gq_slice *chain, size_t n,
                           const char *hostname, enum gq_cert_purpose purpose,
                           enum gq_cert_error *why)
{
  (void) t; (void) chain; (void) n; (void) hostname; (void) purpose;
  if (why)
    *why = GQ_CERT_OTHER;
  return GQ_ERR_UNAVAILABLE;
}

int gq_trust_new (gq_trust **out) { (void) out; return GQ_ERR_UNAVAILABLE; }
void gq_trust_free (gq_trust *t) { (void) t; }

int
gq_trust_add_system (gq_trust *t, size_t *count)
{
  (void) t; (void) count;
  return GQ_ERR_UNAVAILABLE;
}

int
gq_trust_add_pem_file (gq_trust *t, const char *path)
{
  (void) t; (void) path;
  return GQ_ERR_UNAVAILABLE;
}

int
gq_trust_add_pem (gq_trust *t, const void *pem, size_t len)
{
  (void) t; (void) pem; (void) len;
  return GQ_ERR_UNAVAILABLE;
}

int
gq_trust_verify_chain (const gq_trust *t, const gq_slice *chain, size_t n,
                       const char *hostname, enum gq_cert_error *why)
{
  (void) t; (void) chain; (void) n; (void) hostname;
  if (why)
    *why = GQ_CERT_OTHER;
  return GQ_ERR_UNAVAILABLE;
}

#endif
