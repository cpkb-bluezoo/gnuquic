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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/sign.h>

#ifdef HAVE_GNUTLS

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#define MIN_RSA_BITS 2048

struct gq_pubkey
{
  gnutls_pubkey_t key;
  unsigned pk;
  unsigned bits;
};

struct gq_privkey
{
  gnutls_privkey_t key;
  unsigned pk;
  unsigned bits;
};

/* Policy scheme to GnuTLS signature algorithm.  */
static gnutls_sign_algorithm_t
sign_algo (unsigned scheme)
{
  switch (scheme)
    {
    case GQ_SIG_ECDSA_SECP256R1_SHA256: return GNUTLS_SIGN_ECDSA_SECP256R1_SHA256;
    case GQ_SIG_ECDSA_SECP384R1_SHA384: return GNUTLS_SIGN_ECDSA_SECP384R1_SHA384;
    case GQ_SIG_RSA_PKCS1_SHA256:       return GNUTLS_SIGN_RSA_SHA256;
    case GQ_SIG_RSA_PKCS1_SHA384:       return GNUTLS_SIGN_RSA_SHA384;
    case GQ_SIG_RSA_PKCS1_SHA512:       return GNUTLS_SIGN_RSA_SHA512;
    case GQ_SIG_RSA_PSS_RSAE_SHA256:    return GNUTLS_SIGN_RSA_PSS_RSAE_SHA256;
    case GQ_SIG_RSA_PSS_RSAE_SHA384:    return GNUTLS_SIGN_RSA_PSS_RSAE_SHA384;
    case GQ_SIG_RSA_PSS_RSAE_SHA512:    return GNUTLS_SIGN_RSA_PSS_RSAE_SHA512;
    case GQ_SIG_ED25519:                return GNUTLS_SIGN_EDDSA_ED25519;
    case GQ_SIG_MLDSA44:                return GNUTLS_SIGN_MLDSA44;
    case GQ_SIG_MLDSA65:                return GNUTLS_SIGN_MLDSA65;
    case GQ_SIG_MLDSA87:                return GNUTLS_SIGN_MLDSA87;
    default:                            return GNUTLS_SIGN_UNKNOWN;
    }
}

/* Does a key of type PK / BITS fit SCHEME?  The ECDSA schemes bind the
   curve, so the key size must match (RFC 8446 section 4.2.3).  */
static int
key_fits (unsigned pk, unsigned bits, unsigned scheme)
{
  switch (scheme)
    {
    case GQ_SIG_ECDSA_SECP256R1_SHA256:
      return pk == GNUTLS_PK_ECDSA && bits == 256;
    case GQ_SIG_ECDSA_SECP384R1_SHA384:
      return pk == GNUTLS_PK_ECDSA && bits == 384;
    case GQ_SIG_RSA_PKCS1_SHA256:
    case GQ_SIG_RSA_PKCS1_SHA384:
    case GQ_SIG_RSA_PKCS1_SHA512:
    case GQ_SIG_RSA_PSS_RSAE_SHA256:
    case GQ_SIG_RSA_PSS_RSAE_SHA384:
    case GQ_SIG_RSA_PSS_RSAE_SHA512:
      return pk == GNUTLS_PK_RSA && bits >= MIN_RSA_BITS;
    case GQ_SIG_ED25519:
      return pk == GNUTLS_PK_EDDSA_ED25519;
    case GQ_SIG_MLDSA44:
      return pk == GNUTLS_PK_MLDSA44;
    case GQ_SIG_MLDSA65:
      return pk == GNUTLS_PK_MLDSA65;
    case GQ_SIG_MLDSA87:
      return pk == GNUTLS_PK_MLDSA87;
    default:
      return 0;
    }
}

/* A scheme some TLS generation allows (the callers, the engines, apply the
   per-version lists; this layer only refuses what no version permits).  */
static int
allowed_any (unsigned scheme)
{
  return gq_policy_allows_sigscheme (GQ_TLS_1_3, scheme)
    || gq_policy_allows_sigscheme (GQ_TLS_1_2, scheme);
}

static int
is_mldsa (unsigned scheme)
{
  return scheme >= GQ_SIG_MLDSA44 && scheme <= GQ_SIG_MLDSA87;
}

static gnutls_datum_t
datum_of (const void *p, size_t n)
{
  gnutls_datum_t d;

  d.data = (unsigned char *) (uintptr_t) p;
  d.size = (unsigned) n;
  return d;
}

int
gq_sigscheme_available (unsigned scheme)
{
  static int mldsa_probed, mldsa_ok;
  gnutls_pk_algorithm_t pk;
  gnutls_x509_privkey_t k;
  int r;

  if (!allowed_any (scheme))
    return 0;
  if (!is_mldsa (scheme))
    return 1;
  if (!mldsa_probed)
    {
      /* Ask the backend for an ML-DSA-65 key; it fails if unimplemented.  */
      pk = GNUTLS_PK_MLDSA65;
      mldsa_ok = 0;
      if (gnutls_x509_privkey_init (&k) >= 0)
        {
          r = gnutls_x509_privkey_generate (k, pk, 0, 0);
          mldsa_ok = r >= 0;
          gnutls_x509_privkey_deinit (k);
        }
      mldsa_probed = 1;
    }
  return mldsa_ok;
}

int
gq_pubkey_from_cert (gq_pubkey **out, const uint8_t *der, size_t len)
{
  gnutls_x509_crt_t crt;
  gnutls_datum_t d;
  gq_pubkey *k;
  int r = GQ_ERR_CERT;

  if (out == NULL || der == NULL || len == 0 || len > (unsigned) -1)
    return GQ_ERR_INVAL;
  k = calloc (1, sizeof *k);
  if (k == NULL)
    return GQ_ERR_NOMEM;
  d = datum_of (der, len);
  if (gnutls_x509_crt_init (&crt) < 0)
    {
      free (k);
      return GQ_ERR_NOMEM;
    }
  if (gnutls_x509_crt_import (crt, &d, GNUTLS_X509_FMT_DER) >= 0
      && gnutls_pubkey_init (&k->key) >= 0)
    {
      if (gnutls_pubkey_import_x509 (k->key, crt, 0) >= 0)
        {
          int pk = gnutls_pubkey_get_pk_algorithm (k->key, &k->bits);

          if (pk >= 0)
            {
              k->pk = (unsigned) pk;
              if (k->pk != GNUTLS_PK_RSA || k->bits >= MIN_RSA_BITS)
                r = GQ_OK;
            }
        }
      if (r != GQ_OK)
        gnutls_pubkey_deinit (k->key);
    }
  gnutls_x509_crt_deinit (crt);
  if (r != GQ_OK)
    {
      free (k);
      return r;
    }
  *out = k;
  return GQ_OK;
}

void
gq_pubkey_free (gq_pubkey *k)
{
  if (k == NULL)
    return;
  gnutls_pubkey_deinit (k->key);
  free (k);
}

int
gq_pubkey_verify (const gq_pubkey *k, unsigned scheme, const void *data,
                  size_t len, const uint8_t *sig, size_t sig_len)
{
  gnutls_datum_t d, s;
  int r;

  if (k == NULL || (data == NULL && len > 0) || sig == NULL
      || len > (unsigned) -1 || sig_len > (unsigned) -1)
    return GQ_ERR_INVAL;
  if (!allowed_any (scheme))
    return GQ_ERR_UNSUPPORTED;
  if (!key_fits (k->pk, k->bits, scheme))
    return GQ_ERR_CRYPTO;
  d = datum_of (data, len);
  s = datum_of (sig, sig_len);
  r = gnutls_pubkey_verify_data2 (k->key, sign_algo (scheme), 0, &d, &s);
  if (r >= 0)
    return GQ_OK;
  if (is_mldsa (scheme) && r == GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM)
    return GQ_ERR_UNAVAILABLE;
  return GQ_ERR_CRYPTO;
}

int
gq_privkey_from_pem (gq_privkey **out, const void *pem, size_t len)
{
  gnutls_datum_t d;
  gq_privkey *k;
  int pk;

  if (out == NULL || pem == NULL || len == 0 || len > (unsigned) -1)
    return GQ_ERR_INVAL;
  k = calloc (1, sizeof *k);
  if (k == NULL)
    return GQ_ERR_NOMEM;
  if (gnutls_privkey_init (&k->key) < 0)
    {
      free (k);
      return GQ_ERR_NOMEM;
    }
  d = datum_of (pem, len);
  if (gnutls_privkey_import_x509_raw (k->key, &d, GNUTLS_X509_FMT_PEM, NULL,
                                      0) < 0
      || (pk = gnutls_privkey_get_pk_algorithm (k->key, &k->bits)) < 0)
    {
      gnutls_privkey_deinit (k->key);
      free (k);
      return GQ_ERR_CERT;
    }
  k->pk = (unsigned) pk;
  if (k->pk == GNUTLS_PK_RSA && k->bits < MIN_RSA_BITS)
    {
      gnutls_privkey_deinit (k->key);
      free (k);
      return GQ_ERR_CERT;
    }
  *out = k;
  return GQ_OK;
}

int
gq_privkey_from_pem_file (gq_privkey **out, const char *path)
{
  FILE *f;
  char *buf = NULL;
  size_t cap = 0, n = 0, got;
  int r;

  if (path == NULL)
    return GQ_ERR_INVAL;
  f = fopen (path, "rb");
  if (f == NULL)
    return GQ_ERR_INVAL;
  for (;;)
    {
      char *nb;

      if (n == cap)
        {
          cap = cap ? cap * 2 : 4096;
          if (cap > (1u << 20))	/* A key file this large is not a key.  */
            {
              free (buf);
              fclose (f);
              return GQ_ERR_RANGE;
            }
          nb = realloc (buf, cap);
          if (nb == NULL)
            {
              free (buf);
              fclose (f);
              return GQ_ERR_NOMEM;
            }
          buf = nb;
        }
      got = fread (buf + n, 1, cap - n, f);
      if (got == 0)
        break;
      n += got;
    }
  fclose (f);
  r = n ? gq_privkey_from_pem (out, buf, n) : GQ_ERR_INVAL;
  if (buf)
    {
      memset (buf, 0, cap);	/* Key material.  */
      free (buf);
    }
  return r;
}

void
gq_privkey_free (gq_privkey *k)
{
  if (k == NULL)
    return;
  gnutls_privkey_deinit (k->key);
  free (k);
}

int
gq_privkey_supports (const gq_privkey *k, unsigned scheme)
{
  return k != NULL && allowed_any (scheme)
    && key_fits (k->pk, k->bits, scheme);
}

int
gq_privkey_sign (const gq_privkey *k, unsigned scheme, const void *data,
                 size_t len, uint8_t *sig, size_t cap, size_t *sig_len)
{
  gnutls_datum_t d, s = { NULL, 0 };
  int r;

  if (k == NULL || (data == NULL && len > 0) || sig == NULL
      || sig_len == NULL || len > (unsigned) -1)
    return GQ_ERR_INVAL;
  if (!allowed_any (scheme))
    return GQ_ERR_UNSUPPORTED;
  if (!key_fits (k->pk, k->bits, scheme))
    return GQ_ERR_CRYPTO;
  d = datum_of (data, len);
  r = gnutls_privkey_sign_data2 (k->key, sign_algo (scheme), 0, &d, &s);
  if (r < 0)
    return is_mldsa (scheme) ? GQ_ERR_UNAVAILABLE : GQ_ERR_CRYPTO;
  if (s.size > cap)
    r = GQ_ERR_BUFSIZE;
  else
    {
      memcpy (sig, s.data, s.size);
      *sig_len = s.size;
      r = GQ_OK;
    }
  gnutls_free (s.data);
  return r;
}

#else /* !HAVE_GNUTLS */

int gq_sigscheme_available (unsigned s)
{ return !(s >= GQ_SIG_MLDSA44 && s <= GQ_SIG_MLDSA87) && 0; }
int gq_pubkey_from_cert (gq_pubkey **o, const uint8_t *d, size_t n)
{ (void) o; (void) d; (void) n; return GQ_ERR_UNAVAILABLE; }
void gq_pubkey_free (gq_pubkey *k) { (void) k; }
int gq_pubkey_verify (const gq_pubkey *k, unsigned s, const void *d, size_t n,
                      const uint8_t *sig, size_t sl)
{ (void) k; (void) s; (void) d; (void) n; (void) sig; (void) sl;
  return GQ_ERR_UNAVAILABLE; }
int gq_privkey_from_pem (gq_privkey **o, const void *p, size_t n)
{ (void) o; (void) p; (void) n; return GQ_ERR_UNAVAILABLE; }
int gq_privkey_from_pem_file (gq_privkey **o, const char *p)
{ (void) o; (void) p; return GQ_ERR_UNAVAILABLE; }
void gq_privkey_free (gq_privkey *k) { (void) k; }
int gq_privkey_supports (const gq_privkey *k, unsigned s)
{ (void) k; (void) s; return 0; }
int gq_privkey_sign (const gq_privkey *k, unsigned s, const void *d, size_t n,
                     uint8_t *sig, size_t c, size_t *sl)
{ (void) k; (void) s; (void) d; (void) n; (void) sig; (void) c; (void) sl;
  return GQ_ERR_UNAVAILABLE; }

#endif
