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

/* Trust anchors and certificate chain validation.

   This is the seam between GNU QUIC and X.509.  The TLS engines see only
   this interface; the implementation behind it is currently GnuTLS
   (configure --with-gnutls, the default) and may later be replaced by an
   in-tree implementation without touching any caller.

   Validation policy is strict and not configurable from here: chains
   signed with MD5 or SHA-1, or containing RSA keys under 2048 bits, are
   rejected, the leaf must be usable for the stated purpose (TLS server or
   client authentication), validity dates are always checked, and when a
   host name is supplied it must match a subjectAltName (RFC 9525).  */

#ifndef GNUQUIC_TRUST_H
#define GNUQUIC_TRUST_H

#include <stddef.h>

#include <gnuquic/frame.h>	/* gq_slice */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_trust gq_trust;

/* Why a chain was rejected.  */
enum gq_cert_error
{
  GQ_CERT_OK = 0,
  GQ_CERT_UNTRUSTED,		/* No path to a trust anchor.  */
  GQ_CERT_EXPIRED,		/* Expired or not yet valid.  */
  GQ_CERT_HOSTNAME,		/* Name does not match.  */
  GQ_CERT_WEAK_ALGORITHM,	/* MD5/SHA-1/short key.  */
  GQ_CERT_REVOKED,
  GQ_CERT_MALFORMED,		/* Could not parse a certificate.  */
  GQ_CERT_OTHER
};

/* Create an empty trust store (no anchors: everything is untrusted).
   Returns GQ_OK, GQ_ERR_NOMEM or GQ_ERR_UNAVAILABLE.  */
int gq_trust_new (gq_trust **out);

void gq_trust_free (gq_trust *trust);

/* Add the operating system's CA certificates.  On success *COUNT (if
   non-NULL) receives the number added.  */
int gq_trust_add_system (gq_trust *trust, size_t *count);

/* Add PEM-encoded CA certificates from a file or memory.  */
int gq_trust_add_pem_file (gq_trust *trust, const char *path);
int gq_trust_add_pem (gq_trust *trust, const void *pem, size_t len);

/* What a certificate is being used to prove.  */
enum gq_cert_purpose
{
  GQ_PURPOSE_SERVER = 1,	/* TLS server authentication.  */
  GQ_PURPOSE_CLIENT		/* TLS client authentication.  */
};

/* As gq_trust_verify_chain, for an explicit PURPOSE.  Host name checking
   applies to servers only; HOSTNAME is ignored for GQ_PURPOSE_CLIENT.  */
int gq_trust_verify_chain_for (const gq_trust *trust, const gq_slice *chain,
                               size_t n, const char *hostname,
                               enum gq_cert_purpose purpose,
                               enum gq_cert_error *why);

/* Validate CHAIN (N DER certificates, leaf first).  HOSTNAME may be NULL
   to skip name checking (for example for a client certificate, or where
   the caller pins by other means).  Returns GQ_OK if the chain is valid,
   GQ_ERR_CERT otherwise with *WHY (if non-NULL) set to the reason.  */
int gq_trust_verify_chain (const gq_trust *trust, const gq_slice *chain,
                           size_t n, const char *hostname,
                           enum gq_cert_error *why);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TRUST_H */
