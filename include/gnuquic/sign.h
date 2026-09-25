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

/* Digital signatures for the TLS 1.3 CertificateVerify message.

   Like trust.h this is an interface with a GnuTLS implementation behind
   it (configure --with-gnutls).  It loads the server's private key and
   extracts public keys from peer certificates, and signs and verifies
   with the TLS signature schemes allowed by policy.h.

   The caller builds the data to be signed (the 64 spaces, context string
   and transcript hash of RFC 8446 section 4.4.3); this module signs it
   as given.  A scheme must match the key: ECDSA schemes fix the curve,
   RSA-PSS needs an RSA key of at least 2048 bits, Ed25519 needs an
   Ed25519 key, ML-DSA needs an ML-DSA key.

   ML-DSA schemes are in the policy but only usable when the backend
   library implements them; otherwise the functions return
   GQ_ERR_UNAVAILABLE for those schemes.  */

#ifndef GNUQUIC_SIGN_H
#define GNUQUIC_SIGN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gq_pubkey gq_pubkey;
typedef struct gq_privkey gq_privkey;

/* Largest signature any supported scheme produces (RSA-4096 PSS).  */
#define GQ_SIGNATURE_MAX 512

/* 1 if the backend can actually use SCHEME (ML-DSA schemes need a backend
   that implements them).  The result is computed once and cached.  */
int gq_sigscheme_available (unsigned scheme);

/* Extract the public key of a DER X.509 certificate.  RSA keys under
   2048 bits are rejected with GQ_ERR_CERT.  */
int gq_pubkey_from_cert (gq_pubkey **out, const uint8_t *der, size_t len);
void gq_pubkey_free (gq_pubkey *key);

/* Verify SIG over DATA with signature SCHEME (a gq_sigscheme code
   point).  Returns GQ_OK, GQ_ERR_CRYPTO if the signature is wrong or
   the scheme does not fit the key, GQ_ERR_UNSUPPORTED if policy does not
   allow the scheme, or GQ_ERR_UNAVAILABLE.  */
int gq_pubkey_verify (const gq_pubkey *key, unsigned scheme,
                      const void *data, size_t len,
                      const uint8_t *sig, size_t sig_len);

/* Load an unencrypted PEM private key (PKCS#8, or traditional RSA/EC
   format).  RSA keys under 2048 bits are rejected.  */
int gq_privkey_from_pem (gq_privkey **out, const void *pem, size_t len);
int gq_privkey_from_pem_file (gq_privkey **out, const char *path);
void gq_privkey_free (gq_privkey *key);

/* 1 if SCHEME is allowed by policy and fits this key.  */
int gq_privkey_supports (const gq_privkey *key, unsigned scheme);

/* Sign DATA.  SIG needs CAP bytes (GQ_SIGNATURE_MAX is always enough);
   the length is stored in *SIG_LEN.  */
int gq_privkey_sign (const gq_privkey *key, unsigned scheme,
                     const void *data, size_t len,
                     uint8_t *sig, size_t cap, size_t *sig_len);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_SIGN_H */
