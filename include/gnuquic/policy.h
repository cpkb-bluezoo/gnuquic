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

/* Security policy: the only protocol versions, cipher suites, key
   exchange groups and signature schemes GNU QUIC will ever negotiate.

   The lists here are closed.  Anything absent (SSL 3.0, TLS 1.0/1.1,
   CBC and other non-AEAD suites, static RSA key transport, RSA-PSS-less
   RSA signatures in TLS 1.3, SHA-1 signatures, renegotiation,
   compression, finite-field DH groups, export ciphers) is not a
   configuration option; it is not implemented.  TLS 1.2 is a narrower
   profile again: ECDHE on secp256r1 only, and no Ed25519 or ML-DSA.  The "Security policy" chapter of the manual
   gives the reasoning behind each choice.

   Values are the IANA registry code points.  */

#ifndef GNUQUIC_POLICY_H
#define GNUQUIC_POLICY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol versions.  QUIC always uses TLS 1.3.  Versions are pinned per
   endpoint rather than negotiated across generations: an endpoint
   configured for TLS 1.3 never falls back to 1.2.  */
enum gq_version
{
  GQ_TLS_1_2  = 0x0303,
  GQ_TLS_1_3  = 0x0304,
  GQ_DTLS_1_2 = 0xfefd,
  GQ_DTLS_1_3 = 0xfefc
};

/* TLS 1.3 cipher suites (RFC 8446 appendix B.4, RFC 8998 excluded).  */
enum gq_tls13_suite
{
  GQ_TLS_AES_128_GCM_SHA256       = 0x1301,
  GQ_TLS_AES_256_GCM_SHA384       = 0x1302,
  GQ_TLS_CHACHA20_POLY1305_SHA256 = 0x1303
};

/* TLS 1.2 / DTLS 1.2 suites: ECDHE with an AEAD, nothing else.
   Extended master secret (RFC 7627) and secure renegotiation
   indication (RFC 5746) are mandatory; renegotiation itself is refused.  */
enum gq_tls12_suite
{
  GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
  GQ_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
  GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   = 0xc02f,
  GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   = 0xc030,
  GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305  = 0xcca9,
  GQ_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305    = 0xcca8
};

/* Key exchange groups.  TLS 1.2 / DTLS 1.2 use secp256r1 only.  Hybrid post-quantum groups (RFC 10024 /
   draft-ietf-tls-ecdhe-mlkem) come first in the default preference.  */
enum gq_group
{
  GQ_GROUP_SECP256R1            = 0x0017,
  GQ_GROUP_SECP384R1            = 0x0018,
  GQ_GROUP_X25519               = 0x001d,
  GQ_GROUP_SECP256R1_MLKEM768   = 0x11eb,
  GQ_GROUP_X25519_MLKEM768      = 0x11ec,
  GQ_GROUP_SECP384R1_MLKEM1024  = 0x11ed
};

/* Signature schemes.  ML-DSA code points follow the IANA assignments.  */
enum gq_sigscheme
{
  GQ_SIG_ECDSA_SECP256R1_SHA256 = 0x0403,
  GQ_SIG_ECDSA_SECP384R1_SHA384 = 0x0503,
  /* TLS 1.2 / DTLS 1.2 only: RSA PKCS#1 v1.5 with SHA-2 (RFC 5246).
     The TLS 1.2 engine verifies RSA-PSS but signs RSA with these.  */
  GQ_SIG_RSA_PKCS1_SHA256       = 0x0401,
  GQ_SIG_RSA_PKCS1_SHA384       = 0x0501,
  GQ_SIG_RSA_PKCS1_SHA512       = 0x0601,
  GQ_SIG_RSA_PSS_RSAE_SHA256    = 0x0804,
  GQ_SIG_RSA_PSS_RSAE_SHA384    = 0x0805,
  GQ_SIG_RSA_PSS_RSAE_SHA512    = 0x0806,
  GQ_SIG_ED25519                = 0x0807,
  GQ_SIG_MLDSA44                = 0x0904,
  GQ_SIG_MLDSA65                = 0x0905,
  GQ_SIG_MLDSA87                = 0x0906
};

/* Membership tests: 1 if the value is permitted for VERSION, else 0.
   gq_policy_allows_group and gq_policy_default_groups and _sigschemes
   describe TLS 1.3 / DTLS 1.3; the _for variants take a version.
   Unknown code points are never permitted.  */
int gq_policy_allows_version (unsigned version);
int gq_policy_allows_suite (unsigned version, unsigned suite);
int gq_policy_allows_group (unsigned group);
int gq_policy_allows_group_for (unsigned version, unsigned group);
int gq_policy_allows_sigscheme (unsigned version, unsigned scheme);

/* Default preference-ordered lists.  Each returns a static array and
   stores its length in *N.  */
const uint16_t *gq_policy_default_suites (unsigned version, size_t *n);
const uint16_t *gq_policy_default_groups (size_t *n);
const uint16_t *gq_policy_default_groups_for (unsigned version, size_t *n);
const uint16_t *gq_policy_default_sigschemes (size_t *n);
const uint16_t *gq_policy_default_sigschemes_for (unsigned version, size_t *n);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_POLICY_H */
