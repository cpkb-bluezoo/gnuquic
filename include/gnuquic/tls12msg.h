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

/* TLS 1.2 handshake message codecs (RFC 5246 section 7, RFC 8422,
   RFC 5077, RFC 5746, RFC 7627).

   Same conventions as tlsmsg.h, which supplies framing (gq_hs_parse), the
   extension helpers, gq_wbuf and the ClientHello, ServerHello, Finished
   and CertificateVerify body parsers, all of which have the same layout in
   TLS 1.2.  This file adds what differs: the Certificate list without
   per-entry extensions, ServerKeyExchange and ClientKeyExchange for
   ECDHE, CertificateRequest, the RFC 5077 NewSessionTicket, and builders
   for the ClientHello and ServerHello with the TLS 1.2 extensions.

   Status conventions as in tlsmsg.h: GQ_ERR_ENCODING is a syntax error
   (decode_error), GQ_ERR_PROTOCOL a well-formed but illegal value.  */

#ifndef GNUQUIC_TLS12MSG_H
#define GNUQUIC_TLS12MSG_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/frame.h>	/* gq_slice */
#include <gnuquic/tlsmsg.h>

#ifdef __cplusplus
extern "C" {
#endif

enum gq_hs12_type
{
  GQ_HS12_HELLO_REQUEST = 0,
  GQ_HS12_SERVER_KEY_EXCHANGE = 12,
  GQ_HS12_SERVER_HELLO_DONE = 14,
  GQ_HS12_CLIENT_KEY_EXCHANGE = 16
};

enum gq_ext12_type
{
  GQ_EXT12_EC_POINT_FORMATS = 11,
  GQ_EXT12_EXTENDED_MASTER_SECRET = 23,
  GQ_EXT12_SESSION_TICKET = 35,
  GQ_EXT12_SIGNATURE_ALGORITHMS_CERT = 50,
  GQ_EXT12_RENEGOTIATION_INFO = 0xff01
};

/* TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746 section 3.3).  */
#define GQ_TLS12_SCSV_RENEGOTIATION 0x00ff

/* ECCurveType named_curve and the one group used (secp256r1).  */
#define GQ_TLS12_CURVE_NAMED 3
#define GQ_TLS12_POINT_LEN 65

/* ---- Reading ---- */

/* Certificate: a 3-byte-length list of 3-byte-length DER certificates.
   Fills CHAIN (MAX entries) and *N.  More than MAX certificates is
   GQ_ERR_PROTOCOL.  An empty list is valid here (a client with no
   certificate); callers that need one check *N.  */
int gq_tls12_certificate_parse (gq_slice body, gq_slice *chain, size_t max,
                                size_t *n);

/* ServerKeyExchange for ECDHE.  PARAMS is the ServerECDHParams exactly as
   sent (what the signature covers, after the two randoms); POINT the
   encoded public key.  A curve other than named secp256r1 is
   GQ_ERR_PROTOCOL.  */
typedef struct gq_tls12_ske
{
  gq_slice params;
  gq_slice point;
  uint16_t group;		/* The named curve.  */
  uint16_t scheme;		/* SignatureAndHashAlgorithm.  */
  gq_slice signature;
} gq_tls12_ske;

int gq_tls12_ske_parse (gq_slice body, gq_tls12_ske *ske);

/* As gq_tls12_ske_parse, but also accepts secp384r1 and x25519: for a client
   whose hello offered TLS 1.3 as well (gq_tlsauto), whose supported_groups
   were the shared list and so let a TLS 1.2 server choose among them.  */
int gq_tls12_ske_parse_wide (gq_slice body, gq_tls12_ske *ske);

/* CertificateRequest.  SIGALGS is the raw list of uint16 schemes.  A
   request that names no certificate type we can satisfy is not rejected
   here; the CA list is validated for syntax only.  */
int gq_tls12_certreq_parse (gq_slice body, gq_slice *sigalgs);

/* ClientKeyExchange for ECDHE: the client's encoded public point.  */
int gq_tls12_cke_parse (gq_slice body, gq_slice *point);

/* RFC 5077 NewSessionTicket.  */
int gq_tls12_nst_parse (gq_slice body, uint32_t *lifetime, gq_slice *ticket);

/* ---- Writing ---- */

typedef struct gq_tls12_ch_params
{
  const uint8_t *random;	/* 32 bytes.  */
  gq_slice session_id;
  const uint16_t *suites;
  size_t n_suites;
  const char *server_name;	/* NULL: no SNI.  */
  const gq_slice *alpn;
  size_t n_alpn;
  const uint16_t *sigalgs;	/* signature_algorithms.  */
  size_t n_sigalgs;
  const uint16_t *cert_sigalgs;	/* signature_algorithms_cert (may be 0).  */
  size_t n_cert_sigalgs;
  int have_ticket;		/* Send a session_ticket extension...  */
  gq_slice ticket;		/* ...with this ticket (may be empty).  */
  int dtls;			/* DTLS 1.2: version 0xfefd, the cookie field.  */
  gq_slice cookie;		/* DTLS: from a HelloVerifyRequest, else empty.  */
} gq_tls12_ch_params;

/* Always sent: supported_versions {TLS 1.2}, supported_groups
   {secp256r1}, ec_point_formats {uncompressed}, extended_master_secret
   and an empty renegotiation_info.  */
void gq_tls12_build_client_hello (gq_wbuf *w, const gq_tls12_ch_params *p);

typedef struct gq_tls12_sh_params
{
  const uint8_t *random;
  gq_slice session_id;
  uint16_t cipher_suite;
  int issue_ticket;		/* Empty session_ticket extension.  */
  gq_slice alpn;		/* Empty: no ALPN extension.  */
  int dtls;			/* DTLS 1.2: version 0xfefd.  */
} gq_tls12_sh_params;

/* Always includes extended_master_secret and renegotiation_info.  */
void gq_tls12_build_server_hello (gq_wbuf *w, const gq_tls12_sh_params *p);

void gq_tls12_build_certificate (gq_wbuf *w, const gq_slice *chain, size_t n);

/* ServerECDHParams for secp256r1 with POINT (65 bytes), appended to W with
   no message framing: the bytes the signature covers.  */
void gq_tls12_put_ecdh_params (gq_wbuf *w, gq_slice point);

/* ServerKeyExchange: PARAMS as written by gq_tls12_put_ecdh_params, then
   the signature.  */
void gq_tls12_build_ske (gq_wbuf *w, gq_slice params, uint16_t scheme,
                         gq_slice signature);

/* CertificateRequest with the certificate types rsa_sign and ecdsa_sign,
   the given signature schemes and no certificate authorities.  */
void gq_tls12_build_certreq (gq_wbuf *w, const uint16_t *sigalgs, size_t n);

void gq_tls12_build_server_hello_done (gq_wbuf *w);

/* DTLS 1.2 HelloVerifyRequest (RFC 6347 section 4.2.1), handshake type 3:
   the server's version (0xfefd) and a cookie of 1 to 255 bytes.  */
#define GQ_HS12_HELLO_VERIFY_REQUEST 3
int gq_tls12_hvr_parse (gq_slice body, uint16_t *version, gq_slice *cookie);
void gq_tls12_build_hvr (gq_wbuf *w, gq_slice cookie);
void gq_tls12_build_cke (gq_wbuf *w, gq_slice point);
void gq_tls12_build_nst (gq_wbuf *w, uint32_t lifetime, gq_slice ticket);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TLS12MSG_H */
