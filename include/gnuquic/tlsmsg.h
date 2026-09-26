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

/* TLS 1.3 handshake message codecs (RFC 8446 section 4).

   Reading follows the push-parser conventions of frame.h: framing
   (gq_hs_parse) consumes complete messages from a caller-owned buffer and
   leaves a partial tail; message bodies and extensions are then decoded
   into views whose variable-length members are slices into that buffer.
   Nothing is copied or allocated.  Handshake messages are bounded and
   must be hashed whole into the transcript, so unlike a data stream they
   are handled one complete message at a time; gq_hs_parse rejects a
   declared length above the caller's limit before any body arrives.

   Status conventions inside a complete message body:
     GQ_ERR_ENCODING  syntax error (decode_error alert);
     GQ_ERR_PROTOCOL  well-formed but illegal (illegal_parameter alert).

   Iterators return 1 for an item, 0 at the end, or a negative status.

   Writing uses gq_wbuf, a bounds-checked buffer with a sticky error and
   length-prefix back-patching, so message construction reads linearly
   and is checked once at the end.  */

#ifndef GNUQUIC_TLSMSG_H
#define GNUQUIC_TLSMSG_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/frame.h>	/* gq_slice */

#ifdef __cplusplus
extern "C" {
#endif

enum gq_hs_type
{
  GQ_HS_CLIENT_HELLO = 1,
  GQ_HS_SERVER_HELLO = 2,
  GQ_HS_NEW_SESSION_TICKET = 4,
  GQ_HS_END_OF_EARLY_DATA = 5,
  GQ_HS_ENCRYPTED_EXTENSIONS = 8,
  GQ_HS_CERTIFICATE = 11,
  GQ_HS_CERTIFICATE_REQUEST = 13,
  GQ_HS_CERTIFICATE_VERIFY = 15,
  GQ_HS_FINISHED = 20,
  GQ_HS_KEY_UPDATE = 24,
  GQ_HS_MESSAGE_HASH = 254
};

enum gq_ext_type
{
  GQ_EXT_SERVER_NAME = 0,
  GQ_EXT_SUPPORTED_GROUPS = 10,
  GQ_EXT_SIGNATURE_ALGORITHMS = 13,
  GQ_EXT_ALPN = 16,
  GQ_EXT_PRE_SHARED_KEY = 41,
  GQ_EXT_EARLY_DATA = 42,
  GQ_EXT_SUPPORTED_VERSIONS = 43,
  GQ_EXT_COOKIE = 44,
  GQ_EXT_PSK_KEY_EXCHANGE_MODES = 45,
  GQ_EXT_KEY_SHARE = 51,
  GQ_EXT_QUIC_TRANSPORT_PARAMETERS = 57
};

/* PSK key exchange modes (RFC 8446 section 4.2.9).  */
enum { GQ_PSK_KE = 0, GQ_PSK_DHE_KE = 1 };

/* Random value of a HelloRetryRequest: SHA-256 of "HelloRetryRequest".  */
extern const uint8_t gq_hrr_random[32];

/* ---- Framing ---- */

/* Callback for one complete handshake message.  MSG is the whole message
   including its 4-byte header (this is what the transcript hashes);
   BODY is the part after the header.  Return 0 to continue.  */
typedef int (*gq_hs_cb) (void *user, unsigned type, gq_slice msg,
                         gq_slice body);

/* Consume complete handshake messages from *BUF.  GQ_NEED_MORE leaves a
   partial message at *BUF.  A message whose declared body length exceeds
   MAX_BODY yields GQ_ERR_PROTOCOL as soon as its header is seen.
   GQ_ERR_HANDLER: CB stopped; *BUF is just past that message.  */
int gq_hs_parse (const uint8_t **buf, size_t *len, size_t max_body,
                 gq_hs_cb cb, void *user);

/* ---- Message bodies ---- */

typedef struct gq_client_hello
{
  uint16_t legacy_version;
  const uint8_t *random;	/* 32 bytes.  */
  gq_slice session_id;		/* 0 to 32 bytes.  */
  gq_slice legacy_cookie;	/* DTLS only (RFC 9147 section 5.3), else empty.  */
  gq_slice cipher_suites;	/* Raw big-endian uint16 list.  */
  gq_slice extensions;		/* Raw extension block (validated).  */
} gq_client_hello;

/* A legacy_version of 0xfefd or 0xfeff marks a DTLS ClientHello, which
   has the extra legacy_cookie vector after the session ID.  */
int gq_client_hello_parse (gq_slice body, gq_client_hello *ch);

typedef struct gq_server_hello
{
  uint16_t legacy_version;
  const uint8_t *random;	/* 32 bytes.  */
  gq_slice session_id_echo;
  uint16_t cipher_suite;
  int is_hello_retry_request;	/* Random equals gq_hrr_random.  */
  gq_slice extensions;
} gq_server_hello;

int gq_server_hello_parse (gq_slice body, gq_server_hello *sh);

/* EncryptedExtensions: just an extension block.  */
int gq_encrypted_extensions_parse (gq_slice body, gq_slice *extensions);

/* Certificate: request context, then entries walked with
   gq_cert_entry_next.  */
int gq_certificate_parse (gq_slice body, gq_slice *context,
                          gq_slice *entries);
int gq_cert_entry_next (gq_slice *entries, gq_slice *cert_der,
                        gq_slice *extensions);

int gq_certificate_request_parse (gq_slice body, gq_slice *context,
                                  gq_slice *extensions);

int gq_certificate_verify_parse (gq_slice body, uint16_t *scheme,
                                 gq_slice *signature);

/* Finished: VERIFY_DATA must be exactly HASH_LEN bytes.  */
int gq_finished_parse (gq_slice body, size_t hash_len, gq_slice *verify);

typedef struct gq_new_session_ticket
{
  uint32_t lifetime;		/* Seconds.  */
  uint32_t age_add;
  gq_slice nonce;
  gq_slice ticket;
  gq_slice extensions;
} gq_new_session_ticket;

int gq_new_session_ticket_parse (gq_slice body, gq_new_session_ticket *nst);

/* KeyUpdate: *REQUEST_UPDATE is 0 (not_requested) or 1 (requested).  */
int gq_key_update_parse (gq_slice body, int *request_update);

/* ---- Extensions ---- */

/* Check an extension block: well-formed, at most 128 extensions, and no
   type occurs twice (RFC 8446 section 4.2).  */
int gq_ext_validate (gq_slice extensions);

/* Find extension TYPE in a validated block.  Returns 1 and sets *VALUE,
   or 0.  */
int gq_ext_find (gq_slice extensions, unsigned type, gq_slice *value);

/* Iterate a validated block: 1 with (*TYPE, *VALUE), 0 at end.  Pass a
   copy of the block and call repeatedly.  */
int gq_ext_next (gq_slice *rest, unsigned *type, gq_slice *value);

/* Lists of 16-bit values with a 1- or 2-byte length prefix
   (supported_versions, supported_groups, signature_algorithms): parse the
   prefix and return the raw list; then index it.  */
int gq_list_u16 (gq_slice value, unsigned prefix_bytes, gq_slice *list);
size_t gq_u16_count (gq_slice list);
unsigned gq_u16_at (gq_slice list, size_t i);
int gq_u16_contains (gq_slice list, unsigned v);

/* A single uint16 (server supported_versions, HRR key_share, selected
   PSK identity).  */
int gq_ext_u16 (gq_slice value, uint16_t *v);

/* psk_key_exchange_modes: list of uint8.  */
int gq_ext_psk_modes (gq_slice value, gq_slice *modes);

/* server_name: first host_name, checked to be 1-255 printable ASCII.  */
int gq_ext_server_name (gq_slice value, gq_slice *host);

/* ALPN: parse the outer list, then iterate protocol names.  */
int gq_ext_alpn (gq_slice value, gq_slice *protocols);
int gq_alpn_next (gq_slice *protocols, gq_slice *name);

/* key_share.  Client: a list of entries.  Server: one entry.  */
int gq_ext_key_share_client (gq_slice value, gq_slice *entries);
int gq_key_share_next (gq_slice *entries, uint16_t *group, gq_slice *kx);
int gq_ext_key_share_server (gq_slice value, uint16_t *group, gq_slice *kx);

/* pre_shared_key in a ClientHello.  BINDERS_START is the address of the
   binders vector's 2-byte length prefix, so the truncated ClientHello for
   binder computation is the message from its start up to that address.  */
int gq_ext_psk_client (gq_slice value, gq_slice *identities,
                       gq_slice *binders, const uint8_t **binders_start);
int gq_psk_identity_next (gq_slice *identities, gq_slice *identity,
                          uint32_t *obfuscated_age);
int gq_psk_binder_next (gq_slice *binders, gq_slice *binder);

int gq_ext_cookie (gq_slice value, gq_slice *cookie);
int gq_ext_early_data_nst (gq_slice value, uint32_t *max_early_data);

/* ---- Writing ---- */

#define GQ_WBUF_DEPTH 8

typedef struct gq_wbuf
{
  uint8_t *p;
  size_t cap;
  size_t len;
  int err;			/* Sticky: first error, or GQ_OK.  */
  size_t mark[GQ_WBUF_DEPTH];	/* Offsets of open length prefixes.  */
  unsigned char width[GQ_WBUF_DEPTH];
  int depth;
} gq_wbuf;

void gq_wbuf_init (gq_wbuf *w, uint8_t *buf, size_t cap);
void gq_wbuf_u8 (gq_wbuf *w, unsigned v);
void gq_wbuf_u16 (gq_wbuf *w, unsigned v);
void gq_wbuf_u24 (gq_wbuf *w, unsigned long v);
void gq_wbuf_u32 (gq_wbuf *w, uint32_t v);
void gq_wbuf_bytes (gq_wbuf *w, const void *src, size_t n);
void gq_wbuf_slice (gq_wbuf *w, gq_slice s);

/* Open a length-prefixed vector whose prefix is WIDTH (1, 2 or 3) bytes,
   and close it, patching the length.  A vector too long for its prefix
   sets GQ_ERR_RANGE.  */
void gq_wbuf_open (gq_wbuf *w, unsigned width);
void gq_wbuf_close (gq_wbuf *w);

/* Start an extension (type, 2-byte length) and finish it with
   gq_wbuf_close.  */
void gq_wbuf_ext_open (gq_wbuf *w, unsigned type);

/* Start a handshake message (type, 3-byte length) and finish it with
   gq_wbuf_close.  */
void gq_wbuf_hs_open (gq_wbuf *w, unsigned type);

/* GQ_OK, or the first error (buffer too small, vector too long, unbalanced
   open/close).  */
int gq_wbuf_status (const gq_wbuf *w);

typedef struct gq_ext
{
  uint16_t type;
  gq_slice value;
} gq_ext;

typedef struct gq_sh_params
{
  const uint8_t *random;	/* 32 bytes; ignored for a HelloRetryRequest.  */
  gq_slice session_id_echo;
  uint16_t cipher_suite;
  int hello_retry_request;
  uint16_t group;		/* 0: no key_share extension.  */
  gq_slice key_exchange;	/* Empty for a HelloRetryRequest.  */
  gq_slice cookie;		/* HelloRetryRequest only, may be empty.  */
  int psk_selected;
  uint16_t psk_identity;
  int dtls;			/* DTLS 1.3: legacy_version 0xfefd and
				   supported_versions 0xfefc.  */
} gq_sh_params;

/* Each builder appends one complete handshake message.  */
void gq_build_server_hello (gq_wbuf *w, const gq_sh_params *p);
void gq_build_encrypted_extensions (gq_wbuf *w, const gq_ext *exts, size_t n);
void gq_build_certificate (gq_wbuf *w, gq_slice context,
                           const gq_slice *certs, size_t n);
void gq_build_certificate_verify (gq_wbuf *w, uint16_t scheme, gq_slice sig);
void gq_build_finished (gq_wbuf *w, gq_slice verify);
void gq_build_new_session_ticket (gq_wbuf *w, uint32_t lifetime,
                                  uint32_t age_add, gq_slice nonce,
                                  gq_slice ticket, const gq_ext *exts,
                                  size_t n);
void gq_build_key_update (gq_wbuf *w, int request_update);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TLSMSG_H */
