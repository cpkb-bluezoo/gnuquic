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

/* DTLS 1.3 record layer codecs (RFC 9147 section 4).

   Decoding: gq_dtls_records takes one datagram and delivers each record in
   it as a typed event (gq_drec), in order, without copying: the slices in
   an event point into the datagram.  It does not decrypt; protected
   records are handed to gq_dtls_deprotect together with the keys of the
   epoch the record names.  Malformed records end the datagram (what
   follows cannot be framed), as RFC 9147 section 4.5.2 allows: invalid
   records are dropped, never answered.

   Encoding: gq_dtls_put_plain and gq_dtls_protect append one record to a
   datagram buffer each.

   Epoch state (gq_dtls_epoch) holds one direction's keys, sequence
   numbers and anti-replay window.  It derives the AEAD key, the IV and
   the record number encryption key ("sn") from a traffic secret with the
   "dtls13" label prefix.  Records carry a 16-bit sequence number in the
   unified header and its encryption follows section 4.2.3: the mask is
   the AES-ECB or ChaCha20 block of the first 16 ciphertext bytes, the
   same construction as QUIC header protection.  No connection ID is ever
   negotiated, so a record with the C bit set is not ours.  */

#ifndef GNUQUIC_DTLSREC_H
#define GNUQUIC_DTLSREC_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/crypto.h>
#include <gnuquic/frame.h>	/* gq_slice */
#include <gnuquic/tlsmsg.h>	/* gq_wbuf */

#ifdef __cplusplus
extern "C" {
#endif

/* Content types that appear in DTLS records.  */
enum gq_dtls_ct
{
  GQ_DTLS_CT_ALERT = 21,
  GQ_DTLS_CT_HANDSHAKE = 22,
  GQ_DTLS_CT_APPLICATION_DATA = 23,
  GQ_DTLS_CT_ACK = 26
};

#define GQ_DTLS_PLAIN_HEADER 13		/* DTLSPlaintext header.  */
#define GQ_DTLS_CIPHER_HEADER 5		/* Unified header as we write it.  */
#define GQ_DTLS_MAX_PLAINTEXT 16384
/* Bytes a protected record adds to its payload: header, inner content
   type, tag.  */
#define GQ_DTLS_CIPHER_OVERHEAD (GQ_DTLS_CIPHER_HEADER + 1 + GQ_AEAD_TAG_LEN)

/* AEAD confidentiality limit for AES-GCM (RFC 8446 section 5.5): after
   this many records a key update is mandatory.  Rekeying is advised at
   GQ_DTLS_REKEY_ADVISED.  */
#define GQ_DTLS_SEQ_LIMIT (UINT64_C (1) << 24)
#define GQ_DTLS_REKEY_ADVISED (UINT64_C (1) << 22)

/* ---- Decoding: datagram in, record events out ---- */

enum gq_drec_kind
{
  GQ_DREC_PLAINTEXT = 1,	/* DTLSPlaintext: epoch 0.  */
  GQ_DREC_CIPHERTEXT		/* DTLSCiphertext (unified header).  */
};

typedef struct gq_drec
{
  enum gq_drec_kind kind;
  unsigned type;		/* Plaintext only: content type.  */
  uint16_t epoch;		/* Plaintext: the epoch; ciphertext: its low
				   two bits.  */
  uint64_t seq;			/* Plaintext: sequence number; ciphertext: the
				   truncated, still encrypted value.  */
  unsigned seq_len;		/* Ciphertext: bytes of sequence number (1|2).  */
  gq_slice header;		/* Ciphertext: the unified header as sent.  */
  gq_slice body;		/* Fragment, or the encrypted record.  */
} gq_drec;

/* Return nonzero to stop.  */
typedef int (*gq_drec_cb) (void *user, const gq_drec *rec);

/* Deliver every record of DGRAM.  Returns GQ_OK (including when the tail
   was dropped as malformed) or GQ_ERR_HANDLER if CB stopped it.  */
int gq_dtls_records (const uint8_t *dgram, size_t len, gq_drec_cb cb,
                     void *user);

/* ---- Epoch keys ---- */

typedef struct gq_dtls_epoch
{
  int active;
  uint64_t epoch;
  enum gq_aead aead;
  uint8_t key[32], iv[GQ_AEAD_NONCE_LEN], sn_key[32];
  uint64_t send_seq;		/* Next to use.  */
  uint64_t recv_max;		/* Highest authenticated.  */
  uint64_t recv_bits;		/* Bit i: recv_max - i was received.  */
  int recv_any;
  uint64_t bad;			/* Records that failed authentication.  */
} gq_dtls_epoch;

/* Derive the keys of EPOCH from SECRET (hash-length for AEAD).  */
int gq_dtls_epoch_init (gq_dtls_epoch *e, uint64_t epoch, enum gq_aead aead,
                        const uint8_t *secret);
void gq_dtls_epoch_wipe (gq_dtls_epoch *e);

/* ---- Encoding: events in, datagram out ---- */

/* Append a DTLSPlaintext record (epoch 0) of TYPE with sequence number
   SEQ.  The caller owns the sequence counter of epoch 0.  */
void gq_dtls_put_plain (gq_wbuf *w, unsigned type, uint64_t seq,
                        const uint8_t *fragment, size_t len);

/* Append one protected record to OUT (CAP bytes) and advance the epoch's
   sequence number, reported in *SEQ_USED.  GQ_ERR_RANGE when the AEAD
   limit is reached.  */
int gq_dtls_protect (gq_dtls_epoch *e, unsigned type, const uint8_t *payload,
                     size_t len, uint8_t *out, size_t cap, size_t *out_len,
                     uint64_t *seq_used);

/* Decrypt and authenticate REC (a ciphertext event) with epoch E into
   OUT (at least rec->body.len bytes).  On success *TYPE is the inner
   content type, *LEN the payload length and *SEQ the full sequence number
   and the anti-replay window is updated.  GQ_ERR_ENCODING: too short or
   all padding; GQ_ERR_CRYPTO: authentication failed (counted in e->bad);
   GQ_ERR_RANGE: replayed or too old.  Neither is fatal in DTLS: the
   caller drops the record.  */
int gq_dtls_deprotect (gq_dtls_epoch *e, const gq_drec *rec, uint8_t *out,
                       size_t cap, unsigned *type, size_t *len, uint64_t *seq);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_DTLSREC_H */
