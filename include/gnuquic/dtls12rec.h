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

/* DTLS 1.2 record layer codecs (RFC 6347 section 4.1, RFC 5288, RFC 7905).

   Every record has a cleartext 13-byte header: content type, version
   (0xfefd), a 16-bit epoch, a 48-bit sequence number and the length.
   Epoch 0 records are plaintext; after the ChangeCipherSpec, epoch 1
   records are protected with an AEAD only (no CBC, as in TLS 1.2).  The
   additional data and the ChaCha20-Poly1305 nonce use the 64-bit
   epoch || sequence number; an AES-GCM record carries an 8-byte explicit
   nonce chosen by the sender, which the receiver must take from the wire
   (RFC 5288 section 3), and we send epoch || sequence number.

   Same shape as dtlsrec.h: gq_dtls12_records decodes one datagram into
   record events (slices into the datagram, nothing copied), and
   gq_dtls12_put_plain / gq_dtls12_protect append one record to a datagram.
   A record with a bad version or a malformed length ends the walk of its
   datagram (RFC 6347 section 4.1.2.7: invalid records are dropped).

   gq_dtls12_epoch holds a direction's keys, sequence counter and the
   64-record anti-replay window.  Epoch 0 uses the same structure, with no
   keys, to number and check plaintext records.  AES-GCM stops at
   GQ_DTLS12_SEQ_LIMIT records: DTLS 1.2 cannot rekey.  */

#ifndef GNUQUIC_DTLS12REC_H
#define GNUQUIC_DTLS12REC_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/crypto.h>
#include <gnuquic/frame.h>	/* gq_slice */
#include <gnuquic/tlsmsg.h>	/* gq_wbuf */

#ifdef __cplusplus
extern "C" {
#endif

enum gq_dtls12_ct
{
  GQ_D12_CT_CHANGE_CIPHER_SPEC = 20,
  GQ_D12_CT_ALERT = 21,
  GQ_D12_CT_HANDSHAKE = 22,
  GQ_D12_CT_APPLICATION_DATA = 23
};

#define GQ_DTLS12_HEADER 13
#define GQ_DTLS12_MAX_PLAINTEXT 16384
/* Bytes a protected record adds to its payload: header, explicit nonce,
   tag (for ChaCha20-Poly1305 the nonce is absent: this is an upper
   bound).  */
#define GQ_DTLS12_CIPHER_OVERHEAD (GQ_DTLS12_HEADER + 8 + GQ_AEAD_TAG_LEN)
#define GQ_DTLS12_SEQ_LIMIT (UINT64_C (1) << 24)

typedef struct gq_d12rec
{
  unsigned type;
  uint16_t epoch;
  uint64_t seq;
  gq_slice header;		/* The 13 bytes as sent.  */
  gq_slice body;		/* Fragment, or explicit nonce + ciphertext.  */
} gq_d12rec;

/* Return nonzero to stop.  */
typedef int (*gq_d12rec_cb) (void *user, const gq_d12rec *rec);

/* Deliver every record of DGRAM, in order.  Returns GQ_OK (also when a
   malformed tail was dropped) or GQ_ERR_HANDLER.  */
int gq_dtls12_records (const uint8_t *dgram, size_t len, gq_d12rec_cb cb,
                       void *user);

typedef struct gq_dtls12_epoch
{
  int active;			/* Keys installed (epoch 0 never is).  */
  uint16_t epoch;
  enum gq_aead aead;
  uint8_t key[32], iv[GQ_AEAD_NONCE_LEN];
  size_t iv_len;		/* 4 for AES-GCM, 12 for ChaCha20.  */
  uint64_t send_seq;
  uint64_t recv_max, recv_bits;
  int recv_any;
  uint64_t bad;
} gq_dtls12_epoch;

/* An epoch without keys, for plaintext records.  */
void gq_dtls12_epoch_plain (gq_dtls12_epoch *e);
int gq_dtls12_epoch_init (gq_dtls12_epoch *e, uint16_t epoch,
                          enum gq_aead aead, const uint8_t *key,
                          size_t key_len, const uint8_t *iv, size_t iv_len);
void gq_dtls12_epoch_wipe (gq_dtls12_epoch *e);

/* Anti-replay: 1 if SEQ has not been seen and is not too old.  Update only
   after the record authenticated (or, for plaintext, after use).  */
int gq_dtls12_replay_ok (const gq_dtls12_epoch *e, uint64_t seq);
void gq_dtls12_replay_update (gq_dtls12_epoch *e, uint64_t seq);

/* Append a plaintext record of the epoch (which must have no keys) and
   advance its counter.  */
void gq_dtls12_put_plain (gq_wbuf *w, gq_dtls12_epoch *e, unsigned type,
                          const uint8_t *fragment, size_t len);

/* Append a protected record; *SEQ_USED is its sequence number.
   GQ_ERR_RANGE at the AEAD limit.  */
int gq_dtls12_protect (gq_dtls12_epoch *e, unsigned type,
                       const uint8_t *payload, size_t len, uint8_t *out,
                       size_t cap, size_t *out_len);

/* Decrypt and authenticate REC into OUT (at least rec->body.len bytes);
   *LEN is the plaintext length.  The replay window is checked and, on
   success, updated.  GQ_ERR_ENCODING: too short; GQ_ERR_CRYPTO: bad tag
   (counted in e->bad); GQ_ERR_RANGE: replayed or too old.  None is fatal
   in DTLS: the caller drops the record.  */
int gq_dtls12_deprotect (gq_dtls12_epoch *e, const gq_d12rec *rec,
                         uint8_t *out, size_t cap, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_DTLS12REC_H */
