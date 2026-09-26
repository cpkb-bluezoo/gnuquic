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

/* TLS 1.2 record layer (RFC 5246 section 6, RFC 5288, RFC 7905).

   Unlike the TLS 1.3 record layer in record.h, the content type and
   version travel in the clear, ChangeCipherSpec is a real record that
   switches keys, and AES-GCM records carry an 8-byte explicit nonce.
   Only AEAD protection exists: there is no MAC-then-encrypt code path.

   AES-GCM has no in-protocol rekeying in TLS 1.2, so once a direction has
   protected GQ_REC12_SEQ_LIMIT records the layer refuses to continue
   (GQ_ERR_RANGE) and the connection must close.  ChaCha20-Poly1305 is
   limited only by the 64-bit sequence number.

   Reading is push-style like gq_record_receive: the caller keeps the
   incomplete tail.  ChangeCipherSpec records are delivered to the
   callback like any other; the caller installs the read keys from the
   callback, and the layer decrypts every later record with them.  */

#ifndef GNUQUIC_RECORD12_H
#define GNUQUIC_RECORD12_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/crypto.h>
#include <gnuquic/record.h>	/* content types, sizes */

#ifdef __cplusplus
extern "C" {
#endif

/* Largest ciphertext fragment we accept (AES-GCM: 8 + 16 bytes over the
   plaintext; RFC 5246 allows 2^14 + 2048).  */
#define GQ_REC12_MAX_CIPHERTEXT (16384 + 2048)
#define GQ_REC12_MAX_RECORD (GQ_REC_HEADER_LEN + GQ_REC12_MAX_CIPHERTEXT)
/* Worst-case bytes a plaintext record of LEN adds.  */
#define GQ_REC12_OVERHEAD (GQ_REC_HEADER_LEN + 8 + GQ_AEAD_TAG_LEN)
#define GQ_REC12_SEQ_LIMIT (UINT64_C (1) << 24)

struct gq_rec12_dir
{
  int active;
  enum gq_aead aead;
  uint8_t key[32];
  uint8_t iv[12];		/* 4 bytes for AES-GCM, 12 for ChaCha20.  */
  size_t iv_len;
  uint64_t seq;
};

typedef struct gq_record12
{
  struct gq_rec12_dir read, write;
  int first;			/* No record has been read yet.  */
  int alert;			/* Alert to send after a receive failure.  */
} gq_record12;

void gq_record12_init (gq_record12 *r);
void gq_record12_wipe (gq_record12 *r);

/* Install keys for one direction (from gq_tls12_keys) and reset its
   sequence number to zero.  */
int gq_record12_set_keys (gq_record12 *r, enum gq_dir dir, enum gq_aead aead,
                          const uint8_t *key, size_t key_len,
                          const uint8_t *iv, size_t iv_len);

int gq_record12_write_protected (const gq_record12 *r);
int gq_record12_read_protected (const gq_record12 *r);
uint64_t gq_record12_write_seq (const gq_record12 *r);
uint64_t gq_record12_read_seq (const gq_record12 *r);

/* Frame FRAGMENT (at most GQ_REC_MAX_PLAINTEXT bytes) as one record of
   TYPE into OUT, protecting it if write keys are installed.  A
   ChangeCipherSpec is always plaintext.  */
int gq_record12_protect (gq_record12 *r, unsigned type,
                         const uint8_t *fragment, size_t len, uint8_t *out,
                         size_t cap, size_t *out_len);

typedef int (*gq_record12_cb) (void *user, unsigned type, const uint8_t *data,
                               size_t len);

/* Consume whole records from *BUF, calling CB for each with the
   decrypted fragment.  GQ_NEED_MORE leaves a partial record.  On a
   protocol or crypto failure returns a negative status and
   gq_record12_alert gives the alert to send.  GQ_ERR_HANDLER: CB stopped
   the loop; *BUF is just past that record.  */
int gq_record12_receive (gq_record12 *r, uint8_t **buf, size_t *len,
                         gq_record12_cb cb, void *user);

int gq_record12_alert (const gq_record12 *r);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_RECORD12_H */
