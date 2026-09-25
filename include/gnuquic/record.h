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

/* TLS 1.3 record layer (RFC 8446 section 5), for TLS over a byte stream.

   A gq_record holds the current read and write protection state and
   nothing else: no buffers, no allocation.  Until keys are installed the
   direction is plaintext (records carry the first handshake flight);
   afterwards every record is an AEAD-protected TLSCiphertext whose real
   content type travels inside the encryption.  Installing new keys resets
   that direction's sequence number, which is how the handshake stages and
   KeyUpdate are expressed.

   Reading is a push parser in the style of gq_frame_parse: hand it a
   buffer holding the stream so far; it consumes whole records, decrypting
   them in place, and stops at a partial record (GQ_NEED_MORE, buffer left
   at the start of that record).  Records are all-or-nothing, so the caller
   never sees half a record.  Each record is delivered as an event with its
   content type and a slice of the (now plaintext) buffer.

   Writing takes one plaintext fragment of at most GQ_REC_MAX_PLAINTEXT
   bytes and produces one record.  Fragmenting larger messages is the
   caller's job.

   Middlebox compatibility: a ChangeCipherSpec record consisting of the
   single byte 1 is silently dropped when the receiver has been told it is
   acceptable (gq_record_allow_ccs, normally between the first handshake
   message and the peer's Finished).  */

#ifndef GNUQUIC_RECORD_H
#define GNUQUIC_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/crypto.h>
#include <gnuquic/tls.h>	/* enum gq_dir */

#ifdef __cplusplus
extern "C" {
#endif

#define GQ_REC_HEADER_LEN 5
#define GQ_REC_MAX_PLAINTEXT 16384
/* Largest legal ciphertext body: plaintext + type + padding + tag.  */
#define GQ_REC_MAX_CIPHERTEXT (16384 + 256)
/* Worst-case size of one record produced by gq_record_protect.  */
#define GQ_REC_MAX_RECORD (GQ_REC_HEADER_LEN + GQ_REC_MAX_CIPHERTEXT)
/* Bytes added to a fragment by protection, without padding.  */
#define GQ_REC_OVERHEAD (GQ_REC_HEADER_LEN + 1 + GQ_AEAD_TAG_LEN)

/* Records per key before protect refuses (RFC 8446 section 5.5 puts the
   AES-GCM confidentiality limit near 2^24.5; callers should rekey well
   before, see GQ_REC_REKEY_ADVISED).  */
#define GQ_REC_SEQ_LIMIT (UINT64_C (1) << 24)
#define GQ_REC_REKEY_ADVISED (UINT64_C (1) << 22)

enum gq_content_type
{
  GQ_CT_CHANGE_CIPHER_SPEC = 20,
  GQ_CT_ALERT = 21,
  GQ_CT_HANDSHAKE = 22,
  GQ_CT_APPLICATION_DATA = 23
};

struct gq_rec_dir
{
  int active;
  enum gq_aead aead;
  uint8_t key[32];
  uint8_t iv[GQ_AEAD_NONCE_LEN];
  uint64_t seq;
};

typedef struct gq_record
{
  struct gq_rec_dir read, write;
  int ccs_ok;
  int plaintext_sent;		/* Plaintext records written so far.  */
  int server;			/* Server role: never claim 0x0301.  */
  size_t skip_budget;		/* Undecryptable bytes still to be skipped.  */
  int alert;			/* Alert to send after a receive failure.  */
} gq_record;

void gq_record_init (gq_record *r);
void gq_record_wipe (gq_record *r);

/* Install protection for DIR from a traffic SECRET (hash-length, chosen
   by AEAD).  The sequence number restarts at zero.  */
int gq_record_set_keys (gq_record *r, enum gq_dir dir, enum gq_aead aead,
                        const uint8_t *secret, size_t secret_len);

/* Mark this record layer as the server's.  Only the first ClientHello
   record may carry the legacy record version 0x0301 (RFC 8446 section
   5.1); a server's records always say 0x0303.  */
void gq_record_set_server (gq_record *r);

/* After a server declines 0-RTT, the client may still send early-data
   records that cannot be decrypted with the handshake keys.  Allow the
   reader to silently drop protected records that fail authentication until
   BUDGET ciphertext bytes have been skipped (RFC 8446 section 4.2.10).
   0 turns skipping off; it must be turned off once the client's Finished
   is processed.  */
void gq_record_set_skip_budget (gq_record *r, size_t budget);
size_t gq_record_skip_budget (const gq_record *r);

/* Drop write protection and return to plaintext records.  Used when early
   data is abandoned (a HelloRetryRequest, or the server declining it)
   before the handshake keys take over: the next ClientHello is plaintext.  */
void gq_record_reset_write (gq_record *r);

/* Whether we may currently drop a compatibility ChangeCipherSpec.  */
void gq_record_allow_ccs (gq_record *r, int allow);

/* Sequence number of the next record in each direction (the number of
   records protected since the last key change).  */
uint64_t gq_record_write_seq (const gq_record *r);
uint64_t gq_record_read_seq (const gq_record *r);
int gq_record_write_protected (const gq_record *r);

/* Build one record from FRAGMENT (LEN <= GQ_REC_MAX_PLAINTEXT) of type
   TYPE, with PADDING zero bytes hidden inside the encryption (ignored for
   plaintext).  OUT needs LEN + PADDING + GQ_REC_OVERHEAD bytes at most;
   the record size is stored in *OUT_LEN.  Without write keys only
   handshake, alert and ChangeCipherSpec records can be made.  Returns
   GQ_OK, GQ_ERR_INVAL, GQ_ERR_BUFSIZE, or GQ_ERR_RANGE if the sequence
   limit was reached.  */
int gq_record_protect (gq_record *r, unsigned type, const uint8_t *fragment,
                       size_t len, size_t padding, uint8_t *out, size_t cap,
                       size_t *out_len);

/* Record event.  Return 0 to continue.  */
typedef int (*gq_record_cb) (void *user, unsigned type, const uint8_t *data,
                             size_t len);

/* Consume records from *BUF (*LEN bytes), decrypting in place, calling CB
   for each.  Returns:

   GQ_OK           the buffer was consumed completely;
   GQ_NEED_MORE    a partial record remains at BUF and LEN;
   GQ_ERR_PROTOCOL malformed record or unexpected type; gq_record_alert
                   gives the alert to send;
   GQ_ERR_CRYPTO   authentication failed (alert bad_record_mac);
   GQ_ERR_HANDLER  CB refused a record; BUF and LEN are just past it.

   After an error the state is unusable for reading.  */
int gq_record_receive (gq_record *r, uint8_t **buf, size_t *len,
                       gq_record_cb cb, void *user);

/* The alert code (RFC 8446 section 6.2) for the last receive failure.  */
int gq_record_alert (const gq_record *r);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_RECORD_H */
