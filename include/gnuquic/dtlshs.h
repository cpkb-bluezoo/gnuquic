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

/* DTLS 1.3 handshake fragment and ACK codecs (RFC 9147 sections 5.2, 5.5
   and 7).

   Decoding: gq_dtls_hs_parse takes the payload of one handshake record
   and delivers each DTLSHandshake fragment in it as a gq_dtls_hs_frag
   event; gq_dtls_acks takes an ACK record's payload and delivers each
   acknowledged record number.  Slices point into the input.

   Reassembly: gq_dtls_reasm is the small state machine between fragments
   and the handshake engine.  It delivers complete messages, in order, in
   the TLS 1.3 handshake format the engine (and the transcript) expects:
   the 4-byte header without message_seq, fragment_offset and
   fragment_length.  It keeps only the message being assembled, as a
   buffer of that message's size and a short list of the byte ranges seen
   so far.  A fragment of a later message is dropped, not queued (the peer
   retransmits it, and RFC 9147 section 5.2 lets an implementation
   discard it), so memory is bounded by one message.  Fragments may
   overlap and arrive in any order; overlapping bytes must agree.

   Encoding: gq_dtls_put_hs_frag and gq_dtls_put_acks append the
   corresponding payload to a gq_wbuf.  */

#ifndef GNUQUIC_DTLSHS_H
#define GNUQUIC_DTLSHS_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/frame.h>	/* gq_slice */
#include <gnuquic/tlsmsg.h>	/* gq_wbuf */

#ifdef __cplusplus
extern "C" {
#endif

#define GQ_DTLS_HS_HEADER 12

/* ---- Decoding: record payload in, fragment events out ---- */

typedef struct gq_dtls_hs_frag
{
  unsigned type;
  uint32_t length;		/* Of the whole message.  */
  uint16_t message_seq;
  uint32_t frag_off, frag_len;
  gq_slice data;		/* frag_len bytes.  */
} gq_dtls_hs_frag;

typedef int (*gq_dtls_hs_cb) (void *user, const gq_dtls_hs_frag *frag);

/* Deliver each fragment of FRAGMENT (a record's payload).  GQ_ERR_ENCODING
   for a fragment that overruns the record or its message, or a message
   longer than MAX_LEN (GQ_ERR_PROTOCOL); GQ_ERR_HANDLER if CB stopped.  */
int gq_dtls_hs_parse (gq_slice fragment, uint32_t max_len, gq_dtls_hs_cb cb,
                      void *user);

/* ---- Reassembly ---- */

#define GQ_DTLS_RANGES 8

typedef struct gq_dtls_range
{
  uint32_t lo, hi;		/* Bytes [lo, hi) of the message body.  */
} gq_dtls_range;

typedef struct gq_dtls_reasm
{
  uint16_t next_seq;		/* message_seq expected next.  */
  uint32_t max_len;
  uint8_t *buf;			/* 4 + length bytes, once a message starts.  */
  size_t cap;
  int active;			/* A message is being assembled.  */
  unsigned type;
  uint32_t length;
  unsigned n;			/* Ranges seen, sorted, disjoint.  */
  gq_dtls_range range[GQ_DTLS_RANGES];
} gq_dtls_reasm;

void gq_dtls_reasm_init (gq_dtls_reasm *r, uint32_t max_len, uint16_t first);
/* Release the buffer (keeps the position; it is regrown when needed).  */
void gq_dtls_reasm_trim (gq_dtls_reasm *r);
void gq_dtls_reasm_free (gq_dtls_reasm *r);

/* What happened to a fragment.  Only DELIVERED, BUFFERED and DUPLICATE may
   be acknowledged (RFC 9147 section 7: never a message we discarded).  */
enum gq_drx
{
  GQ_DRX_DELIVERED = 1,		/* Completed the next message.  */
  GQ_DRX_BUFFERED,		/* Part of the next message, still partial.  */
  GQ_DRX_DUPLICATE,		/* From a message already delivered.  */
  GQ_DRX_DROPPED		/* A later message, or no room: not kept.  */
};

/* Called with each completed message: TYPE and the whole TLS-format
   message.  Return nonzero to stop (the push then returns
   GQ_ERR_HANDLER).  */
typedef int (*gq_dtls_msg_cb) (void *user, unsigned type, gq_slice msg);

/* Feed one fragment.  Returns a positive gq_drx, or a negative status:
   GQ_ERR_PROTOCOL if the fragment disagrees with earlier ones of its
   message (type, length or overlapping bytes), GQ_ERR_NOMEM.  */
int gq_dtls_reasm_push (gq_dtls_reasm *r, const gq_dtls_hs_frag *frag,
                        gq_dtls_msg_cb cb, void *user);

/* A message is partly received.  */
int gq_dtls_reasm_partial (const gq_dtls_reasm *r);

/* ---- ACKs ---- */

typedef struct gq_dtls_recno
{
  uint64_t epoch, seq;
} gq_dtls_recno;

typedef int (*gq_dtls_ack_cb) (void *user, gq_dtls_recno rec);

/* Deliver each record number of an ACK payload.  */
int gq_dtls_acks (gq_slice body, gq_dtls_ack_cb cb, void *user);

/* ---- Encoding ---- */

/* Append the fragment [OFF, OFF+N) of a message of LENGTH bytes with type
   TYPE and message_seq SEQ.  DATA points at those N bytes.  */
void gq_dtls_put_hs_frag (gq_wbuf *w, unsigned type, uint32_t length,
                          uint16_t seq, uint32_t off, const uint8_t *data,
                          size_t n);

/* Append an ACK payload for the N record numbers (at most 8191).  */
void gq_dtls_put_acks (gq_wbuf *w, const gq_dtls_recno *nums, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_DTLSHS_H */
