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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/keysched.h>
#include <gnuquic/dtlsrec.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* ------------------------------------------------------------------ */
/* Decoding                                                           */
/* ------------------------------------------------------------------ */

int
gq_dtls_records (const uint8_t *p, size_t n, gq_drec_cb cb, void *user)
{
  while (n > 0)
    {
      gq_drec r;
      unsigned b = p[0];
      size_t hdr, len, i;

      memset (&r, 0, sizeof r);
      if (b == GQ_DTLS_CT_ALERT || b == GQ_DTLS_CT_HANDSHAKE
          || b == GQ_DTLS_CT_ACK)
        {
          if (n < GQ_DTLS_PLAIN_HEADER)
            return GQ_OK;
          hdr = GQ_DTLS_PLAIN_HEADER;
          len = ((size_t) p[11] << 8) | p[12];
          if (len > n - hdr || len > GQ_DTLS_MAX_PLAINTEXT)
            return GQ_OK;
          r.kind = GQ_DREC_PLAINTEXT;
          r.type = b;
          r.epoch = (uint16_t) (((unsigned) p[3] << 8) | p[4]);
          for (i = 5; i < 11; i++)
            r.seq = (r.seq << 8) | p[i];
        }
      else if ((b & 0xe0) == 0x20 && !(b & 0x10))
        {
          /* 001 C S L E E, and no connection ID was negotiated.  */
          r.seq_len = (b & 0x08) ? 2 : 1;
          hdr = 1 + r.seq_len + ((b & 0x04) ? 2 : 0);
          if (n < hdr)
            return GQ_OK;
          if (b & 0x04)
            len = ((size_t) p[hdr - 2] << 8) | p[hdr - 1];
          else
            len = n - hdr;		/* Runs to the end of the datagram.  */
          if (len > n - hdr)
            return GQ_OK;
          r.kind = GQ_DREC_CIPHERTEXT;
          r.epoch = b & 3;
          for (i = 0; i < r.seq_len; i++)
            r.seq = (r.seq << 8) | p[1 + i];
          r.header.data = p;
          r.header.len = hdr;
        }
      else
        return GQ_OK;			/* Not a DTLS record we can frame.  */
      r.body.data = p + hdr;
      r.body.len = len;
      if (cb && cb (user, &r))
        return GQ_ERR_HANDLER;
      p += hdr + len;
      n -= hdr + len;
    }
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Epoch keys                                                         */
/* ------------------------------------------------------------------ */

int
gq_dtls_epoch_init (gq_dtls_epoch *e, uint64_t epoch, enum gq_aead aead,
                    const uint8_t *secret)
{
  if (e == NULL || secret == NULL)
    return GQ_ERR_INVAL;
  if (gq_aead_key_size (aead) == 0)
    return GQ_ERR_UNSUPPORTED;
  memset (e, 0, sizeof *e);
  TRY (gq_traffic_keys_dtls (aead, secret, e->key, e->iv, e->sn_key));
  e->active = 1;
  e->epoch = epoch;
  e->aead = aead;
  return GQ_OK;
}

void
gq_dtls_epoch_wipe (gq_dtls_epoch *e)
{
  gq_wipe (e, sizeof *e);
}

/* ------------------------------------------------------------------ */
/* Encoding                                                           */
/* ------------------------------------------------------------------ */

void
gq_dtls_put_plain (gq_wbuf *w, unsigned type, uint64_t seq,
                   const uint8_t *fragment, size_t len)
{
  gq_wbuf_u8 (w, type);
  gq_wbuf_u16 (w, 0xfefd);		/* legacy_record_version */
  gq_wbuf_u16 (w, 0);			/* epoch */
  gq_wbuf_u16 (w, (unsigned) (seq >> 32) & 0xffff);
  gq_wbuf_u32 (w, (uint32_t) seq);
  gq_wbuf_u16 (w, (unsigned) len);
  gq_wbuf_bytes (w, fragment, len);
}

/* Per-record nonce: the IV XOR the 64-bit sequence number, right aligned.
   Unlike DTLS 1.2 the epoch is not part of it (RFC 9147 section 4).  */
static void
nonce_for (const gq_dtls_epoch *e, uint64_t seq,
           uint8_t nonce[GQ_AEAD_NONCE_LEN])
{
  size_t i;

  memcpy (nonce, e->iv, GQ_AEAD_NONCE_LEN);
  for (i = 0; i < 8; i++)
    nonce[GQ_AEAD_NONCE_LEN - 1 - i] ^= (uint8_t) (seq >> (8 * i));
}

/* Record number encryption: XOR the mask onto the sequence number bytes.  */
static int
mask_seq (const gq_dtls_epoch *e, const uint8_t *ct, uint8_t *seqbytes,
          unsigned n)
{
  uint8_t m[GQ_HP_MASK_LEN];
  unsigned i;

  TRY (gq_hp_mask (e->aead, e->sn_key, gq_aead_key_size (e->aead), ct, m));
  for (i = 0; i < n; i++)
    seqbytes[i] ^= m[i];
  return GQ_OK;
}

int
gq_dtls_protect (gq_dtls_epoch *e, unsigned type, const uint8_t *payload,
                 size_t len, uint8_t *out, size_t cap, size_t *out_len,
                 uint64_t *seq_used)
{
  uint8_t nonce[GQ_AEAD_NONCE_LEN];
  size_t inner = len + 1, body = inner + GQ_AEAD_TAG_LEN;
  uint64_t seq;

  if (e == NULL || !e->active || out == NULL || out_len == NULL
      || (payload == NULL && len > 0) || len > GQ_DTLS_MAX_PLAINTEXT)
    return GQ_ERR_INVAL;
  if (cap < GQ_DTLS_CIPHER_HEADER + body)
    return GQ_ERR_BUFSIZE;
  seq = e->send_seq;
  if (seq >= (UINT64_C (1) << 48) - 1
      || (e->aead != GQ_AEAD_CHACHA20_POLY1305 && seq >= GQ_DTLS_SEQ_LIMIT))
    return GQ_ERR_RANGE;

  /* 001 C=0 S=1 L=1 EE: 16-bit sequence number, explicit length.  */
  out[0] = (uint8_t) (0x2c | (e->epoch & 3));
  out[1] = (uint8_t) (seq >> 8);
  out[2] = (uint8_t) seq;
  out[3] = (uint8_t) (body >> 8);
  out[4] = (uint8_t) body;
  if (len)
    memmove (out + GQ_DTLS_CIPHER_HEADER, payload, len);
  out[GQ_DTLS_CIPHER_HEADER + len] = (uint8_t) type;
  nonce_for (e, seq, nonce);
  /* The additional data is the header before sequence number encryption.  */
  TRY (gq_aead_seal (e->aead, e->key, gq_aead_key_size (e->aead), nonce, out,
                     GQ_DTLS_CIPHER_HEADER, out + GQ_DTLS_CIPHER_HEADER, inner,
                     out + GQ_DTLS_CIPHER_HEADER, body));
  TRY (mask_seq (e, out + GQ_DTLS_CIPHER_HEADER, out + 1, 2));
  e->send_seq++;
  *out_len = GQ_DTLS_CIPHER_HEADER + body;
  if (seq_used)
    *seq_used = seq;
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Decryption                                                         */
/* ------------------------------------------------------------------ */

/* The full sequence number nearest to one more than the highest seen
   (RFC 9147 section 4.2.2; the same algorithm as QUIC packet numbers).  */
static uint64_t
reconstruct (const gq_dtls_epoch *e, uint64_t trunc, unsigned bits)
{
  uint64_t expected = e->recv_any ? e->recv_max + 1 : 0;
  uint64_t win = UINT64_C (1) << bits, half = win / 2;
  uint64_t cand = (expected & ~(win - 1)) | trunc;

  if (cand + half <= expected && cand + win < (UINT64_C (1) << 48))
    cand += win;
  else if (cand >= expected + half && cand >= win)
    cand -= win;
  return cand;
}

static int
replay_ok (const gq_dtls_epoch *e, uint64_t seq)
{
  uint64_t d;

  if (!e->recv_any || seq > e->recv_max)
    return 1;
  d = e->recv_max - seq;
  return d < 64 && !((e->recv_bits >> d) & 1);
}

static void
replay_update (gq_dtls_epoch *e, uint64_t seq)
{
  if (!e->recv_any || seq > e->recv_max)
    {
      uint64_t shift = e->recv_any ? seq - e->recv_max : 0;

      e->recv_bits = shift >= 64 ? 1 : (e->recv_bits << shift) | 1;
      e->recv_max = seq;
      e->recv_any = 1;
    }
  else
    e->recv_bits |= UINT64_C (1) << (e->recv_max - seq);
}

int
gq_dtls_deprotect (gq_dtls_epoch *e, const gq_drec *rec, uint8_t *out,
                   size_t cap, unsigned *type, size_t *len, uint64_t *seq_out)
{
  uint8_t hdr[GQ_DTLS_CIPHER_HEADER], nonce[GQ_AEAD_NONCE_LEN];
  uint64_t seq = 0;
  size_t n = rec->body.len, plen, hl = rec->header.len, i;
  unsigned bits = rec->seq_len * 8;

  if (e == NULL || !e->active || rec->kind != GQ_DREC_CIPHERTEXT
      || hl > sizeof hdr)
    return GQ_ERR_INVAL;
  /* The mask needs 16 ciphertext bytes; a tag alone provides them.  */
  if (n < GQ_AEAD_TAG_LEN + 1 || n < GQ_HP_SAMPLE_LEN)
    return GQ_ERR_ENCODING;
  if (cap < n - GQ_AEAD_TAG_LEN)
    return GQ_ERR_BUFSIZE;

  /* Decrypt the sequence number in a copy of the header, which is then the
     additional data.  */
  memcpy (hdr, rec->header.data, hl);
  TRY (mask_seq (e, rec->body.data, hdr + 1, rec->seq_len));
  for (i = 0; i < rec->seq_len; i++)
    seq = (seq << 8) | hdr[1 + i];
  seq = reconstruct (e, seq, bits);
  if (e->aead != GQ_AEAD_CHACHA20_POLY1305 && seq >= GQ_DTLS_SEQ_LIMIT)
    return GQ_ERR_RANGE;

  nonce_for (e, seq, nonce);
  if (gq_aead_open (e->aead, e->key, gq_aead_key_size (e->aead), nonce, hdr,
                    hl, rec->body.data, n, out, n - GQ_AEAD_TAG_LEN)
      != GQ_OK)
    {
      e->bad++;
      return GQ_ERR_CRYPTO;
    }
  /* Only now, after authentication, is the record number trusted.  */
  if (!replay_ok (e, seq))
    return GQ_ERR_RANGE;
  replay_update (e, seq);

  /* DTLSInnerPlaintext: content, type, zero padding.  */
  plen = n - GQ_AEAD_TAG_LEN;
  while (plen > 0 && out[plen - 1] == 0)
    plen--;
  if (plen == 0)
    return GQ_ERR_ENCODING;
  *type = out[plen - 1];
  *len = plen - 1;
  if (*len > GQ_DTLS_MAX_PLAINTEXT)
    return GQ_ERR_ENCODING;
  if (seq_out)
    *seq_out = seq;
  return GQ_OK;
}
