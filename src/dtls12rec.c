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
#include <gnuquic/dtls12rec.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

int
gq_dtls12_records (const uint8_t *p, size_t n, gq_d12rec_cb cb, void *user)
{
  while (n > 0)
    {
      gq_d12rec r;
      size_t len, i;
      unsigned ver;

      if (n < GQ_DTLS12_HEADER)
        return GQ_OK;
      r.type = p[0];
      ver = ((unsigned) p[1] << 8) | p[2];
      len = ((size_t) p[11] << 8) | p[12];
      if (len > n - GQ_DTLS12_HEADER
          || len > GQ_DTLS12_MAX_PLAINTEXT + 2048)
        return GQ_OK;
      r.epoch = (uint16_t) (((unsigned) p[3] << 8) | p[4]);
      r.seq = 0;
      for (i = 5; i < 11; i++)
        r.seq = (r.seq << 8) | p[i];
      r.header.data = p;
      r.header.len = GQ_DTLS12_HEADER;
      r.body.data = p + GQ_DTLS12_HEADER;
      r.body.len = len;
      /* 0xfefd, or 0xfeff on the first ClientHello for compatibility.  */
      if (r.type >= 20 && r.type <= 23 && (ver == 0xfefd || ver == 0xfeff)
          && cb && cb (user, &r))
        return GQ_ERR_HANDLER;
      p += GQ_DTLS12_HEADER + len;
      n -= GQ_DTLS12_HEADER + len;
    }
  return GQ_OK;
}

void
gq_dtls12_epoch_plain (gq_dtls12_epoch *e)
{
  memset (e, 0, sizeof *e);
}

int
gq_dtls12_epoch_init (gq_dtls12_epoch *e, uint16_t epoch, enum gq_aead aead,
                      const uint8_t *key, size_t key_len, const uint8_t *iv,
                      size_t iv_len)
{
  if (e == NULL || key == NULL || iv == NULL)
    return GQ_ERR_INVAL;
  if (gq_aead_key_size (aead) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (key_len != gq_aead_key_size (aead)
      || iv_len != (aead == GQ_AEAD_CHACHA20_POLY1305 ? 12u : 4u))
    return GQ_ERR_INVAL;
  memset (e, 0, sizeof *e);
  e->active = 1;
  e->epoch = epoch;
  e->aead = aead;
  memcpy (e->key, key, key_len);
  memcpy (e->iv, iv, iv_len);
  e->iv_len = iv_len;
  return GQ_OK;
}

void
gq_dtls12_epoch_wipe (gq_dtls12_epoch *e)
{
  gq_wipe (e, sizeof *e);
}

int
gq_dtls12_replay_ok (const gq_dtls12_epoch *e, uint64_t seq)
{
  uint64_t d;

  if (!e->recv_any || seq > e->recv_max)
    return 1;
  d = e->recv_max - seq;
  return d < 64 && !((e->recv_bits >> d) & 1);
}

void
gq_dtls12_replay_update (gq_dtls12_epoch *e, uint64_t seq)
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

static void
put_header (uint8_t *h, unsigned type, uint16_t epoch, uint64_t seq,
            size_t len)
{
  int i;

  h[0] = (uint8_t) type;
  h[1] = 0xfe;
  h[2] = 0xfd;
  h[3] = (uint8_t) (epoch >> 8);
  h[4] = (uint8_t) epoch;
  for (i = 0; i < 6; i++)
    h[5 + i] = (uint8_t) (seq >> (40 - 8 * i));
  h[11] = (uint8_t) (len >> 8);
  h[12] = (uint8_t) len;
}

void
gq_dtls12_put_plain (gq_wbuf *w, gq_dtls12_epoch *e, unsigned type,
                     const uint8_t *fragment, size_t len)
{
  uint8_t h[GQ_DTLS12_HEADER];

  put_header (h, type, 0, e->send_seq++, len);
  gq_wbuf_bytes (w, h, sizeof h);
  gq_wbuf_bytes (w, fragment, len);
}

/* epoch || sequence number as 8 bytes.  */
static void
epoch_seq (uint8_t out[8], uint16_t epoch, uint64_t seq)
{
  int i;

  out[0] = (uint8_t) (epoch >> 8);
  out[1] = (uint8_t) epoch;
  for (i = 0; i < 6; i++)
    out[2 + i] = (uint8_t) (seq >> (40 - 8 * i));
}

/* Additional data: epoch || seq, type, version, plaintext length.  */
static void
make_aad (uint8_t aad[13], uint16_t epoch, uint64_t seq, unsigned type,
          const uint8_t version[2], size_t plen)
{
  epoch_seq (aad, epoch, seq);
  aad[8] = (uint8_t) type;
  aad[9] = version[0];
  aad[10] = version[1];
  aad[11] = (uint8_t) (plen >> 8);
  aad[12] = (uint8_t) plen;
}

/* GCM: salt then the explicit nonce from the wire.  ChaCha20: the 12-byte
   IV XOR epoch || sequence number, right aligned (RFC 7905 section 2).  */
static void
make_nonce (const gq_dtls12_epoch *e, const uint8_t es[8],
            uint8_t nonce[GQ_AEAD_NONCE_LEN])
{
  size_t i;

  if (e->aead == GQ_AEAD_CHACHA20_POLY1305)
    {
      memcpy (nonce, e->iv, GQ_AEAD_NONCE_LEN);
      for (i = 0; i < 8; i++)
        nonce[4 + i] ^= es[i];
    }
  else
    {
      memcpy (nonce, e->iv, 4);
      memcpy (nonce + 4, es, 8);
    }
}

static size_t
explicit_len (const gq_dtls12_epoch *e)
{
  return e->aead == GQ_AEAD_CHACHA20_POLY1305 ? 0 : 8;
}

static int
exhausted (const gq_dtls12_epoch *e, uint64_t seq)
{
  return seq >= (UINT64_C (1) << 48) - 1
    || (e->aead != GQ_AEAD_CHACHA20_POLY1305 && seq >= GQ_DTLS12_SEQ_LIMIT);
}

int
gq_dtls12_protect (gq_dtls12_epoch *e, unsigned type, const uint8_t *payload,
                   size_t len, uint8_t *out, size_t cap, size_t *out_len)
{
  uint8_t nonce[GQ_AEAD_NONCE_LEN], aad[13], es[8];
  size_t el, body;
  uint64_t seq;

  if (e == NULL || !e->active || out == NULL || out_len == NULL
      || (payload == NULL && len > 0) || len > GQ_DTLS12_MAX_PLAINTEXT)
    return GQ_ERR_INVAL;
  el = explicit_len (e);
  body = el + len + GQ_AEAD_TAG_LEN;
  if (cap < GQ_DTLS12_HEADER + body)
    return GQ_ERR_BUFSIZE;
  seq = e->send_seq;
  if (exhausted (e, seq))
    return GQ_ERR_RANGE;

  epoch_seq (es, e->epoch, seq);
  put_header (out, type, e->epoch, seq, body);
  /* The plaintext may sit where the ciphertext goes: move it first.  */
  if (len)
    memmove (out + GQ_DTLS12_HEADER + el, payload, len);
  if (el)
    memcpy (out + GQ_DTLS12_HEADER, es, 8);
  make_nonce (e, es, nonce);
  make_aad (aad, e->epoch, seq, type, (const uint8_t *) "\xfe\xfd", len);
  TRY (gq_aead_seal (e->aead, e->key, gq_aead_key_size (e->aead), nonce, aad,
                     sizeof aad, out + GQ_DTLS12_HEADER + el, len,
                     out + GQ_DTLS12_HEADER + el, len + GQ_AEAD_TAG_LEN));
  e->send_seq++;
  *out_len = GQ_DTLS12_HEADER + body;
  return GQ_OK;
}

int
gq_dtls12_deprotect (gq_dtls12_epoch *e, const gq_d12rec *rec, uint8_t *out,
                     size_t cap, size_t *len)
{
  uint8_t nonce[GQ_AEAD_NONCE_LEN], aad[13], es[8];
  size_t el, n = rec->body.len, plen;

  if (e == NULL || !e->active)
    return GQ_ERR_INVAL;
  el = explicit_len (e);
  if (n < el + GQ_AEAD_TAG_LEN)
    return GQ_ERR_ENCODING;
  plen = n - el - GQ_AEAD_TAG_LEN;
  if (plen > GQ_DTLS12_MAX_PLAINTEXT)
    return GQ_ERR_ENCODING;
  if (cap < plen)
    return GQ_ERR_BUFSIZE;
  if (exhausted (e, rec->seq))
    return GQ_ERR_RANGE;
  if (!gq_dtls12_replay_ok (e, rec->seq))
    return GQ_ERR_RANGE;

  /* The explicit nonce is whatever the sender put on the wire; the
     additional data is built from the record header.  */
  if (el)
    memcpy (es, rec->body.data, 8);
  else
    epoch_seq (es, rec->epoch, rec->seq);
  make_nonce (e, es, nonce);
  /* The version as received: DTLS 1.2 authenticates it.  */
  make_aad (aad, rec->epoch, rec->seq, rec->type, rec->header.data + 1, plen);
  if (gq_aead_open (e->aead, e->key, gq_aead_key_size (e->aead), nonce, aad,
                    sizeof aad, rec->body.data + el, n - el, out, plen)
      != GQ_OK)
    {
      e->bad++;
      return GQ_ERR_CRYPTO;
    }
  gq_dtls12_replay_update (e, rec->seq);
  *len = plen;
  return GQ_OK;
}
