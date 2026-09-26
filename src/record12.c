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
#include <gnuquic/record12.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* Alert codes used here.  */
#define ALERT_UNEXPECTED_MESSAGE 10
#define ALERT_BAD_RECORD_MAC 20
#define ALERT_RECORD_OVERFLOW 22
#define ALERT_DECODE_ERROR 50
#define ALERT_PROTOCOL_VERSION 70

void
gq_record12_init (gq_record12 *r)
{
  memset (r, 0, sizeof *r);
  r->first = 1;
  r->alert = -1;
}

void
gq_record12_wipe (gq_record12 *r)
{
  gq_wipe (r, sizeof *r);
}

int
gq_record12_set_keys (gq_record12 *r, enum gq_dir dir, enum gq_aead aead,
                      const uint8_t *key, size_t key_len, const uint8_t *iv,
                      size_t iv_len)
{
  struct gq_rec12_dir *d;

  if (r == NULL || key == NULL || iv == NULL
      || (dir != GQ_DIR_READ && dir != GQ_DIR_WRITE))
    return GQ_ERR_INVAL;
  if (gq_aead_key_size (aead) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (key_len != gq_aead_key_size (aead)
      || iv_len != (aead == GQ_AEAD_CHACHA20_POLY1305 ? 12u : 4u))
    return GQ_ERR_INVAL;
  d = dir == GQ_DIR_READ ? &r->read : &r->write;
  memset (d, 0, sizeof *d);
  d->active = 1;
  d->aead = aead;
  memcpy (d->key, key, key_len);
  memcpy (d->iv, iv, iv_len);
  d->iv_len = iv_len;
  return GQ_OK;
}

int
gq_record12_write_protected (const gq_record12 *r)
{
  return r->write.active;
}

int
gq_record12_read_protected (const gq_record12 *r)
{
  return r->read.active;
}

uint64_t
gq_record12_write_seq (const gq_record12 *r)
{
  return r->write.seq;
}

uint64_t
gq_record12_read_seq (const gq_record12 *r)
{
  return r->read.seq;
}

int
gq_record12_alert (const gq_record12 *r)
{
  return r->alert;
}

static int
bad (gq_record12 *r, int alert, int status)
{
  r->alert = alert;
  return status;
}

static void
put64 (uint8_t *p, uint64_t v)
{
  int i;

  for (i = 0; i < 8; i++)
    p[i] = (uint8_t) (v >> (56 - 8 * i));
}

/* Nonce and explicit part.  GCM: implicit salt then the 8-byte explicit
   nonce, which we set to the sequence number (RFC 5288 section 3).
   ChaCha20-Poly1305: the 12-byte IV XOR the sequence number, right
   aligned (RFC 7905 section 2).  */
static void
nonce_for (const struct gq_rec12_dir *d, const uint8_t *explicit_part,
           uint8_t nonce[GQ_AEAD_NONCE_LEN])
{
  size_t i;

  if (d->aead == GQ_AEAD_CHACHA20_POLY1305)
    {
      uint8_t s[8];

      put64 (s, d->seq);
      memcpy (nonce, d->iv, GQ_AEAD_NONCE_LEN);
      for (i = 0; i < 8; i++)
        nonce[4 + i] ^= s[i];
    }
  else
    {
      memcpy (nonce, d->iv, 4);
      memcpy (nonce + 4, explicit_part, 8);
    }
}

static size_t
explicit_len (const struct gq_rec12_dir *d)
{
  return d->aead == GQ_AEAD_CHACHA20_POLY1305 ? 0 : 8;
}

/* True if the direction may not protect or accept another record.  */
static int
exhausted (const struct gq_rec12_dir *d)
{
  if (d->seq == UINT64_MAX)
    return 1;
  return d->aead != GQ_AEAD_CHACHA20_POLY1305 && d->seq >= GQ_REC12_SEQ_LIMIT;
}

/* Additional data: seq_num, type, version, length of the plaintext.  */
static void
make_aad (uint8_t aad[13], uint64_t seq, unsigned type, size_t plen)
{
  put64 (aad, seq);
  aad[8] = (uint8_t) type;
  aad[9] = 3;
  aad[10] = 3;
  aad[11] = (uint8_t) (plen >> 8);
  aad[12] = (uint8_t) plen;
}

int
gq_record12_protect (gq_record12 *r, unsigned type, const uint8_t *fragment,
                     size_t len, uint8_t *out, size_t cap, size_t *out_len)
{
  uint8_t nonce[GQ_AEAD_NONCE_LEN], aad[13];
  size_t el, body;

  if (r == NULL || out == NULL || out_len == NULL
      || (fragment == NULL && len > 0) || len > GQ_REC_MAX_PLAINTEXT
      || type < GQ_CT_CHANGE_CIPHER_SPEC || type > GQ_CT_APPLICATION_DATA)
    return GQ_ERR_INVAL;

  if (!r->write.active || type == GQ_CT_CHANGE_CIPHER_SPEC)
    {
      if (cap < GQ_REC_HEADER_LEN + len)
        return GQ_ERR_BUFSIZE;
      out[0] = (uint8_t) type;
      out[1] = 3;
      out[2] = 3;
      out[3] = (uint8_t) (len >> 8);
      out[4] = (uint8_t) len;
      if (len)
        memcpy (out + GQ_REC_HEADER_LEN, fragment, len);
      *out_len = GQ_REC_HEADER_LEN + len;
      return GQ_OK;
    }

  if (exhausted (&r->write))
    return GQ_ERR_RANGE;
  el = explicit_len (&r->write);
  body = el + len + GQ_AEAD_TAG_LEN;
  if (cap < GQ_REC_HEADER_LEN + body)
    return GQ_ERR_BUFSIZE;
  out[0] = (uint8_t) type;
  out[1] = 3;
  out[2] = 3;
  out[3] = (uint8_t) (body >> 8);
  out[4] = (uint8_t) body;
  /* Seal in place: the plaintext moves behind the explicit nonce first
     (the caller may have built it there).  */
  if (len)
    memmove (out + GQ_REC_HEADER_LEN + el, fragment, len);
  if (el)
    put64 (out + GQ_REC_HEADER_LEN, r->write.seq);
  nonce_for (&r->write, out + GQ_REC_HEADER_LEN, nonce);
  make_aad (aad, r->write.seq, type, len);
  TRY (gq_aead_seal (r->write.aead, r->write.key,
                     gq_aead_key_size (r->write.aead), nonce, aad,
                     sizeof aad, out + GQ_REC_HEADER_LEN + el, len,
                     out + GQ_REC_HEADER_LEN + el, len + GQ_AEAD_TAG_LEN));
  r->write.seq++;
  *out_len = GQ_REC_HEADER_LEN + body;
  return GQ_OK;
}

int
gq_record12_receive (gq_record12 *r, uint8_t **buf, size_t *len,
                     gq_record12_cb cb, void *user)
{
  while (*len > 0)
    {
      uint8_t *p = *buf;
      unsigned type;
      size_t n, plen;
      uint8_t *body;

      if (*len < GQ_REC_HEADER_LEN)
        return GQ_NEED_MORE;
      type = p[0];
      n = ((size_t) p[3] << 8) | p[4];

      if (type < GQ_CT_CHANGE_CIPHER_SPEC || type > GQ_CT_APPLICATION_DATA
          || p[1] != 3)
        return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
      /* The record version is 0x0303, except that the very first record of
         a connection (the ClientHello) may say 0x0301 (RFC 5246 appendix
         E).  Anything else is a version we do not speak.  */
      if (p[2] != 3 && !(r->first && !r->read.active && p[2] == 1))
        return bad (r, ALERT_PROTOCOL_VERSION, GQ_ERR_PROTOCOL);
      if (n > (r->read.active ? GQ_REC12_MAX_CIPHERTEXT
                              : GQ_REC_MAX_PLAINTEXT))
        return bad (r, ALERT_RECORD_OVERFLOW, GQ_ERR_PROTOCOL);
      if (*len - GQ_REC_HEADER_LEN < n)
        return GQ_NEED_MORE;
      body = p + GQ_REC_HEADER_LEN;

      if (type == GQ_CT_CHANGE_CIPHER_SPEC)
        {
          /* Sent in the clear, before the peer's Finished.  A second one
             (or one after keys are on) would be a renegotiation.  */
          if (r->read.active)
            return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
          if (n != 1 || body[0] != 1)
            return bad (r, ALERT_DECODE_ERROR, GQ_ERR_PROTOCOL);
          plen = n;
        }
      else if (r->read.active)
        {
          uint8_t nonce[GQ_AEAD_NONCE_LEN], aad[13];
          size_t el = explicit_len (&r->read);
          int rc;

          if (n < el + GQ_AEAD_TAG_LEN)
            return bad (r, ALERT_DECODE_ERROR, GQ_ERR_PROTOCOL);
          if (exhausted (&r->read))
            return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
          plen = n - el - GQ_AEAD_TAG_LEN;
          if (plen > GQ_REC_MAX_PLAINTEXT)
            return bad (r, ALERT_RECORD_OVERFLOW, GQ_ERR_PROTOCOL);
          nonce_for (&r->read, body, nonce);
          make_aad (aad, r->read.seq, type, plen);
          rc = gq_aead_open (r->read.aead, r->read.key,
                             gq_aead_key_size (r->read.aead), nonce, aad,
                             sizeof aad, body + el, n - el, body + el, plen);
          if (rc != GQ_OK)
            return bad (r, ALERT_BAD_RECORD_MAC, GQ_ERR_CRYPTO);
          r->read.seq++;
          body += el;
        }
      else
        {
          if (type == GQ_CT_APPLICATION_DATA)
            return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
          plen = n;
        }

      /* Empty handshake and alert fragments are forbidden (RFC 5246
         section 6.2.1); empty application data is harmless and dropped.  */
      if ((type == GQ_CT_HANDSHAKE || type == GQ_CT_ALERT) && plen == 0)
        return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);

      r->first = 0;
      *buf = p + GQ_REC_HEADER_LEN + n;
      *len -= GQ_REC_HEADER_LEN + n;
      if (plen == 0 && type == GQ_CT_APPLICATION_DATA)
        continue;
      if (cb && cb (user, type, body, plen))
        return GQ_ERR_HANDLER;
    }
  return GQ_OK;
}
