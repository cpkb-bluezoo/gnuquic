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
#include <gnuquic/record.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

void
gq_record_init (gq_record *r)
{
  memset (r, 0, sizeof *r);
  r->alert = -1;
}

void
gq_record_wipe (gq_record *r)
{
  gq_wipe (r, sizeof *r);
}

int
gq_record_set_keys (gq_record *r, enum gq_dir dir, enum gq_aead aead,
                    const uint8_t *secret, size_t secret_len)
{
  struct gq_rec_dir *d;
  uint8_t key[32], iv[GQ_AEAD_NONCE_LEN];

  if (r == NULL || secret == NULL || (dir != GQ_DIR_READ && dir != GQ_DIR_WRITE))
    return GQ_ERR_INVAL;
  if (gq_aead_key_size (aead) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (secret_len != gq_hash_size (gq_aead_hash (aead)))
    return GQ_ERR_INVAL;
  TRY (gq_traffic_keys (aead, secret, key, iv));
  d = dir == GQ_DIR_READ ? &r->read : &r->write;
  d->active = 1;
  d->aead = aead;
  memset (d->key, 0, sizeof d->key);
  memcpy (d->key, key, gq_aead_key_size (aead));
  memcpy (d->iv, iv, sizeof d->iv);
  d->seq = 0;
  gq_wipe (key, sizeof key);
  return GQ_OK;
}

void
gq_record_set_server (gq_record *r)
{
  r->server = 1;
}

void
gq_record_set_skip_budget (gq_record *r, size_t budget)
{
  r->skip_budget = budget;
}

void
gq_record_reset_write (gq_record *r)
{
  gq_wipe (&r->write, sizeof r->write);
}

size_t
gq_record_skip_budget (const gq_record *r)
{
  return r->skip_budget;
}

void
gq_record_allow_ccs (gq_record *r, int allow)
{
  r->ccs_ok = allow != 0;
}

uint64_t
gq_record_write_seq (const gq_record *r)
{
  return r->write.seq;
}

uint64_t
gq_record_read_seq (const gq_record *r)
{
  return r->read.seq;
}

int
gq_record_write_protected (const gq_record *r)
{
  return r->write.active;
}

/* Per-record nonce: the IV XOR the 64-bit sequence number, right aligned
   (RFC 8446 section 5.3).  */
static void
nonce_for (const struct gq_rec_dir *d, uint8_t nonce[GQ_AEAD_NONCE_LEN])
{
  size_t i;

  memcpy (nonce, d->iv, GQ_AEAD_NONCE_LEN);
  for (i = 0; i < 8; i++)
    nonce[GQ_AEAD_NONCE_LEN - 1 - i] ^= (uint8_t) (d->seq >> (8 * i));
}

int
gq_record_protect (gq_record *r, unsigned type, const uint8_t *fragment,
                   size_t len, size_t padding, uint8_t *out, size_t cap,
                   size_t *out_len)
{
  size_t body;
  uint8_t nonce[GQ_AEAD_NONCE_LEN];

  if (r == NULL || out == NULL || out_len == NULL
      || (fragment == NULL && len > 0) || len > GQ_REC_MAX_PLAINTEXT)
    return GQ_ERR_INVAL;

  if (!r->write.active)
    {
      /* Plaintext: only records that exist before keys.  */
      if (type != GQ_CT_HANDSHAKE && type != GQ_CT_ALERT
          && type != GQ_CT_CHANGE_CIPHER_SPEC)
        return GQ_ERR_INVAL;
      if (cap < GQ_REC_HEADER_LEN + len)
        return GQ_ERR_BUFSIZE;
      out[0] = (uint8_t) type;
      /* The very first record may claim 0x0301 for old middleboxes
         (RFC 8446 section 5.1); everything else says 0x0303.  */
      out[1] = 3;
      out[2] = (!r->server && type == GQ_CT_HANDSHAKE && r->plaintext_sent == 0)
               ? 1 : 3;
      out[3] = (uint8_t) (len >> 8);
      out[4] = (uint8_t) len;
      if (len)
        memcpy (out + GQ_REC_HEADER_LEN, fragment, len);
      r->plaintext_sent++;
      *out_len = GQ_REC_HEADER_LEN + len;
      return GQ_OK;
    }

  /* Protected: ChangeCipherSpec never travels encrypted.  */
  if (type == GQ_CT_CHANGE_CIPHER_SPEC)
    return GQ_ERR_INVAL;
  if (r->write.seq >= GQ_REC_SEQ_LIMIT)
    return GQ_ERR_RANGE;
  body = len + 1 + padding + GQ_AEAD_TAG_LEN;
  if (body > GQ_REC_MAX_CIPHERTEXT)
    return GQ_ERR_INVAL;
  if (cap < GQ_REC_HEADER_LEN + body)
    return GQ_ERR_BUFSIZE;

  out[0] = GQ_CT_APPLICATION_DATA;
  out[1] = 3;
  out[2] = 3;
  out[3] = (uint8_t) (body >> 8);
  out[4] = (uint8_t) body;
  if (len)
    memcpy (out + GQ_REC_HEADER_LEN, fragment, len);
  out[GQ_REC_HEADER_LEN + len] = (uint8_t) type;
  if (padding)
    memset (out + GQ_REC_HEADER_LEN + len + 1, 0, padding);

  nonce_for (&r->write, nonce);
  TRY (gq_aead_seal (r->write.aead, r->write.key,
                     gq_aead_key_size (r->write.aead), nonce, out,
                     GQ_REC_HEADER_LEN, out + GQ_REC_HEADER_LEN,
                     len + 1 + padding, out + GQ_REC_HEADER_LEN,
                     len + 1 + padding + GQ_AEAD_TAG_LEN));
  r->write.seq++;
  *out_len = GQ_REC_HEADER_LEN + body;
  return GQ_OK;
}

int
gq_record_alert (const gq_record *r)
{
  return r->alert;
}

/* Alert codes used here (RFC 8446 section 6.2).  */
#define ALERT_UNEXPECTED_MESSAGE 10
#define ALERT_BAD_RECORD_MAC 20
#define ALERT_RECORD_OVERFLOW 22
#define ALERT_DECODE_ERROR 50

static int
bad (gq_record *r, int alert, int status)
{
  r->alert = alert;
  return status;
}

int
gq_record_receive (gq_record *r, uint8_t **buf, size_t *len, gq_record_cb cb,
                   void *user)
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

      /* Anything that does not look like a TLS record header at all.  */
      if (p[1] != 3 || (type < GQ_CT_CHANGE_CIPHER_SPEC
                        || type > GQ_CT_APPLICATION_DATA))
        return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
      if (n > (r->read.active ? GQ_REC_MAX_CIPHERTEXT : GQ_REC_MAX_PLAINTEXT))
        return bad (r, ALERT_RECORD_OVERFLOW, GQ_ERR_PROTOCOL);
      if (*len - GQ_REC_HEADER_LEN < n)
        return GQ_NEED_MORE;
      body = p + GQ_REC_HEADER_LEN;

      if (type == GQ_CT_CHANGE_CIPHER_SPEC)
        {
          /* Compatibility record: exactly one byte, value 1, and only when
             the handshake state allows it.  Dropped, never delivered.  */
          if (!r->ccs_ok || n != 1 || body[0] != 1)
            return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
          *buf = body + n;
          *len -= GQ_REC_HEADER_LEN + n;
          continue;
        }

      if (r->read.active)
        {
          uint8_t nonce[GQ_AEAD_NONCE_LEN];
          int rc;

          if (type != GQ_CT_APPLICATION_DATA)
            return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
          if (n < 1 + GQ_AEAD_TAG_LEN)
            return bad (r, ALERT_DECODE_ERROR, GQ_ERR_PROTOCOL);
          if (r->read.seq >= GQ_REC_SEQ_LIMIT)
            return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
          nonce_for (&r->read, nonce);
          rc = gq_aead_open (r->read.aead, r->read.key,
                             gq_aead_key_size (r->read.aead), nonce, p,
                             GQ_REC_HEADER_LEN, body, n, body,
                             n - GQ_AEAD_TAG_LEN);
          if (rc != GQ_OK)
            {
              /* Possibly a 0-RTT record we declined: drop it if allowed.  */
              if (r->skip_budget >= n)
                {
                  r->skip_budget -= n;
                  *buf = p + GQ_REC_HEADER_LEN + n;
                  *len -= GQ_REC_HEADER_LEN + n;
                  continue;
                }
              return bad (r, ALERT_BAD_RECORD_MAC, GQ_ERR_CRYPTO);
            }
          r->read.seq++;
          /* Strip zero padding; the last nonzero byte is the type.  */
          plen = n - GQ_AEAD_TAG_LEN;
          while (plen > 0 && body[plen - 1] == 0)
            plen--;
          if (plen == 0)
            return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
          type = body[plen - 1];
          plen--;
          if (plen > GQ_REC_MAX_PLAINTEXT)
            return bad (r, ALERT_RECORD_OVERFLOW, GQ_ERR_PROTOCOL);
          if (type != GQ_CT_ALERT && type != GQ_CT_HANDSHAKE
              && type != GQ_CT_APPLICATION_DATA)
            return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
        }
      else
        {
          /* Early data we declined arrives as application_data records
             before we have any read keys; skip it while the budget lasts
             (RFC 8446 section 4.2.10).  */
          if (type == GQ_CT_APPLICATION_DATA && r->skip_budget >= n)
            {
              r->skip_budget -= n;
              *buf = p + GQ_REC_HEADER_LEN + n;
              *len -= GQ_REC_HEADER_LEN + n;
              continue;
            }
          /* Otherwise before keys only handshake and alert records exist.  */
          if (type != GQ_CT_HANDSHAKE && type != GQ_CT_ALERT)
            return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);
          plen = n;
        }

      /* Empty handshake fragments are forbidden (RFC 8446 section 5.1).  */
      if (type == GQ_CT_HANDSHAKE && plen == 0)
        return bad (r, ALERT_UNEXPECTED_MESSAGE, GQ_ERR_PROTOCOL);

      *buf = p + GQ_REC_HEADER_LEN + n;
      *len -= GQ_REC_HEADER_LEN + n;
      if (cb && cb (user, type, body, plen))
        return GQ_ERR_HANDLER;
    }
  return GQ_OK;
}
