/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of quickstep.

   quickstep is free software: you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   quickstep is distributed in the hope that it will be useful, but
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

#include <quickstep/status.h>
#include <quickstep/crypto.h>
#include <quickstep/quiclb.h>

#define TRY_R(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

#define SINGLE_PASS_LEN 16
#define MAX_HALF ((GQ_QUICLB_MAX_PLAINTEXT_LEN + 1) / 2)

int
gq_quiclb_config_init (gq_quiclb_config *cfg, unsigned config_id,
                       const uint8_t *server_id, size_t server_id_len,
                       size_t nonce_len,
                       const uint8_t key[GQ_QUICLB_KEY_LEN],
                       int encodes_length)
{
  if (cfg == NULL || server_id == NULL || server_id_len < 1
      || config_id > GQ_QUICLB_MAX_CONFIG_ID
      || nonce_len < GQ_QUICLB_MIN_NONCE_LEN
      || server_id_len + nonce_len > GQ_QUICLB_MAX_PLAINTEXT_LEN)
    return GQ_ERR_INVAL;
  memset (cfg, 0, sizeof *cfg);
  cfg->config_id = config_id;
  memcpy (cfg->server_id, server_id, server_id_len);
  cfg->server_id_len = server_id_len;
  cfg->nonce_len = nonce_len;
  if (key)
    {
      memcpy (cfg->key, key, GQ_QUICLB_KEY_LEN);
      cfg->have_key = 1;
    }
  cfg->encodes_length = encodes_length != 0;
  return GQ_OK;
}

size_t
gq_quiclb_cid_len (const gq_quiclb_config *cfg)
{
  return cfg ? 1 + cfg->server_id_len + cfg->nonce_len : 0;
}

/* ---- The Feistel construction of section 5.4.2 ---- */

static void
clear_nibble (uint8_t *half, size_t half_len, int left)
{
  if (left)
    half[half_len - 1] &= (uint8_t) 0xf0;
  else
    half[0] &= (uint8_t) 0x0f;
}

/* One round: XOR the truncated AES of the expanded SOURCE into TARGET,
   clearing the shared nibble when the plaintext length is odd.  */
static int
feistel_round (const uint8_t key[GQ_QUICLB_KEY_LEN], const uint8_t *source,
              const uint8_t *target, size_t half, size_t len, int pass,
              int odd, int target_is_left, uint8_t *out)
{
  uint8_t block[16], mask[16];
  size_t i;

  memset (block, 0, sizeof block);
  memcpy (block, source, half);
  block[14] = (uint8_t) len;
  block[15] = (uint8_t) pass;
  if (gq_aes128_ecb_encrypt (key, block, mask) != GQ_OK)
    return GQ_ERR_CRYPTO;
  for (i = 0; i < half; i++)
    out[i] = (uint8_t) (target[i] ^ mask[i]);
  if (odd)
    clear_nibble (out, half, target_is_left);
  return GQ_OK;
}

static void
split (const uint8_t *data, size_t len, size_t half, int odd, int left,
      uint8_t *out)
{
  if (left)
    memcpy (out, data, half);
  else
    memcpy (out, data + len - half, half);
  if (odd)
    clear_nibble (out, half, left);
}

static void
merge (const uint8_t *left, const uint8_t *right, size_t len, size_t half,
      uint8_t *out)
{
  size_t right_start = len - half, i;

  memset (out, 0, len);
  memcpy (out, left, half);
  for (i = 0; i < half; i++)
    out[right_start + i] |= right[i];
}

/* Four-pass Feistel network (encrypt: passes 1..4; decrypt: 4..1 with the
   source and target of each round swapped, which inverts it).  */
static int
feistel (const uint8_t key[GQ_QUICLB_KEY_LEN], const uint8_t *in, size_t len,
        int decrypt, uint8_t *out)
{
  size_t half = (len + 1) / 2;
  int odd = (len & 1) != 0;
  uint8_t left[MAX_HALF], right[MAX_HALF], next[MAX_HALF];

  split (in, len, half, odd, 1, left);
  split (in, len, half, odd, 0, right);
  if (!decrypt)
    {
      TRY_R (feistel_round (key, left, right, half, len, 1, odd, 0, next));
      memcpy (right, next, half);
      TRY_R (feistel_round (key, right, left, half, len, 2, odd, 1, next));
      memcpy (left, next, half);
      TRY_R (feistel_round (key, left, right, half, len, 3, odd, 0, next));
      memcpy (right, next, half);
      TRY_R (feistel_round (key, right, left, half, len, 4, odd, 1, next));
      memcpy (left, next, half);
    }
  else
    {
      TRY_R (feistel_round (key, right, left, half, len, 4, odd, 1, next));
      memcpy (left, next, half);
      TRY_R (feistel_round (key, left, right, half, len, 3, odd, 0, next));
      memcpy (right, next, half);
      TRY_R (feistel_round (key, right, left, half, len, 2, odd, 1, next));
      memcpy (left, next, half);
      TRY_R (feistel_round (key, left, right, half, len, 1, odd, 0, next));
      memcpy (right, next, half);
    }
  merge (left, right, len, half, out);
  return GQ_OK;
}

static int
quiclb_crypt (const gq_quiclb_config *cfg, const uint8_t *in, size_t len,
             int decrypt, uint8_t *out)
{
  if (len == SINGLE_PASS_LEN)
    return decrypt ? gq_aes128_ecb_decrypt (cfg->key, in, out)
                   : gq_aes128_ecb_encrypt (cfg->key, in, out);
  return feistel (cfg->key, in, len, decrypt, out);
}

int
gq_quiclb_encode (const gq_quiclb_config *cfg, const uint8_t *nonce,
                  uint8_t *out, size_t out_len)
{
  uint8_t plain[GQ_QUICLB_MAX_PLAINTEXT_LEN];
  uint8_t body[GQ_QUICLB_MAX_PLAINTEXT_LEN];
  size_t plen;
  unsigned low;

  if (cfg == NULL || nonce == NULL || out == NULL
      || out_len != gq_quiclb_cid_len (cfg))
    return GQ_ERR_INVAL;
  plen = cfg->server_id_len + cfg->nonce_len;
  memcpy (plain, cfg->server_id, cfg->server_id_len);
  memcpy (plain + cfg->server_id_len, nonce, cfg->nonce_len);
  if (cfg->have_key)
    TRY_R (quiclb_crypt (cfg, plain, plen, 0, body));
  else
    memcpy (body, plain, plen);
  low = cfg->encodes_length ? (unsigned) (out_len - 1) : 0;
  out[0] = (uint8_t) ((cfg->config_id << 5) | (low & 0x1f));
  memcpy (out + 1, body, plen);
  return GQ_OK;
}

int
gq_quiclb_cid_gen (void *user, uint8_t *out, size_t len)
{
  const gq_quiclb_config *cfg = user;
  uint8_t nonce[GQ_QUICLB_MAX_PLAINTEXT_LEN];

  if (cfg == NULL || out == NULL || len != gq_quiclb_cid_len (cfg))
    return GQ_ERR_INVAL;
  TRY_R (gq_random (nonce, cfg->nonce_len));
  TRY_R (gq_quiclb_encode (cfg, nonce, out, len));
  if (!cfg->encodes_length)
    {
      /* The low five bits are free entropy (section 3.3).  */
      uint8_t bits;

      TRY_R (gq_random (&bits, 1));
      out[0] = (uint8_t) ((cfg->config_id << 5) | (bits & 0x1f));
    }
  return GQ_OK;
}

int
gq_quiclb_decode_server_id (const gq_quiclb_config *cfg, const uint8_t *cid,
                            size_t cid_len, uint8_t *out, size_t *out_len)
{
  uint8_t body[GQ_QUICLB_MAX_PLAINTEXT_LEN];
  size_t plen;

  if (cfg == NULL || cid == NULL || out_len == NULL
      || cid_len != gq_quiclb_cid_len (cfg)
      || (unsigned) (cid[0] >> 5) != cfg->config_id)
    return GQ_ERR_ENCODING;
  if (cfg->encodes_length && (size_t) (cid[0] & 0x1f) + 1 != cid_len)
    return GQ_ERR_ENCODING;
  plen = cfg->server_id_len + cfg->nonce_len;
  if (cfg->have_key)
    TRY_R (quiclb_crypt (cfg, cid + 1, plen, 1, body));
  else
    memcpy (body, cid + 1, plen);
  if (*out_len < cfg->server_id_len)
    return GQ_ERR_BUFSIZE;
  if (out)
    memcpy (out, body, cfg->server_id_len);
  *out_len = cfg->server_id_len;
  return GQ_OK;
}

int
gq_quiclb_is_own (const gq_quiclb_config *cfg, const uint8_t *cid,
                  size_t cid_len)
{
  uint8_t got[GQ_QUICLB_MAX_PLAINTEXT_LEN];
  size_t got_len = sizeof got;

  if (gq_quiclb_decode_server_id (cfg, cid, cid_len, got, &got_len) != GQ_OK)
    return 0;
  return got_len == cfg->server_id_len
         && memcmp (got, cfg->server_id, got_len) == 0;
}
