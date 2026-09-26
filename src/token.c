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
#include <gnuquic/crypto.h>
#include <gnuquic/token.h>

#define NONCE_LEN GQ_AEAD_NONCE_LEN
#define PT_MAX (1 + 8 + 1 + GQ_MAX_CID_LEN + 1 + GQ_MAX_CID_LEN)

int
gq_token_keys_init (gq_token_keys *k)
{
  memset (k, 0, sizeof *k);
  return gq_random (k->key[0], GQ_TOKEN_KEY_LEN);
}

int
gq_token_keys_rotate (gq_token_keys *k)
{
  uint8_t fresh[GQ_TOKEN_KEY_LEN];

  if (gq_random (fresh, sizeof fresh) != GQ_OK)
    return GQ_ERR_CRYPTO;
  memcpy (k->key[1], k->key[0], GQ_TOKEN_KEY_LEN);
  memcpy (k->key[0], fresh, sizeof fresh);
  k->have_prev = 1;
  memset (fresh, 0, sizeof fresh);
  return GQ_OK;
}

void
gq_token_keys_wipe (gq_token_keys *k)
{
  memset (k, 0, sizeof *k);
}

int
gq_token_make (const gq_token_keys *k, enum gq_token_kind kind,
               const uint8_t *addr, size_t addr_len, const gq_cid *odcid,
               const gq_cid *scid, uint64_t now_s, uint8_t *out, size_t *len)
{
  uint8_t pt[PT_MAX];
  size_t n = 0, i;
  int r;

  if (kind != GQ_TOKEN_RETRY && kind != GQ_TOKEN_NEW_TOKEN)
    return GQ_ERR_INVAL;
  if (kind == GQ_TOKEN_RETRY && (odcid == NULL || scid == NULL))
    return GQ_ERR_INVAL;
  pt[n++] = (uint8_t) kind;
  for (i = 0; i < 8; i++)
    pt[n++] = (uint8_t) (now_s >> (56 - 8 * i));
  pt[n++] = kind == GQ_TOKEN_RETRY ? odcid->len : 0;
  if (kind == GQ_TOKEN_RETRY)
    {
      memcpy (pt + n, odcid->data, odcid->len);
      n += odcid->len;
    }
  pt[n++] = kind == GQ_TOKEN_RETRY ? scid->len : 0;
  if (kind == GQ_TOKEN_RETRY)
    {
      memcpy (pt + n, scid->data, scid->len);
      n += scid->len;
    }
  if (gq_random (out, NONCE_LEN) != GQ_OK)
    return GQ_ERR_CRYPTO;
  r = gq_aead_seal (GQ_AEAD_AES_256_GCM, k->key[0], GQ_TOKEN_KEY_LEN, out,
                    addr, addr_len, pt, n, out + NONCE_LEN,
                    n + GQ_AEAD_TAG_LEN);
  if (r != GQ_OK)
    return r;
  *len = NONCE_LEN + n + GQ_AEAD_TAG_LEN;
  return GQ_OK;
}

static int
parse (const uint8_t *pt, size_t n, gq_token_info *info)
{
  size_t p = 0, i;
  uint8_t l;

  memset (info, 0, sizeof *info);
  if (n < 1 + 8 + 1 + 1)
    return GQ_ERR_CRYPTO;
  info->kind = (enum gq_token_kind) pt[p++];
  if (info->kind != GQ_TOKEN_RETRY && info->kind != GQ_TOKEN_NEW_TOKEN)
    return GQ_ERR_CRYPTO;
  for (i = 0; i < 8; i++)
    info->issued = (info->issued << 8) | pt[p++];
  l = pt[p++];
  if (l > GQ_MAX_CID_LEN || p + l + 1 > n)
    return GQ_ERR_CRYPTO;
  info->odcid.len = l;
  memcpy (info->odcid.data, pt + p, l);
  p += l;
  l = pt[p++];
  if (l > GQ_MAX_CID_LEN || p + l != n)
    return GQ_ERR_CRYPTO;
  info->scid.len = l;
  memcpy (info->scid.data, pt + p, l);
  if (info->kind == GQ_TOKEN_RETRY && (info->odcid.len == 0
                                       || info->scid.len == 0))
    return GQ_ERR_CRYPTO;
  return GQ_OK;
}

int
gq_token_check (const gq_token_keys *k, const uint8_t *addr, size_t addr_len,
                const uint8_t *token, size_t len, uint64_t now_s,
                uint32_t retry_lifetime_s, uint32_t new_lifetime_s,
                gq_token_info *info)
{
  uint8_t pt[PT_MAX];
  size_t n, i;
  int r = GQ_ERR_CRYPTO;
  uint32_t life;

  if (len < NONCE_LEN + GQ_AEAD_TAG_LEN + 1
      || len - NONCE_LEN - GQ_AEAD_TAG_LEN > PT_MAX)
    return GQ_ERR_CRYPTO;
  n = len - NONCE_LEN - GQ_AEAD_TAG_LEN;
  for (i = 0; i < (size_t) (k->have_prev ? 2 : 1); i++)
    {
      r = gq_aead_open (GQ_AEAD_AES_256_GCM, k->key[i], GQ_TOKEN_KEY_LEN,
                        token, addr, addr_len, token + NONCE_LEN,
                        len - NONCE_LEN, pt, n);
      if (r == GQ_OK)
        break;
    }
  if (r != GQ_OK)
    return GQ_ERR_CRYPTO;
  r = parse (pt, n, info);
  if (r != GQ_OK)
    return r;
  life = info->kind == GQ_TOKEN_RETRY ? retry_lifetime_s : new_lifetime_s;
  if (info->issued > now_s || now_s - info->issued > life)
    return GQ_ERR_RANGE;
  return GQ_OK;
}
