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

#include <stdlib.h>
#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/crypto.h>
#include <gnuquic/tickets.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

#define NAME_LEN 16
#define NONCE_LEN GQ_AEAD_NONCE_LEN
#define TICKET_VERSION 1

struct slot
{
  int used;
  uint8_t name[NAME_LEN];
  uint8_t key[GQ_TICKET_KEY_LEN];
  unsigned serial;		/* Age: lower is older.  */
};

struct gq_ticket_keys
{
  struct slot slot[GQ_TICKET_KEYS_MAX];
  int active;			/* Index of the encryption key.  */
  unsigned next_serial;
};

/* The name identifies a key without revealing it.  */
static int
key_name (const uint8_t key[GQ_TICKET_KEY_LEN], uint8_t name[NAME_LEN])
{
  uint8_t in[GQ_TICKET_KEY_LEN + 16], h[32];

  memcpy (in, "gnuquic ticket:", 16);
  memcpy (in + 16, key, GQ_TICKET_KEY_LEN);
  TRY (gq_hash_compute (GQ_HASH_SHA256, in, sizeof in, h, sizeof h));
  memcpy (name, h, NAME_LEN);
  gq_wipe (in, sizeof in);
  return GQ_OK;
}

int
gq_ticket_keys_add (gq_ticket_keys *k, const uint8_t key[GQ_TICKET_KEY_LEN],
                    int active)
{
  uint8_t name[NAME_LEN];
  int i, victim = -1;

  if (k == NULL || key == NULL)
    return GQ_ERR_INVAL;
  TRY (key_name (key, name));
  for (i = 0; i < GQ_TICKET_KEYS_MAX; i++)
    if (k->slot[i].used && memcmp (k->slot[i].name, name, NAME_LEN) == 0)
      {
        if (active)
          k->active = i;
        return GQ_OK;		/* Already present.  */
      }
  for (i = 0; i < GQ_TICKET_KEYS_MAX; i++)
    if (!k->slot[i].used)
      {
        victim = i;
        break;
      }
  if (victim < 0)
    {
      /* Drop the oldest key that is not the active one.  */
      for (i = 0; i < GQ_TICKET_KEYS_MAX; i++)
        if (i != k->active
            && (victim < 0 || k->slot[i].serial < k->slot[victim].serial))
          victim = i;
    }
  k->slot[victim].used = 1;
  memcpy (k->slot[victim].name, name, NAME_LEN);
  memcpy (k->slot[victim].key, key, GQ_TICKET_KEY_LEN);
  k->slot[victim].serial = k->next_serial++;
  if (active || !k->slot[k->active].used)
    k->active = victim;
  return GQ_OK;
}

int
gq_ticket_keys_new (gq_ticket_keys **out)
{
  gq_ticket_keys *k;
  uint8_t key[GQ_TICKET_KEY_LEN];
  int r;

  if (out == NULL)
    return GQ_ERR_INVAL;
  TRY (gq_crypto_init ());
  k = calloc (1, sizeof *k);
  if (k == NULL)
    return GQ_ERR_NOMEM;
  r = gq_random (key, sizeof key);
  if (r == GQ_OK)
    r = gq_ticket_keys_add (k, key, 1);
  gq_wipe (key, sizeof key);
  if (r != GQ_OK)
    {
      free (k);
      return r;
    }
  *out = k;
  return GQ_OK;
}

void
gq_ticket_keys_free (gq_ticket_keys *k)
{
  if (k == NULL)
    return;
  gq_wipe (k, sizeof *k);
  free (k);
}

int
gq_ticket_keys_rotate (gq_ticket_keys *k)
{
  uint8_t key[GQ_TICKET_KEY_LEN];
  int r;

  if (k == NULL)
    return GQ_ERR_INVAL;
  r = gq_random (key, sizeof key);
  if (r == GQ_OK)
    r = gq_ticket_keys_add (k, key, 1);
  gq_wipe (key, sizeof key);
  return r;
}

/* ------------------------------------------------------------------ */
/* State encoding                                                     */
/* ------------------------------------------------------------------ */

static void
put_be (uint8_t **p, uint64_t v, unsigned n)
{
  unsigned i;

  for (i = 0; i < n; i++)
    *(*p)++ = (uint8_t) (v >> (8 * (n - 1 - i)));
}

static int
get_be (const uint8_t **p, const uint8_t *end, unsigned n, uint64_t *v)
{
  unsigned i;

  if ((size_t) (end - *p) < n)
    return 0;
  *v = 0;
  for (i = 0; i < n; i++)
    *v = (*v << 8) | *(*p)++;
  return 1;
}

/* Bytes of the encoded state (an upper bound is sizeof buf below).  */
static size_t
encode_state (const gq_session_state *s, uint8_t *out)
{
  uint8_t *p = out;

  *p++ = TICKET_VERSION;
  put_be (&p, s->cipher_suite, 2);
  *p++ = (uint8_t) s->psk_len;
  memcpy (p, s->psk, s->psk_len);
  p += s->psk_len;
  put_be (&p, s->created_ms, 8);
  put_be (&p, s->age_add, 4);
  put_be (&p, s->lifetime, 4);
  put_be (&p, s->max_early_data, 4);
  *p++ = s->client_authenticated ? 1 : 0;
  *p++ = (uint8_t) s->server_name_len;
  memcpy (p, s->server_name, s->server_name_len);
  p += s->server_name_len;
  *p++ = (uint8_t) s->alpn_len;
  memcpy (p, s->alpn, s->alpn_len);
  p += s->alpn_len;
  return (size_t) (p - out);
}

static int
decode_state (const uint8_t *in, size_t len, gq_session_state *s)
{
  const uint8_t *p = in, *end = in + len;
  uint64_t v;

  memset (s, 0, sizeof *s);
  if (len < 1 || *p++ != TICKET_VERSION)
    return GQ_ERR_ENCODING;
  if (!get_be (&p, end, 2, &v))
    return GQ_ERR_ENCODING;
  s->cipher_suite = (uint16_t) v;
  if (end - p < 1)
    return GQ_ERR_ENCODING;
  s->psk_len = *p++;
  if (s->psk_len == 0 || s->psk_len > sizeof s->psk
      || (size_t) (end - p) < s->psk_len)
    return GQ_ERR_ENCODING;
  memcpy (s->psk, p, s->psk_len);
  p += s->psk_len;
  if (!get_be (&p, end, 8, &s->created_ms))
    return GQ_ERR_ENCODING;
  if (!get_be (&p, end, 4, &v)) return GQ_ERR_ENCODING;
  s->age_add = (uint32_t) v;
  if (!get_be (&p, end, 4, &v)) return GQ_ERR_ENCODING;
  s->lifetime = (uint32_t) v;
  if (!get_be (&p, end, 4, &v)) return GQ_ERR_ENCODING;
  s->max_early_data = (uint32_t) v;
  if (end - p < 2)
    return GQ_ERR_ENCODING;
  s->client_authenticated = *p++ & 1;
  s->server_name_len = *p++;
  if ((size_t) (end - p) < s->server_name_len + 1)
    return GQ_ERR_ENCODING;
  memcpy (s->server_name, p, s->server_name_len);
  s->server_name[s->server_name_len] = 0;
  p += s->server_name_len;
  s->alpn_len = *p++;
  if ((size_t) (end - p) != s->alpn_len)
    return GQ_ERR_ENCODING;
  memcpy (s->alpn, p, s->alpn_len);
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Seal and open                                                      */
/* ------------------------------------------------------------------ */

int
gq_ticket_seal (const gq_ticket_keys *k, const gq_session_state *s,
                uint8_t *out, size_t cap, size_t *out_len)
{
  uint8_t plain[700];
  size_t pl, total;
  const struct slot *a;
  int r;

  if (k == NULL || s == NULL || out == NULL || out_len == NULL
      || s->psk_len == 0 || s->psk_len > sizeof s->psk
      || s->server_name_len > 255 || s->alpn_len > sizeof s->alpn)
    return GQ_ERR_INVAL;
  a = &k->slot[k->active];
  if (!a->used)
    return GQ_ERR_INVAL;
  pl = encode_state (s, plain);
  total = NAME_LEN + NONCE_LEN + pl + GQ_AEAD_TAG_LEN;
  if (cap < total)
    return GQ_ERR_BUFSIZE;

  memcpy (out, a->name, NAME_LEN);
  TRY (gq_random (out + NAME_LEN, NONCE_LEN));
  r = gq_aead_seal (GQ_AEAD_AES_256_GCM, a->key, GQ_TICKET_KEY_LEN,
                    out + NAME_LEN, a->name, NAME_LEN, plain, pl,
                    out + NAME_LEN + NONCE_LEN, pl + GQ_AEAD_TAG_LEN);
  gq_wipe (plain, sizeof plain);
  if (r == GQ_OK)
    *out_len = total;
  return r;
}

int
gq_ticket_open (const gq_ticket_keys *k, const uint8_t *t, size_t len,
                gq_session_state *s, int *active_key)
{
  uint8_t plain[700];
  size_t pl;
  int i, r = GQ_ERR_CRYPTO;

  if (k == NULL || t == NULL || s == NULL)
    return GQ_ERR_INVAL;
  if (len < NAME_LEN + NONCE_LEN + GQ_AEAD_TAG_LEN + 1
      || len > NAME_LEN + NONCE_LEN + sizeof plain + GQ_AEAD_TAG_LEN)
    return GQ_ERR_CRYPTO;
  pl = len - NAME_LEN - NONCE_LEN - GQ_AEAD_TAG_LEN;

  for (i = 0; i < GQ_TICKET_KEYS_MAX; i++)
    {
      if (!k->slot[i].used || memcmp (k->slot[i].name, t, NAME_LEN) != 0)
        continue;
      r = gq_aead_open (GQ_AEAD_AES_256_GCM, k->slot[i].key,
                        GQ_TICKET_KEY_LEN, t + NAME_LEN, t, NAME_LEN,
                        t + NAME_LEN + NONCE_LEN,
                        pl + GQ_AEAD_TAG_LEN, plain, pl);
      if (r == GQ_OK)
        {
          if (active_key)
            *active_key = i == k->active;
          r = decode_state (plain, pl, s);
        }
      break;
    }
  gq_wipe (plain, sizeof plain);
  return r;
}
