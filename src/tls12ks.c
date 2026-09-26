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
#include <gnuquic/policy.h>
#include <gnuquic/keysched.h>
#include <gnuquic/tls12ks.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

#define PRF_LABEL_MAX 64
#define PRF_SEED_MAX 512

int
gq_tls12_suite_params (unsigned suite, enum gq_aead *aead, enum gq_hash *hash)
{
  switch (suite)
    {
    case GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
    case GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
      *aead = GQ_AEAD_AES_128_GCM; *hash = GQ_HASH_SHA256; return 1;
    case GQ_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
    case GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
      *aead = GQ_AEAD_AES_256_GCM; *hash = GQ_HASH_SHA384; return 1;
    case GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
    case GQ_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
      *aead = GQ_AEAD_CHACHA20_POLY1305; *hash = GQ_HASH_SHA256; return 1;
    default:
      return 0;
    }
}

int
gq_tls12_suite_is_rsa (unsigned suite)
{
  return suite == GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    || suite == GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    || suite == GQ_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305;
}

/* P_hash (secret, seed) = HMAC (secret, A(1) + seed) + HMAC (secret,
   A(2) + seed) + ..., with A(0) = seed and A(i) = HMAC (secret, A(i-1)).
   SEED here is label + seed.  */
int
gq_tls12_prf (enum gq_hash hash, const uint8_t *secret, size_t secret_len,
              const char *label, const uint8_t *seed, size_t seed_len,
              uint8_t *out, size_t out_len)
{
  uint8_t ls[PRF_LABEL_MAX + PRF_SEED_MAX];
  uint8_t a[GQ_MAX_HASH_LEN], buf[GQ_MAX_HASH_LEN + PRF_LABEL_MAX + PRF_SEED_MAX];
  uint8_t chunk[GQ_MAX_HASH_LEN];
  size_t hl = gq_hash_size (hash), ll, done = 0;
  int r = GQ_OK;

  if (hl == 0 || label == NULL || (seed == NULL && seed_len > 0)
      || (out == NULL && out_len > 0) || (secret == NULL && secret_len > 0))
    return GQ_ERR_INVAL;
  ll = strlen (label);
  if (ll > PRF_LABEL_MAX || seed_len > PRF_SEED_MAX)
    return GQ_ERR_RANGE;
  memcpy (ls, label, ll);
  if (seed_len)
    memcpy (ls + ll, seed, seed_len);
  ll += seed_len;

  r = gq_hmac (hash, secret, secret_len, ls, ll, a, hl);
  while (r == GQ_OK && done < out_len)
    {
      size_t n = out_len - done < hl ? out_len - done : hl;

      memcpy (buf, a, hl);
      memcpy (buf + hl, ls, ll);
      r = gq_hmac (hash, secret, secret_len, buf, hl + ll, chunk, hl);
      if (r != GQ_OK)
        break;
      memcpy (out + done, chunk, n);
      done += n;
      if (done < out_len)
        {
          memcpy (chunk, a, hl);
          r = gq_hmac (hash, secret, secret_len, chunk, hl, a, hl);
        }
    }
  gq_wipe (ls, sizeof ls);
  gq_wipe (a, sizeof a);
  gq_wipe (buf, sizeof buf);
  gq_wipe (chunk, sizeof chunk);
  if (r != GQ_OK && out_len)
    gq_wipe (out, out_len);
  return r;
}

int
gq_tls12_master_secret (enum gq_hash hash, const uint8_t *premaster,
                        size_t premaster_len, const uint8_t *session_hash,
                        uint8_t master[GQ_TLS12_MASTER_LEN])
{
  return gq_tls12_prf (hash, premaster, premaster_len,
                       "extended master secret", session_hash,
                       gq_hash_size (hash), master, GQ_TLS12_MASTER_LEN);
}

int
gq_tls12_key_block (enum gq_hash hash, enum gq_aead aead,
                    const uint8_t master[GQ_TLS12_MASTER_LEN],
                    const uint8_t server_random[32],
                    const uint8_t client_random[32], gq_tls12_keys *keys)
{
  uint8_t seed[64], block[2 * 32 + 2 * 12];
  size_t kl = gq_aead_key_size (aead), il, off = 0;
  int r;

  if (kl == 0)
    return GQ_ERR_UNSUPPORTED;
  il = aead == GQ_AEAD_CHACHA20_POLY1305 ? 12 : 4;
  memcpy (seed, server_random, 32);
  memcpy (seed + 32, client_random, 32);
  r = gq_tls12_prf (hash, master, GQ_TLS12_MASTER_LEN, "key expansion", seed,
                    sizeof seed, block, 2 * kl + 2 * il);
  if (r == GQ_OK)
    {
      memset (keys, 0, sizeof *keys);
      keys->aead = aead;
      keys->key_len = kl;
      keys->iv_len = il;
      memcpy (keys->client_key, block + off, kl); off += kl;
      memcpy (keys->server_key, block + off, kl); off += kl;
      memcpy (keys->client_iv, block + off, il); off += il;
      memcpy (keys->server_iv, block + off, il);
    }
  gq_wipe (block, sizeof block);
  return r;
}

int
gq_tls12_verify_data (enum gq_hash hash,
                      const uint8_t master[GQ_TLS12_MASTER_LEN],
                      int from_client, const uint8_t *handshake_hash,
                      uint8_t out[GQ_TLS12_VERIFY_LEN])
{
  return gq_tls12_prf (hash, master, GQ_TLS12_MASTER_LEN,
                       from_client ? "client finished" : "server finished",
                       handshake_hash, gq_hash_size (hash), out,
                       GQ_TLS12_VERIFY_LEN);
}

int
gq_tls12_exporter (enum gq_hash hash,
                   const uint8_t master[GQ_TLS12_MASTER_LEN],
                   const uint8_t client_random[32],
                   const uint8_t server_random[32], const char *label,
                   const uint8_t *context, size_t context_len, uint8_t *out,
                   size_t out_len)
{
  uint8_t seed[64 + 2 + 256];
  size_t n = 64;

  if (label == NULL || (context == NULL && context_len > 0))
    return GQ_ERR_INVAL;
  /* RFC 5705 section 4: exporter labels must not collide with the
     handshake's own PRF labels.  */
  if (!strcmp (label, "master secret") || !strcmp (label, "key expansion")
      || !strcmp (label, "client finished") || !strcmp (label, "server finished")
      || !strcmp (label, "extended master secret"))
    return GQ_ERR_INVAL;
  if (context_len > 256 || context_len > 0xffff)
    return GQ_ERR_RANGE;
  memcpy (seed, client_random, 32);
  memcpy (seed + 32, server_random, 32);
  if (context)
    {
      seed[n++] = (uint8_t) (context_len >> 8);
      seed[n++] = (uint8_t) context_len;
      memcpy (seed + n, context, context_len);
      n += context_len;
    }
  return gq_tls12_prf (hash, master, GQ_TLS12_MASTER_LEN, label, seed, n, out,
                       out_len);
}
