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

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* Derive-Secret (RFC 8446 section 7.1): expand-label with a transcript
   hash as context.  */
static int
derive_secret (const gq_ks *ks, const char *label, const uint8_t *th,
               uint8_t *out)
{
  return gq_hkdf_expand_label_v (ks->hash, ks->dtls, ks->secret, ks->hlen,
                                 label, th, ks->hlen, out, ks->hlen);
}

/* Hash of the empty string, the transcript for the "derived" steps.  */
static int
empty_hash (const gq_ks *ks, uint8_t *out)
{
  return gq_hash_compute (ks->hash, "", 0, out, ks->hlen);
}

int
gq_ks_early_v (gq_ks *ks, enum gq_hash hash, const uint8_t *psk,
               size_t psk_len, int dtls)
{
  static const uint8_t zeros[GQ_MAX_HASH_LEN];
  size_t hl = gq_hash_size (hash);

  if (ks == NULL)
    return GQ_ERR_INVAL;
  if (hl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (psk == NULL ? psk_len != 0 : psk_len != hl)
    return GQ_ERR_INVAL;
  memset (ks, 0, sizeof *ks);
  ks->hash = hash;
  ks->hlen = hl;
  ks->dtls = dtls != 0;
  ks->stage = GQ_KS_EARLY;
  /* Salt is zeros: an empty salt in HKDF-Extract is exactly that.  */
  return gq_hkdf_extract (hash, NULL, 0, psk ? psk : zeros, hl,
                          ks->secret, hl);
}

int
gq_ks_early (gq_ks *ks, enum gq_hash hash, const uint8_t *psk, size_t psk_len)
{
  return gq_ks_early_v (ks, hash, psk, psk_len, 0);
}

int
gq_ks_binder_key (const gq_ks *ks, int resumption, uint8_t *out)
{
  uint8_t eh[GQ_MAX_HASH_LEN];

  if (ks == NULL || out == NULL || ks->stage != GQ_KS_EARLY)
    return GQ_ERR_INVAL;
  TRY (empty_hash (ks, eh));
  return derive_secret (ks, resumption ? "res binder" : "ext binder", eh, out);
}

int
gq_ks_client_early_traffic (const gq_ks *ks, const uint8_t *hello_hash,
                            uint8_t *out)
{
  if (ks == NULL || hello_hash == NULL || out == NULL
      || ks->stage != GQ_KS_EARLY)
    return GQ_ERR_INVAL;
  return derive_secret (ks, "c e traffic", hello_hash, out);
}

/* Replace the current secret by HKDF-Extract (Derive-Secret (current,
   "derived", ""), ikm).  */
static int
advance (gq_ks *ks, const uint8_t *ikm, size_t ikm_len)
{
  uint8_t eh[GQ_MAX_HASH_LEN], derived[GQ_MAX_HASH_LEN];
  int r;

  r = empty_hash (ks, eh);
  if (r == GQ_OK)
    r = derive_secret (ks, "derived", eh, derived);
  if (r == GQ_OK)
    r = gq_hkdf_extract (ks->hash, derived, ks->hlen, ikm, ikm_len,
                         ks->secret, ks->hlen);
  gq_wipe (derived, sizeof derived);
  return r;
}

int
gq_ks_handshake (gq_ks *ks, const uint8_t *shared, size_t shared_len)
{
  static const uint8_t zeros[GQ_MAX_HASH_LEN];

  if (ks == NULL || ks->stage != GQ_KS_EARLY
      || (shared == NULL && shared_len != 0))
    return GQ_ERR_INVAL;
  if (shared == NULL)
    {
      shared = zeros;
      shared_len = ks->hlen;
    }
  TRY (advance (ks, shared, shared_len));
  ks->stage = GQ_KS_HANDSHAKE;
  return GQ_OK;
}

int
gq_ks_handshake_traffic (const gq_ks *ks, const uint8_t *hello_hash,
                         uint8_t *client, uint8_t *server)
{
  if (ks == NULL || hello_hash == NULL || ks->stage != GQ_KS_HANDSHAKE)
    return GQ_ERR_INVAL;
  if (client)
    TRY (derive_secret (ks, "c hs traffic", hello_hash, client));
  if (server)
    TRY (derive_secret (ks, "s hs traffic", hello_hash, server));
  return GQ_OK;
}

int
gq_ks_master (gq_ks *ks)
{
  static const uint8_t zeros[GQ_MAX_HASH_LEN];

  if (ks == NULL || ks->stage != GQ_KS_HANDSHAKE)
    return GQ_ERR_INVAL;
  TRY (advance (ks, zeros, ks->hlen));
  ks->stage = GQ_KS_MASTER;
  return GQ_OK;
}

int
gq_ks_app_traffic (const gq_ks *ks, const uint8_t *fin_hash, uint8_t *client,
                   uint8_t *server)
{
  if (ks == NULL || fin_hash == NULL || ks->stage != GQ_KS_MASTER)
    return GQ_ERR_INVAL;
  if (client)
    TRY (derive_secret (ks, "c ap traffic", fin_hash, client));
  if (server)
    TRY (derive_secret (ks, "s ap traffic", fin_hash, server));
  return GQ_OK;
}

int
gq_ks_exporter_master (const gq_ks *ks, const uint8_t *fin_hash, uint8_t *out)
{
  if (ks == NULL || fin_hash == NULL || out == NULL
      || ks->stage != GQ_KS_MASTER)
    return GQ_ERR_INVAL;
  return derive_secret (ks, "exp master", fin_hash, out);
}

int
gq_ks_resumption_master (const gq_ks *ks, const uint8_t *fin_hash,
                         uint8_t *out)
{
  if (ks == NULL || fin_hash == NULL || out == NULL
      || ks->stage != GQ_KS_MASTER)
    return GQ_ERR_INVAL;
  return derive_secret (ks, "res master", fin_hash, out);
}

void
gq_ks_wipe (gq_ks *ks)
{
  gq_wipe (ks, sizeof *ks);
}

static int
finished_key (enum gq_hash hash, int dtls, const uint8_t *base, uint8_t *out)
{
  size_t hl = gq_hash_size (hash);

  if (hl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (base == NULL || out == NULL)
    return GQ_ERR_INVAL;
  return gq_hkdf_expand_label_v (hash, dtls, base, hl, "finished", NULL, 0,
                                 out, hl);
}

int
gq_finished_key (enum gq_hash hash, const uint8_t *base, uint8_t *out)
{
  return finished_key (hash, 0, base, out);
}

int
gq_finished_verify_data_v (enum gq_hash hash, int dtls, const uint8_t *base,
                           const uint8_t *th, uint8_t *out)
{
  uint8_t fk[GQ_MAX_HASH_LEN];
  size_t hl = gq_hash_size (hash);
  int r;

  if (th == NULL)
    return GQ_ERR_INVAL;
  r = finished_key (hash, dtls, base, fk);
  if (r == GQ_OK)
    r = gq_hmac (hash, fk, hl, th, hl, out, hl);
  gq_wipe (fk, sizeof fk);
  return r;
}

int
gq_finished_verify_data (enum gq_hash hash, const uint8_t *base,
                         const uint8_t *th, uint8_t *out)
{
  return gq_finished_verify_data_v (hash, 0, base, th, out);
}

int
gq_traffic_secret_update_v (enum gq_hash hash, int dtls,
                            const uint8_t *secret, uint8_t *next)
{
  size_t hl = gq_hash_size (hash);

  if (hl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (secret == NULL || next == NULL)
    return GQ_ERR_INVAL;
  return gq_hkdf_expand_label_v (hash, dtls, secret, hl, "traffic upd", NULL,
                                 0, next, hl);
}

int
gq_traffic_secret_update (enum gq_hash hash, const uint8_t *secret,
                          uint8_t *next)
{
  return gq_traffic_secret_update_v (hash, 0, secret, next);
}

static int
traffic_keys (enum gq_aead aead, int dtls, const uint8_t *secret, uint8_t *key,
              uint8_t iv[GQ_AEAD_NONCE_LEN])
{
  enum gq_hash h = gq_aead_hash (aead);
  size_t kl = gq_aead_key_size (aead), hl = gq_hash_size (h);

  if (kl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (secret == NULL || key == NULL || iv == NULL)
    return GQ_ERR_INVAL;
  TRY (gq_hkdf_expand_label_v (h, dtls, secret, hl, "key", NULL, 0, key, kl));
  return gq_hkdf_expand_label_v (h, dtls, secret, hl, "iv", NULL, 0, iv,
                                 GQ_AEAD_NONCE_LEN);
}

int
gq_traffic_keys (enum gq_aead aead, const uint8_t *secret, uint8_t *key,
                 uint8_t iv[GQ_AEAD_NONCE_LEN])
{
  return traffic_keys (aead, 0, secret, key, iv);
}

int
gq_traffic_keys_dtls (enum gq_aead aead, const uint8_t *secret, uint8_t *key,
                      uint8_t iv[GQ_AEAD_NONCE_LEN], uint8_t *sn_key)
{
  enum gq_hash h = gq_aead_hash (aead);

  TRY (traffic_keys (aead, 1, secret, key, iv));
  if (sn_key == NULL)
    return GQ_ERR_INVAL;
  /* Record number encryption key (RFC 9147 section 4.2.3).  */
  return gq_hkdf_expand_label_v (h, 1, secret, gq_hash_size (h), "sn", NULL,
                                 0, sn_key, gq_aead_key_size (aead));
}

int
gq_resumption_psk_v (enum gq_hash hash, int dtls, const uint8_t *res_master,
                     const uint8_t *nonce, size_t nonce_len, uint8_t *out)
{
  size_t hl = gq_hash_size (hash);

  if (hl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (res_master == NULL || out == NULL || (nonce == NULL && nonce_len))
    return GQ_ERR_INVAL;
  return gq_hkdf_expand_label_v (hash, dtls, res_master, hl, "resumption",
                                 nonce, nonce_len, out, hl);
}

int
gq_resumption_psk (enum gq_hash hash, const uint8_t *res_master,
                   const uint8_t *nonce, size_t nonce_len, uint8_t *out)
{
  return gq_resumption_psk_v (hash, 0, res_master, nonce, nonce_len, out);
}
