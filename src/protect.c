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
#include <gnuquic/packet.h>
#include <gnuquic/protect.h>

#include "version.h"

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* ------------------------------------------------------------------ */
/* Key derivation                                                     */
/* ------------------------------------------------------------------ */

void
gq_packet_keys_wipe (gq_packet_keys *k)
{
  gq_wipe (k, sizeof *k);
}

int
gq_packet_keys_derive (uint32_t version, enum gq_aead aead,
                       const uint8_t *secret, size_t secret_len,
                       gq_packet_keys *k)
{
  const struct gq_version_info *vi = gq_version_lookup (version);
  enum gq_hash h = gq_aead_hash (aead);
  size_t kl = gq_aead_key_size (aead);

  if (vi == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (kl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (secret == NULL || k == NULL || secret_len != gq_hash_size (h))
    return GQ_ERR_INVAL;

  memset (k, 0, sizeof *k);
  k->aead = aead;
  TRY (gq_hkdf_expand_label (h, secret, secret_len, vi->label_key,
                             NULL, 0, k->key, kl));
  TRY (gq_hkdf_expand_label (h, secret, secret_len, vi->label_iv, NULL, 0,
                             k->iv, GQ_AEAD_NONCE_LEN));
  return gq_hkdf_expand_label (h, secret, secret_len, vi->label_hp, NULL,
                               0, k->hp, kl);
}

int
gq_initial_secrets (uint32_t version, const uint8_t *dcid, size_t dcid_len,
                    uint8_t client[GQ_INITIAL_SECRET_LEN],
                    uint8_t server[GQ_INITIAL_SECRET_LEN])
{
  const struct gq_version_info *vi = gq_version_lookup (version);
  uint8_t initial[32];
  int r;

  if (vi == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (dcid_len > 255 || (dcid == NULL && dcid_len > 0))
    return GQ_ERR_INVAL;

  r = gq_hkdf_extract (GQ_HASH_SHA256, vi->initial_salt,
                       sizeof vi->initial_salt, dcid, dcid_len, initial,
                       sizeof initial);
  if (r == GQ_OK && client)
    r = gq_hkdf_expand_label (GQ_HASH_SHA256, initial, sizeof initial,
                              "client in", NULL, 0, client,
                              GQ_INITIAL_SECRET_LEN);
  if (r == GQ_OK && server)
    r = gq_hkdf_expand_label (GQ_HASH_SHA256, initial, sizeof initial,
                              "server in", NULL, 0, server,
                              GQ_INITIAL_SECRET_LEN);
  gq_wipe (initial, sizeof initial);
  return r;
}

int
gq_packet_keys_initial (uint32_t version, const uint8_t *dcid,
                        size_t dcid_len, gq_packet_keys *client,
                        gq_packet_keys *server)
{
  uint8_t cs[GQ_INITIAL_SECRET_LEN], ss[GQ_INITIAL_SECRET_LEN];
  int r = gq_initial_secrets (version, dcid, dcid_len, cs, ss);

  if (r == GQ_OK && client)
    r = gq_packet_keys_derive (version, GQ_AEAD_AES_128_GCM, cs,
                               sizeof cs, client);
  if (r == GQ_OK && server)
    r = gq_packet_keys_derive (version, GQ_AEAD_AES_128_GCM, ss,
                               sizeof ss, server);
  gq_wipe (cs, sizeof cs);
  gq_wipe (ss, sizeof ss);
  return r;
}

int
gq_packet_keys_update (uint32_t version, const gq_packet_keys *cur,
                       const uint8_t *secret, size_t secret_len,
                       uint8_t *next_secret, gq_packet_keys *next)
{
  const struct gq_version_info *vi = gq_version_lookup (version);
  enum gq_hash h;
  int r;

  if (vi == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (cur == NULL || secret == NULL || next_secret == NULL || next == NULL)
    return GQ_ERR_INVAL;
  h = gq_aead_hash (cur->aead);
  if (secret_len != gq_hash_size (h))
    return GQ_ERR_INVAL;

  r = gq_hkdf_expand_label (h, secret, secret_len, vi->label_ku, NULL, 0,
                            next_secret, secret_len);
  if (r == GQ_OK)
    {
      uint8_t hp[32];

      memcpy (hp, cur->hp, sizeof hp);	/* CUR and NEXT may alias.  */
      r = gq_packet_keys_derive (version, cur->aead, next_secret,
                                 secret_len, next);
      memcpy (next->hp, hp, sizeof hp);
      gq_wipe (hp, sizeof hp);
    }
  return r;
}

/* ------------------------------------------------------------------ */
/* Packet protection                                                  */
/* ------------------------------------------------------------------ */

/* Nonce is the IV with the packet number XORed into its low 8 bytes
   (RFC 9001 section 5.3).  */
static void
make_nonce (const gq_packet_keys *k, uint64_t pn, uint8_t nonce[GQ_AEAD_NONCE_LEN])
{
  size_t i;

  memcpy (nonce, k->iv, GQ_AEAD_NONCE_LEN);
  for (i = 0; i < 8; i++)
    nonce[GQ_AEAD_NONCE_LEN - 1 - i] ^= (uint8_t) (pn >> (8 * i));
}

/* Apply or remove the header protection mask.  Long headers protect the
   low 4 bits of the first byte, short headers the low 5.  The mask is a
   plain XOR, so the same code serves both directions; on removal the
   packet number length is only known after unmasking the first byte.  */
static int
hp_mask (const gq_packet_keys *k, uint8_t *pkt, size_t pn_offset,
         size_t *pn_len, int removing)
{
  uint8_t mask[GQ_HP_MASK_LEN];
  size_t i, n;

  TRY (gq_hp_mask (k->aead, k->hp, gq_aead_key_size (k->aead),
                   pkt + pn_offset + 4, mask));
  pkt[0] ^= mask[0] & ((pkt[0] & 0x80) ? 0x0f : 0x1f);
  if (removing)
    *pn_len = (size_t) (pkt[0] & 3) + 1;
  n = *pn_len;
  for (i = 0; i < n; i++)
    pkt[pn_offset + i] ^= mask[1 + i];
  return GQ_OK;
}

int
gq_packet_seal (const gq_packet_keys *k, uint64_t pn, uint8_t *pkt,
                size_t pn_offset, size_t pn_len, size_t payload_len,
                size_t cap, size_t *out_len)
{
  size_t hdr = pn_offset + pn_len;
  uint8_t nonce[GQ_AEAD_NONCE_LEN];
  int r;

  if (k == NULL || pkt == NULL || out_len == NULL || pn_len < 1
      || pn_len > 4 || pn_offset == 0)
    return GQ_ERR_INVAL;
  if (payload_len < 4 - pn_len)
    return GQ_ERR_RANGE;	/* Too short to sample; add padding.  */
  if (cap < hdr + payload_len + GQ_AEAD_TAG_LEN)
    return GQ_ERR_BUFSIZE;

  make_nonce (k, pn, nonce);
  r = gq_aead_seal (k->aead, k->key, gq_aead_key_size (k->aead), nonce,
                    pkt, hdr, pkt + hdr, payload_len, pkt + hdr,
                    payload_len + GQ_AEAD_TAG_LEN);
  if (r == GQ_OK)
    r = hp_mask (k, pkt, pn_offset, &pn_len, 0);
  if (r == GQ_OK)
    *out_len = hdr + payload_len + GQ_AEAD_TAG_LEN;
  return r;
}

int
gq_hp_remove (const gq_packet_keys *k, uint8_t *pkt, size_t len,
              size_t pn_offset, size_t *pn_len)
{
  if (k == NULL || pkt == NULL || pn_len == NULL || pn_offset == 0)
    return GQ_ERR_INVAL;
  if (len < pn_offset + 4 + GQ_HP_SAMPLE_LEN)
    return GQ_ERR_ENCODING;
  return hp_mask (k, pkt, pn_offset, pn_len, 1);
}

int
gq_packet_decrypt (const gq_packet_keys *k, uint64_t full_pn, uint8_t *pkt,
                   size_t len, size_t pn_offset, size_t pn_len,
                   size_t *payload_off, size_t *payload_len)
{
  size_t hdr = pn_offset + pn_len;
  uint8_t nonce[GQ_AEAD_NONCE_LEN];
  unsigned reserved;
  int r;

  if (k == NULL || pkt == NULL || payload_off == NULL || payload_len == NULL
      || pn_len < 1 || pn_len > 4)
    return GQ_ERR_INVAL;
  if (len < hdr + GQ_AEAD_TAG_LEN)
    return GQ_ERR_ENCODING;

  make_nonce (k, full_pn, nonce);
  r = gq_aead_open (k->aead, k->key, gq_aead_key_size (k->aead), nonce,
                    pkt, hdr, pkt + hdr, len - hdr, pkt + hdr,
                    len - hdr - GQ_AEAD_TAG_LEN);
  if (r != GQ_OK)
    return r;

  *payload_off = hdr;
  *payload_len = len - hdr - GQ_AEAD_TAG_LEN;
  reserved = (pkt[0] & 0x80) ? (pkt[0] & 0x0c) : (pkt[0] & 0x18);
  return reserved ? GQ_ERR_ENCODING : GQ_OK;
}

int
gq_packet_open (const gq_packet_keys *k, int have_largest,
                uint64_t largest_received, uint8_t *pkt, size_t len,
                size_t pn_offset, uint64_t *pn, size_t *payload_off,
                size_t *payload_len)
{
  size_t pn_len, i;
  uint64_t truncated = 0, full;

  if (pn == NULL)
    return GQ_ERR_INVAL;
  TRY (gq_hp_remove (k, pkt, len, pn_offset, &pn_len));
  for (i = 0; i < pn_len; i++)
    truncated = (truncated << 8) | pkt[pn_offset + i];
  full = gq_pn_decode (have_largest, largest_received, truncated, pn_len);
  *pn = full;
  return gq_packet_decrypt (k, full, pkt, len, pn_offset, pn_len,
                            payload_off, payload_len);
}

/* ------------------------------------------------------------------ */
/* Retry                                                              */
/* ------------------------------------------------------------------ */

/* The pseudo-packet used as associated data is the ODCID (length
   prefixed) followed by the Retry packet without its tag.  Retry
   packets are small; refuse anything that does not fit.  */
#define RETRY_PSEUDO_MAX 2048

int
gq_retry_tag (uint32_t version, const uint8_t *odcid, size_t odcid_len,
              const uint8_t *retry_no_tag, size_t len,
              uint8_t tag[GQ_RETRY_TAG_LEN])
{
  const struct gq_version_info *vi = gq_version_lookup (version);
  uint8_t pseudo[RETRY_PSEUDO_MAX];

  if (vi == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (odcid_len > GQ_MAX_CID_LEN || (odcid == NULL && odcid_len > 0)
      || retry_no_tag == NULL || tag == NULL)
    return GQ_ERR_INVAL;
  if (1 + odcid_len + len > sizeof pseudo)
    return GQ_ERR_RANGE;

  pseudo[0] = (uint8_t) odcid_len;
  if (odcid_len)
    memcpy (pseudo + 1, odcid, odcid_len);
  memcpy (pseudo + 1 + odcid_len, retry_no_tag, len);

  /* The key and nonce are public constants; this AEAD is an integrity
     check against corruption and off-path forgery, not a secret.  */
  return gq_aead_seal (GQ_AEAD_AES_128_GCM, vi->retry_key,
                       sizeof vi->retry_key, vi->retry_nonce, pseudo,
                       1 + odcid_len + len, NULL, 0, tag, GQ_RETRY_TAG_LEN);
}

int
gq_retry_build (uint32_t version, const uint8_t *dcid, size_t dcid_len,
                const uint8_t *scid, size_t scid_len, const uint8_t *token,
                size_t token_len, const uint8_t *odcid, size_t odcid_len,
                uint8_t unused_bits, uint8_t *out, size_t cap,
                size_t *written)
{
  const struct gq_version_info *vi = gq_version_lookup (version);
  size_t off = 0;

  if (vi == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (dcid_len > GQ_MAX_CID_LEN || scid_len > GQ_MAX_CID_LEN
      || token_len == 0 || token == NULL || written == NULL
      || (dcid == NULL && dcid_len > 0) || (scid == NULL && scid_len > 0))
    return GQ_ERR_INVAL;
  if (cap < 7 + dcid_len + scid_len + token_len + GQ_RETRY_TAG_LEN)
    return GQ_ERR_BUFSIZE;

  out[off++] = (uint8_t) (0xc0 | (vi->type_bits[3] << 4) | (unused_bits & 0x0f));
  out[off++] = (uint8_t) (version >> 24);
  out[off++] = (uint8_t) (version >> 16);
  out[off++] = (uint8_t) (version >> 8);
  out[off++] = (uint8_t) version;
  out[off++] = (uint8_t) dcid_len;
  if (dcid_len)
    memcpy (out + off, dcid, dcid_len);
  off += dcid_len;
  out[off++] = (uint8_t) scid_len;
  if (scid_len)
    memcpy (out + off, scid, scid_len);
  off += scid_len;
  memcpy (out + off, token, token_len);
  off += token_len;

  TRY (gq_retry_tag (version, odcid, odcid_len, out, off, out + off));
  *written = off + GQ_RETRY_TAG_LEN;
  return GQ_OK;
}

int
gq_retry_verify (const gq_long_header *h, const uint8_t *pkt, size_t len,
                 const uint8_t *odcid, size_t odcid_len)
{
  uint8_t tag[GQ_RETRY_TAG_LEN];

  if (h == NULL || h->type != GQ_PKT_RETRY || pkt == NULL
      || len < GQ_RETRY_TAG_LEN)
    return GQ_ERR_INVAL;
  TRY (gq_retry_tag (h->version, odcid, odcid_len, pkt,
                     len - GQ_RETRY_TAG_LEN, tag));
  return gq_ct_equal (tag, pkt + len - GQ_RETRY_TAG_LEN, GQ_RETRY_TAG_LEN)
    ? GQ_OK : GQ_ERR_CRYPTO;
}
