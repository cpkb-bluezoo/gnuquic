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

#include <gcrypt.h>

#include <gnuquic/status.h>
#include <gnuquic/crypto.h>

#include "gettext.h"

#define GQ_MIN_GCRYPT "1.11.0"

void
gq_wipe (void *secret, size_t len)
{
  volatile uint8_t *p = secret;

  while (len--)
    *p++ = 0;
}

int
gq_ct_equal (const void *a, const void *b, size_t n)
{
  const uint8_t *x = a, *y = b;
  uint8_t diff = 0;
  size_t i;

  for (i = 0; i < n; i++)
    diff |= x[i] ^ y[i];
  return diff == 0;
}

int
gq_crypto_init (void)
{
  gqi_i18n_init ();
  if (gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    return GQ_OK;
  if (!gcry_check_version (GQ_MIN_GCRYPT))
    return GQ_ERR_CRYPTO;
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  return GQ_OK;
}

int
gq_random (void *buf, size_t len)
{
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  gcry_randomize (buf, len, GCRY_STRONG_RANDOM);
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Hashes and HMAC                                                    */
/* ------------------------------------------------------------------ */

size_t
gq_hash_size (enum gq_hash alg)
{
  switch (alg)
    {
    case GQ_HASH_SHA256: return 32;
    case GQ_HASH_SHA384: return 48;
    default:             return 0;
    }
}

static int
hash_algo (enum gq_hash alg)
{
  return alg == GQ_HASH_SHA256 ? GCRY_MD_SHA256
       : alg == GQ_HASH_SHA384 ? GCRY_MD_SHA384 : 0;
}

static int
mac_algo (enum gq_hash alg)
{
  return alg == GQ_HASH_SHA256 ? GCRY_MAC_HMAC_SHA256
       : alg == GQ_HASH_SHA384 ? GCRY_MAC_HMAC_SHA384 : 0;
}

int
gq_hash_compute (enum gq_hash alg, const void *data, size_t len,
                 uint8_t *out, size_t outlen)
{
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_hash_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (outlen != gq_hash_size (alg) || (data == NULL && len > 0))
    return GQ_ERR_INVAL;
  gcry_md_hash_buffer (hash_algo (alg), out, data, len);
  return GQ_OK;
}

int
gq_hmac (enum gq_hash alg, const void *key, size_t keylen,
         const void *data, size_t len, uint8_t *out, size_t outlen)
{
  gcry_mac_hd_t h;
  size_t n = outlen;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_hash_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (outlen != gq_hash_size (alg) || (data == NULL && len > 0))
    return GQ_ERR_INVAL;

  if (gcry_mac_open (&h, mac_algo (alg), 0, NULL))
    return GQ_ERR_CRYPTO;
  r = GQ_ERR_CRYPTO;
  if (!gcry_mac_setkey (h, key, keylen)
      && !gcry_mac_write (h, data, len)
      && !gcry_mac_read (h, out, &n) && n == outlen)
    r = GQ_OK;
  gcry_mac_close (h);
  return r;
}

/* ------------------------------------------------------------------ */
/* HKDF                                                               */
/* ------------------------------------------------------------------ */

int
gq_hkdf_extract (enum gq_hash alg, const void *salt, size_t saltlen,
                 const void *ikm, size_t ikmlen,
                 uint8_t *prk, size_t prklen)
{
  uint8_t zeros[64];
  size_t hl = gq_hash_size (alg);

  if (hl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (saltlen == 0)
    {
      memset (zeros, 0, hl);
      salt = zeros;
      saltlen = hl;
    }
  return gq_hmac (alg, salt, saltlen, ikm, ikmlen, prk, prklen);
}

int
gq_hkdf_expand (enum gq_hash alg, const void *prk, size_t prklen,
                const void *info, size_t infolen,
                uint8_t *out, size_t outlen)
{
  gcry_mac_hd_t h;
  uint8_t t[64];
  size_t hl = gq_hash_size (alg);
  size_t done = 0;
  uint8_t counter = 1;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (hl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (prklen < hl || (info == NULL && infolen > 0)
      || outlen > 255 * hl || (out == NULL && outlen > 0))
    return GQ_ERR_INVAL;

  if (gcry_mac_open (&h, mac_algo (alg), 0, NULL))
    return GQ_ERR_CRYPTO;
  if (gcry_mac_setkey (h, prk, prklen))
    {
      gcry_mac_close (h);
      return GQ_ERR_CRYPTO;
    }

  /* T(n) = HMAC (PRK, T(n-1) | info | n).  */
  r = GQ_OK;
  while (done < outlen && r == GQ_OK)
    {
      size_t n = hl;
      size_t take = outlen - done < hl ? outlen - done : hl;

      if (done > 0 && gcry_mac_write (h, t, hl))
        r = GQ_ERR_CRYPTO;
      else if (gcry_mac_write (h, info, infolen)
               || gcry_mac_write (h, &counter, 1)
               || gcry_mac_read (h, t, &n) || n != hl
               || gcry_mac_reset (h))
        r = GQ_ERR_CRYPTO;
      else
        {
          memcpy (out + done, t, take);
          done += take;
          counter++;
        }
    }
  gcry_mac_close (h);
  gq_wipe (t, sizeof t);
  return r;
}

int
gq_hkdf_expand_label_v (enum gq_hash alg, int dtls, const void *secret,
                        size_t secretlen, const char *label,
                        const void *context, size_t contextlen, uint8_t *out,
                        size_t outlen)
{
  /* struct { uint16 length; opaque label<7..255>; opaque context<0..255>; } */
  uint8_t info[2 + 1 + 255 + 1 + 255];
  static const char tls_prefix[] = "tls13 ", dtls_prefix[] = "dtls13";
  const char *prefix = dtls ? dtls_prefix : tls_prefix;
  size_t plen = dtls ? sizeof dtls_prefix - 1 : sizeof tls_prefix - 1;
  size_t llen, off = 0;

  if (label == NULL || outlen > 0xffff || contextlen > 255
      || (context == NULL && contextlen > 0))
    return GQ_ERR_INVAL;
  llen = strlen (label);
  if (plen + llen > 255)
    return GQ_ERR_INVAL;

  info[off++] = (uint8_t) (outlen >> 8);
  info[off++] = (uint8_t) outlen;
  info[off++] = (uint8_t) (plen + llen);
  memcpy (info + off, prefix, plen);
  off += plen;
  memcpy (info + off, label, llen);
  off += llen;
  info[off++] = (uint8_t) contextlen;
  if (contextlen)
    memcpy (info + off, context, contextlen);
  off += contextlen;

  return gq_hkdf_expand (alg, secret, secretlen, info, off, out, outlen);
}

int
gq_hkdf_expand_label (enum gq_hash alg, const void *secret, size_t secretlen,
                      const char *label, const void *context,
                      size_t contextlen, uint8_t *out, size_t outlen)
{
  return gq_hkdf_expand_label_v (alg, 0, secret, secretlen, label, context,
                                 contextlen, out, outlen);
}

/* ------------------------------------------------------------------ */
/* AEAD and header protection                                         */
/* ------------------------------------------------------------------ */

size_t
gq_aead_key_size (enum gq_aead alg)
{
  switch (alg)
    {
    case GQ_AEAD_AES_128_GCM:		return 16;
    case GQ_AEAD_AES_256_GCM:		return 32;
    case GQ_AEAD_CHACHA20_POLY1305:	return 32;
    default:				return 0;
    }
}

enum gq_hash
gq_aead_hash (enum gq_aead alg)
{
  return alg == GQ_AEAD_AES_256_GCM ? GQ_HASH_SHA384 : GQ_HASH_SHA256;
}

static int
aead_open_handle (enum gq_aead alg, gcry_cipher_hd_t *h)
{
  int algo, mode;

  switch (alg)
    {
    case GQ_AEAD_AES_128_GCM:
      algo = GCRY_CIPHER_AES128;
      mode = GCRY_CIPHER_MODE_GCM;
      break;
    case GQ_AEAD_AES_256_GCM:
      algo = GCRY_CIPHER_AES256;
      mode = GCRY_CIPHER_MODE_GCM;
      break;
    case GQ_AEAD_CHACHA20_POLY1305:
      algo = GCRY_CIPHER_CHACHA20;
      mode = GCRY_CIPHER_MODE_POLY1305;
      break;
    default:
      return GQ_ERR_UNSUPPORTED;
    }
  return gcry_cipher_open (h, algo, mode, 0) ? GQ_ERR_CRYPTO : GQ_OK;
}

static int
aead_setup (enum gq_aead alg, gcry_cipher_hd_t *h, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, const void *aad,
            size_t aadlen)
{
  int r = aead_open_handle (alg, h);

  if (r != GQ_OK)
    return r;
  if (gcry_cipher_setkey (*h, key, keylen)
      || gcry_cipher_setiv (*h, nonce, GQ_AEAD_NONCE_LEN)
      || (aadlen > 0 && gcry_cipher_authenticate (*h, aad, aadlen)))
    {
      gcry_cipher_close (*h);
      return GQ_ERR_CRYPTO;
    }
  return GQ_OK;
}

int
gq_aead_seal (enum gq_aead alg, const uint8_t *key, size_t keylen,
              const uint8_t *nonce, const void *aad, size_t aadlen,
              const void *pt, size_t ptlen, uint8_t *out, size_t outlen)
{
  gcry_cipher_hd_t h;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_aead_key_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (keylen != gq_aead_key_size (alg) || key == NULL || nonce == NULL
      || (aad == NULL && aadlen > 0) || (pt == NULL && ptlen > 0)
      || outlen != ptlen + GQ_AEAD_TAG_LEN)
    return GQ_ERR_INVAL;

  r = aead_setup (alg, &h, key, keylen, nonce, aad, aadlen);
  if (r != GQ_OK)
    return r;
  if (ptlen > 0 && gcry_cipher_encrypt (h, out, ptlen, pt, ptlen))
    r = GQ_ERR_CRYPTO;
  else if (gcry_cipher_gettag (h, out + ptlen, GQ_AEAD_TAG_LEN))
    r = GQ_ERR_CRYPTO;
  gcry_cipher_close (h);
  return r;
}

int
gq_aead_open (enum gq_aead alg, const uint8_t *key, size_t keylen,
              const uint8_t *nonce, const void *aad, size_t aadlen,
              const void *ct, size_t ctlen, uint8_t *out, size_t outlen)
{
  gcry_cipher_hd_t h;
  size_t ptlen;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_aead_key_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (ctlen < GQ_AEAD_TAG_LEN)
    return GQ_ERR_CRYPTO;
  ptlen = ctlen - GQ_AEAD_TAG_LEN;
  if (keylen != gq_aead_key_size (alg) || key == NULL || nonce == NULL
      || (aad == NULL && aadlen > 0) || ct == NULL || outlen != ptlen)
    return GQ_ERR_INVAL;

  r = aead_setup (alg, &h, key, keylen, nonce, aad, aadlen);
  if (r != GQ_OK)
    return r;
  if (ptlen > 0 && gcry_cipher_decrypt (h, out, ptlen, ct, ptlen))
    r = GQ_ERR_CRYPTO;
  else if (gcry_cipher_checktag (h, (const uint8_t *) ct + ptlen,
                                 GQ_AEAD_TAG_LEN))
    r = GQ_ERR_CRYPTO;
  gcry_cipher_close (h);
  if (r != GQ_OK && ptlen > 0)
    gq_wipe (out, ptlen);
  return r;
}

int
gq_hp_mask (enum gq_aead alg, const uint8_t *hp_key, size_t keylen,
            const uint8_t sample[GQ_HP_SAMPLE_LEN],
            uint8_t mask[GQ_HP_MASK_LEN])
{
  gcry_cipher_hd_t h;
  uint8_t block[GQ_HP_SAMPLE_LEN];
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_aead_key_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (keylen != gq_aead_key_size (alg) || hp_key == NULL)
    return GQ_ERR_INVAL;

  if (alg == GQ_AEAD_CHACHA20_POLY1305)
    {
      /* Counter is the first four sample bytes (little endian) and the
         nonce the remaining twelve; libgcrypt's ChaCha20 accepts exactly
         that 16-byte layout through setiv.  Encrypting zeros yields the keystream.  */
      static const uint8_t zeros[GQ_HP_MASK_LEN];

      if (gcry_cipher_open (&h, GCRY_CIPHER_CHACHA20,
                            GCRY_CIPHER_MODE_STREAM, 0))
        return GQ_ERR_CRYPTO;
      if (gcry_cipher_setkey (h, hp_key, keylen)
          || gcry_cipher_setiv (h, sample, GQ_HP_SAMPLE_LEN)
          || gcry_cipher_encrypt (h, mask, GQ_HP_MASK_LEN, zeros,
                                  GQ_HP_MASK_LEN))
        r = GQ_ERR_CRYPTO;
      gcry_cipher_close (h);
      return r;
    }

  if (gcry_cipher_open (&h, alg == GQ_AEAD_AES_128_GCM
                            ? GCRY_CIPHER_AES128 : GCRY_CIPHER_AES256,
                        GCRY_CIPHER_MODE_ECB, 0))
    return GQ_ERR_CRYPTO;
  if (gcry_cipher_setkey (h, hp_key, keylen)
      || gcry_cipher_encrypt (h, block, sizeof block, sample,
                              GQ_HP_SAMPLE_LEN))
    r = GQ_ERR_CRYPTO;
  else
    memcpy (mask, block, GQ_HP_MASK_LEN);
  gcry_cipher_close (h);
  gq_wipe (block, sizeof block);
  return r;
}
