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

/* TLS 1.2 record layer: framing, both AEAD constructions, and everything
   the receiver must refuse.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/record12.h>

#include "tst-util.h"

struct sink
{
  uint8_t data[70000];
  size_t n;
  int calls;
  unsigned last_type;
};

static int
on_rec (void *u, unsigned type, const uint8_t *d, size_t n)
{
  struct sink *s = u;

  memcpy (s->data + s->n, d, n);
  s->n += n;
  s->calls++;
  s->last_type = type;
  return 0;
}

static void
keys (gq_record12 *w, gq_record12 *r, enum gq_aead aead)
{
  uint8_t key[32], iv[12];
  size_t kl = gq_aead_key_size (aead), il = aead == GQ_AEAD_CHACHA20_POLY1305 ? 12 : 4, i;

  for (i = 0; i < 32; i++)
    key[i] = (uint8_t) (i * 7 + 1);
  for (i = 0; i < 12; i++)
    iv[i] = (uint8_t) (0xa0 + i);
  CHECK_EQ (gq_record12_set_keys (w, GQ_DIR_WRITE, aead, key, kl, iv, il), GQ_OK);
  CHECK_EQ (gq_record12_set_keys (r, GQ_DIR_READ, aead, key, kl, iv, il), GQ_OK);
}

static void
test_plaintext (void)
{
  gq_record12 w, r;
  uint8_t out[64], *p;
  size_t n, l;
  struct sink s;

  gq_record12_init (&w);
  gq_record12_init (&r);
  memset (&s, 0, sizeof s);
  CHECK_EQ (gq_record12_protect (&w, GQ_CT_HANDSHAKE, (const uint8_t *) "abc", 3,
                                 out, sizeof out, &n), GQ_OK);
  CHECK (n == 8 && out[0] == 22 && out[1] == 3 && out[2] == 3 && out[4] == 3);
  p = out;
  l = n;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, &s), GQ_OK);
  CHECK (s.n == 3 && memcmp (s.data, "abc", 3) == 0 && l == 0);

  /* No application data before keys, in either direction.  */
  out[0] = 23;
  p = out;
  l = n;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, &s), GQ_ERR_PROTOCOL);
  CHECK_EQ (gq_record12_alert (&r), 10);
}

static void
test_roundtrip (enum gq_aead aead)
{
  gq_record12 w, r;
  static uint8_t out[GQ_REC12_MAX_RECORD], pt[16384];
  uint8_t ccs = 1;
  size_t n, l, i;
  uint8_t *p;
  struct sink *s = calloc (1, sizeof *s);

  gq_record12_init (&w);
  gq_record12_init (&r);
  keys (&w, &r, aead);
  for (i = 0; i < sizeof pt; i++)
    pt[i] = (uint8_t) i;

  /* Sizes from empty to the maximum; sequence numbers advance.  */
  {
    static const size_t sizes[] = { 0, 1, 15, 16, 17, 1000, 16384 };

    for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++)
      {
        s->n = 0;
        CHECK_EQ (gq_record12_protect (&w, GQ_CT_APPLICATION_DATA, pt, sizes[i],
                                       out, sizeof out, &n), GQ_OK);
        CHECK (n == GQ_REC_HEADER_LEN + sizes[i] + 16
                    + (aead == GQ_AEAD_CHACHA20_POLY1305 ? 0 : 8));
        p = out;
        l = n;
        CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_OK);
        CHECK (l == 0 && s->n == sizes[i] && memcmp (s->data, pt, sizes[i]) == 0);
      }
    CHECK_EQ (gq_record12_write_seq (&w), (long long) (sizeof sizes / sizeof sizes[0]));
    CHECK_EQ (gq_record12_read_seq (&r), (long long) (sizeof sizes / sizeof sizes[0]));
  }

  /* Too large a plaintext is refused.  */
  CHECK_EQ (gq_record12_protect (&w, GQ_CT_APPLICATION_DATA, pt, 16385, out,
                                 sizeof out, &n), GQ_ERR_INVAL);

  /* ChangeCipherSpec is never protected, and one after keys is refused.  */
  CHECK_EQ (gq_record12_protect (&w, GQ_CT_CHANGE_CIPHER_SPEC, &ccs, 1, out,
                                 sizeof out, &n), GQ_OK);
  CHECK (n == 6 && out[0] == 20);
  p = out;
  l = n;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_ERR_PROTOCOL);

  /* Every single-bit change to a record is caught: header (via the AAD),
     explicit nonce, ciphertext and tag.  */
  {
    gq_record12 w2, r2;
    size_t bit, total;

    gq_record12_init (&w2);
    keys (&w2, &r2, aead);
    CHECK_EQ (gq_record12_protect (&w2, GQ_CT_HANDSHAKE, pt, 20, out,
                                   sizeof out, &total), GQ_OK);
    for (bit = 0; bit < total * 8; bit++)
      {
        uint8_t copy[64];
        size_t cl = total;
        uint8_t *cp = copy;
        int rc;

        /* The length bytes change framing rather than content: skip.  */
        if (bit / 8 == 3 || bit / 8 == 4)
          continue;
        memcpy (copy, out, total);
        copy[bit / 8] ^= (uint8_t) (1 << (bit % 8));
        gq_record12_init (&r2);
        keys (&w2, &r2, aead);
        s->n = 0;
        rc = gq_record12_receive (&r2, &cp, &cl, on_rec, s);
        /* A flipped explicit nonce changes the AEAD nonce, so it fails as
           well (except for ChaCha20, which has none).  A flipped version
           minor byte is a protocol_version error.  */
        CHECK (rc != GQ_OK);
        CHECK (s->n == 0);
      }
  }

  /* Record replayed under a later sequence number does not verify.  */
  {
    gq_record12 w2, r2;
    size_t m;

    gq_record12_init (&w2);
    keys (&w2, &r2, aead);
    CHECK_EQ (gq_record12_protect (&w2, GQ_CT_APPLICATION_DATA, pt, 5, out,
                                   sizeof out, &m), GQ_OK);
    p = out;
    l = m;
    CHECK_EQ (gq_record12_receive (&r2, &p, &l, on_rec, s), GQ_OK);
    p = out;
    l = m;
    CHECK_EQ (gq_record12_receive (&r2, &p, &l, on_rec, s), GQ_ERR_CRYPTO);
    CHECK_EQ (gq_record12_alert (&r2), 20);
  }
  free (s);
}

static void
test_chunking (void)
{
  gq_record12 w, r;
  static uint8_t wire[3 * 200];
  uint8_t rec[200], buf[600];
  size_t n, off = 0, l, chunk, k;
  struct sink *s = calloc (1, sizeof *s);

  gq_record12_init (&w);
  keys (&w, &r, GQ_AEAD_AES_128_GCM);
  for (k = 0; k < 3; k++)
    {
      uint8_t msg[40];

      memset (msg, (int) ('a' + k), sizeof msg);
      CHECK_EQ (gq_record12_protect (&w, GQ_CT_HANDSHAKE, msg, sizeof msg, rec,
                                     sizeof rec, &n), GQ_OK);
      memcpy (wire + off, rec, n);
      off += n;
    }
  /* Feeding one byte to any chunk size gives the same events.  */
  for (chunk = 1; chunk < off; chunk += 7)
    {
      size_t pos = 0, have = 0;

      gq_record12_init (&r);
      keys (&w, &r, GQ_AEAD_AES_128_GCM);
      s->n = 0;
      s->calls = 0;
      while (pos < off)
        {
          uint8_t *p = buf;
          size_t take = off - pos < chunk ? off - pos : chunk;
          int rc;

          memcpy (buf + have, wire + pos, take);
          have += take;
          pos += take;
          l = have;
          rc = gq_record12_receive (&r, &p, &l, on_rec, s);
          CHECK (rc == GQ_OK || rc == GQ_NEED_MORE);
          memmove (buf, p, l);
          have = l;
        }
      CHECK (s->calls == 3 && s->n == 120 && have == 0);
    }
  free (s);
}

static void
test_headers (void)
{
  gq_record12 r;
  struct sink *s = calloc (1, sizeof *s);
  uint8_t h[5 + 4] = { 22, 3, 3, 0, 4, 1, 2, 3, 4 };
  uint8_t *p;
  size_t l;

  /* The first record may say 0x0301 (a ClientHello); later ones may not.  */
  gq_record12_init (&r);
  h[2] = 1;
  p = h; l = sizeof h;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_OK);
  p = h; l = sizeof h;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_ERR_PROTOCOL);
  CHECK_EQ (gq_record12_alert (&r), 70);

  /* SSL 3.0, TLS 1.3-style, and non-TLS bytes.  */
  gq_record12_init (&r);
  h[1] = 3; h[2] = 0;
  p = h; l = sizeof h;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_ERR_PROTOCOL);
  gq_record12_init (&r);
  h[1] = 4; h[2] = 3;
  p = h; l = sizeof h;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_ERR_PROTOCOL);
  gq_record12_init (&r);
  h[0] = 99; h[1] = 3; h[2] = 3;
  p = h; l = sizeof h;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_ERR_PROTOCOL);

  /* Oversized declared length, empty handshake and alert, bad CCS.  */
  gq_record12_init (&r);
  h[0] = 22; h[3] = 0x40; h[4] = 0x01;
  p = h; l = sizeof h;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_ERR_PROTOCOL);
  CHECK_EQ (gq_record12_alert (&r), 22);
  gq_record12_init (&r);
  h[3] = 0; h[4] = 0;
  p = h; l = 5;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_ERR_PROTOCOL);
  gq_record12_init (&r);
  h[0] = 20; h[3] = 0; h[4] = 1; h[5] = 2;
  p = h; l = 6;
  CHECK_EQ (gq_record12_receive (&r, &p, &l, on_rec, s), GQ_ERR_PROTOCOL);
  CHECK_EQ (gq_record12_alert (&r), 50);
  free (s);
}

static void
test_limits (void)
{
  gq_record12 w, r;
  uint8_t out[64];
  size_t n;

  /* AES-GCM stops at the record limit; ChaCha20-Poly1305 does not.  */
  gq_record12_init (&w);
  keys (&w, &r, GQ_AEAD_AES_128_GCM);
  w.write.seq = GQ_REC12_SEQ_LIMIT - 1;
  CHECK_EQ (gq_record12_protect (&w, GQ_CT_APPLICATION_DATA, (const uint8_t *) "x",
                                 1, out, sizeof out, &n), GQ_OK);
  CHECK_EQ (gq_record12_protect (&w, GQ_CT_APPLICATION_DATA, (const uint8_t *) "x",
                                 1, out, sizeof out, &n), GQ_ERR_RANGE);
  gq_record12_init (&w);
  keys (&w, &r, GQ_AEAD_CHACHA20_POLY1305);
  w.write.seq = GQ_REC12_SEQ_LIMIT + 5;
  CHECK_EQ (gq_record12_protect (&w, GQ_CT_APPLICATION_DATA, (const uint8_t *) "x",
                                 1, out, sizeof out, &n), GQ_OK);
  w.write.seq = UINT64_MAX;
  CHECK_EQ (gq_record12_protect (&w, GQ_CT_APPLICATION_DATA, (const uint8_t *) "x",
                                 1, out, sizeof out, &n), GQ_ERR_RANGE);

  /* Bad key parameters.  */
  {
    uint8_t k[32] = { 0 }, iv[12] = { 0 };

    CHECK_EQ (gq_record12_set_keys (&w, GQ_DIR_WRITE, GQ_AEAD_AES_128_GCM, k, 16,
                                    iv, 12), GQ_ERR_INVAL);
    CHECK_EQ (gq_record12_set_keys (&w, GQ_DIR_WRITE, GQ_AEAD_AES_128_GCM, k, 32,
                                    iv, 4), GQ_ERR_INVAL);
    CHECK_EQ (gq_record12_set_keys (&w, GQ_DIR_WRITE, (enum gq_aead) 9, k, 16,
                                    iv, 4), GQ_ERR_UNSUPPORTED);
  }
}

int
main (void)
{
  gq_crypto_init ();
  test_plaintext ();
  test_roundtrip (GQ_AEAD_AES_128_GCM);
  test_roundtrip (GQ_AEAD_AES_256_GCM);
  test_roundtrip (GQ_AEAD_CHACHA20_POLY1305);
  test_chunking ();
  test_headers ();
  test_limits ();
  TST_DONE ();
}
