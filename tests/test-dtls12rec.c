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

/* DTLS 1.2 record layer: framing, both AEAD constructions, and what the
   receiver must refuse.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/dtls12rec.h>

#include "tst-util.h"

struct log
{
  int n;
  struct { unsigned type; uint16_t epoch; uint64_t seq; size_t body; } e[8];
};

static int
on_rec (void *u, const gq_d12rec *r)
{
  struct log *l = u;

  if (l->n < 8)
    {
      l->e[l->n].type = r->type;
      l->e[l->n].epoch = r->epoch;
      l->e[l->n].seq = r->seq;
      l->e[l->n].body = r->body.len;
      l->n++;
    }
  return 0;
}

static void
test_framing (void)
{
  uint8_t d[200], frag[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  gq_wbuf w;
  gq_dtls12_epoch e0;
  struct log l;
  size_t cut, total;

  gq_dtls12_epoch_plain (&e0);
  e0.send_seq = 0x0102030405ull;
  gq_wbuf_init (&w, d, sizeof d);
  gq_dtls12_put_plain (&w, &e0, GQ_D12_CT_HANDSHAKE, frag, 10);
  gq_dtls12_put_plain (&w, &e0, GQ_D12_CT_CHANGE_CIPHER_SPEC, frag, 1);
  gq_dtls12_put_plain (&w, &e0, GQ_D12_CT_ALERT, frag, 2);
  CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
  total = w.len;
  CHECK_EQ (total, (size_t) (13 * 3 + 13));
  CHECK_EQ (d[0], 22);
  CHECK (d[1] == 0xfe && d[2] == 0xfd && d[3] == 0 && d[4] == 0);
  CHECK_EQ (e0.send_seq, 0x0102030408ull);

  memset (&l, 0, sizeof l);
  CHECK_EQ (gq_dtls12_records (d, total, on_rec, &l), GQ_OK);
  CHECK_EQ (l.n, 3);
  CHECK (l.e[0].type == 22 && l.e[0].seq == 0x0102030405ull && l.e[0].body == 10);
  CHECK (l.e[1].type == 20 && l.e[1].seq == 0x0102030406ull);
  CHECK (l.e[2].type == 21 && l.e[2].epoch == 0);

  /* A prefix ending mid-record delivers the whole records before it.  */
  for (cut = 0; cut < total; cut++)
    {
      int want = cut >= 23 ? (cut >= 37 ? (cut >= 52 ? 3 : 2) : 1) : 0;

      memset (&l, 0, sizeof l);
      CHECK_EQ (gq_dtls12_records (d, cut, on_rec, &l), GQ_OK);
      CHECK_EQ (l.n, want);
    }

  /* Version 0xfeff is allowed (first ClientHello); others skip that record
     only; unknown types skip it too.  */
  d[1] = 0xfe; d[2] = 0xff;
  memset (&l, 0, sizeof l);
  gq_dtls12_records (d, total, on_rec, &l);
  CHECK_EQ (l.n, 3);
  d[1] = 0x03; d[2] = 0x03;		/* A TLS record.  */
  memset (&l, 0, sizeof l);
  gq_dtls12_records (d, total, on_rec, &l);
  CHECK_EQ (l.n, 2);
  d[1] = 0xfe; d[2] = 0xfd; d[0] = 25;
  memset (&l, 0, sizeof l);
  gq_dtls12_records (d, total, on_rec, &l);
  CHECK_EQ (l.n, 2);
}

/* ---- Protection ---- */

static gq_dtls12_epoch tx, rx;

static void
keys (enum gq_aead aead)
{
  uint8_t key[32], iv[12];
  size_t kl = gq_aead_key_size (aead), il, i;

  il = aead == GQ_AEAD_CHACHA20_POLY1305 ? 12 : 4;
  for (i = 0; i < 32; i++)
    key[i] = (uint8_t) (i * 5 + 2);
  for (i = 0; i < 12; i++)
    iv[i] = (uint8_t) (0x90 + i);
  CHECK_EQ (gq_dtls12_epoch_init (&tx, 1, aead, key, kl, iv, il), GQ_OK);
  CHECK_EQ (gq_dtls12_epoch_init (&rx, 1, aead, key, kl, iv, il), GQ_OK);
}

struct one
{
  gq_d12rec rec;
  int got;
};

static int
grab (void *u, const gq_d12rec *r)
{
  struct one *o = u;

  o->rec = *r;
  o->got++;
  return 0;
}

static int
open_one (const uint8_t *d, size_t n, uint8_t *out, size_t *len)
{
  struct one o;

  memset (&o, 0, sizeof o);
  gq_dtls12_records (d, n, grab, &o);
  if (o.got != 1)
    return GQ_ERR_ENCODING;
  return gq_dtls12_deprotect (&rx, &o.rec, out, 4096, len);
}

static void
test_roundtrip (enum gq_aead aead)
{
  uint8_t out[2048], back[2048], pt[1500];
  size_t n, len, i, ov = aead == GQ_AEAD_CHACHA20_POLY1305 ? 16 : 24;

  keys (aead);
  for (i = 0; i < sizeof pt; i++)
    pt[i] = (uint8_t) (i * 7);
  for (i = 0; i < 200; i++)
    {
      size_t plen = (i * 37) % 1400;

      CHECK_EQ (gq_dtls12_protect (&tx, GQ_D12_CT_APPLICATION_DATA, pt, plen,
                                   out, sizeof out, &n), GQ_OK);
      CHECK_EQ (n, 13 + plen + ov);
      CHECK_EQ (open_one (out, n, back, &len), GQ_OK);
      CHECK (len == plen && memcmp (back, pt, plen) == 0);
    }

  /* Every bit of the record (except the length, which re-frames) either
     breaks authentication or is refused: header fields are in the AAD.  */
  keys (aead);
  CHECK_EQ (gq_dtls12_protect (&tx, GQ_D12_CT_HANDSHAKE, pt, 24, out,
                               sizeof out, &n), GQ_OK);
  for (i = 0; i < n * 8; i++)
    {
      uint8_t copy[128];

      if (i / 8 == 11 || i / 8 == 12)
        continue;
      memcpy (copy, out, n);
      copy[i / 8] ^= (uint8_t) (1 << (i % 8));
      keys (aead);
      /* Type and version changes are dropped by the framing, the rest by
         the tag.  */
      CHECK (open_one (copy, n, back, &len) != GQ_OK);
    }

  /* Replay and reordering inside the window; too old.  */
  keys (aead);
  {
    uint8_t rec[10][80];
    size_t rl[10];

    for (i = 0; i < 10; i++)
      CHECK_EQ (gq_dtls12_protect (&tx, 23, pt, 8, rec[i], 80, &rl[i]), GQ_OK);
    CHECK_EQ (open_one (rec[9], rl[9], back, &len), GQ_OK);
    CHECK_EQ (open_one (rec[9], rl[9], back, &len), GQ_ERR_RANGE);
    CHECK_EQ (open_one (rec[2], rl[2], back, &len), GQ_OK);
    CHECK_EQ (open_one (rec[2], rl[2], back, &len), GQ_ERR_RANGE);
  }
  keys (aead);
  {
    uint8_t first[80], later[80];
    size_t fl, ll;

    CHECK_EQ (gq_dtls12_protect (&tx, 23, pt, 4, first, 80, &fl), GQ_OK);
    tx.send_seq = 300;
    CHECK_EQ (gq_dtls12_protect (&tx, 23, pt, 4, later, 80, &ll), GQ_OK);
    CHECK_EQ (open_one (later, ll, back, &len), GQ_OK);
    CHECK_EQ (open_one (first, fl, back, &len), GQ_ERR_RANGE);
  }

  /* Sizes and limits.  */
  keys (aead);
  CHECK_EQ (gq_dtls12_protect (&tx, 23, pt, 1400, out, 100, &n),
            GQ_ERR_BUFSIZE);
  CHECK_EQ (gq_dtls12_protect (&tx, 23, pt, 20000, out, sizeof out, &n),
            GQ_ERR_INVAL);
  tx.send_seq = GQ_DTLS12_SEQ_LIMIT;
  CHECK_EQ (gq_dtls12_protect (&tx, 23, pt, 4, out, 80, &n),
            aead == GQ_AEAD_CHACHA20_POLY1305 ? GQ_OK : GQ_ERR_RANGE);
}

/* A record made by hand from the RFCs, with an explicit nonce that is NOT
   epoch || sequence: the receiver must use the one on the wire.  */
static void
test_wire_nonce (void)
{
  uint8_t rec[128], nonce[12], aad[13], back[64], pt[9] = "explicit";
  size_t len, i;
  uint64_t seq = 0x0000abcdefull;

  keys (GQ_AEAD_AES_128_GCM);
  memcpy (nonce, tx.iv, 4);
  for (i = 0; i < 8; i++)
    nonce[4 + i] = (uint8_t) (0xc0 + i);		/* sender's choice */
  aad[0] = 0; aad[1] = 1;			/* epoch */
  for (i = 0; i < 6; i++)
    aad[2 + i] = (uint8_t) (seq >> (40 - 8 * i));
  aad[8] = 23; aad[9] = 0xfe; aad[10] = 0xfd; aad[11] = 0; aad[12] = 9;
  rec[0] = 23; rec[1] = 0xfe; rec[2] = 0xfd; rec[3] = 0; rec[4] = 1;
  memcpy (rec + 5, aad + 2, 6);
  rec[11] = 0; rec[12] = 8 + 9 + 16;
  memcpy (rec + 13, nonce + 4, 8);
  memcpy (rec + 21, pt, 9);
  CHECK_EQ (gq_aead_seal (GQ_AEAD_AES_128_GCM, tx.key, 16, nonce, aad, 13,
                          rec + 21, 9, rec + 21, 9 + 16), GQ_OK);
  CHECK_EQ (open_one (rec, 13 + 8 + 9 + 16, back, &len), GQ_OK);
  CHECK (len == 9 && memcmp (back, pt, 9) == 0);
  /* And ChaCha20-Poly1305: IV xor (epoch || seq).  */
  keys (GQ_AEAD_CHACHA20_POLY1305);
  memcpy (nonce, tx.iv, 12);
  for (i = 0; i < 8; i++)
    nonce[4 + i] ^= aad[i];
  rec[11] = 0; rec[12] = 9 + 16;
  memcpy (rec + 13, pt, 9);
  CHECK_EQ (gq_aead_seal (GQ_AEAD_CHACHA20_POLY1305, tx.key, 32, nonce, aad,
                          13, rec + 13, 9, rec + 13, 9 + 16), GQ_OK);
  CHECK_EQ (open_one (rec, 13 + 9 + 16, back, &len), GQ_OK);
  CHECK (len == 9 && memcmp (back, pt, 9) == 0);
}

static void
test_misc (void)
{
  uint8_t k[32] = { 0 }, iv[12] = { 0 };
  gq_dtls12_epoch e;

  CHECK_EQ (gq_dtls12_epoch_init (&e, 1, GQ_AEAD_AES_128_GCM, k, 32, iv, 4),
            GQ_ERR_INVAL);
  CHECK_EQ (gq_dtls12_epoch_init (&e, 1, GQ_AEAD_AES_128_GCM, k, 16, iv, 12),
            GQ_ERR_INVAL);
  CHECK_EQ (gq_dtls12_epoch_init (&e, 1, (enum gq_aead) 9, k, 16, iv, 4),
            GQ_ERR_UNSUPPORTED);
  /* The replay window of plain epochs.  */
  gq_dtls12_epoch_plain (&e);
  CHECK (gq_dtls12_replay_ok (&e, 5));
  gq_dtls12_replay_update (&e, 5);
  CHECK (!gq_dtls12_replay_ok (&e, 5) && gq_dtls12_replay_ok (&e, 4)
         && gq_dtls12_replay_ok (&e, 6));
  gq_dtls12_replay_update (&e, 100);
  CHECK (!gq_dtls12_replay_ok (&e, 5) && !gq_dtls12_replay_ok (&e, 36)
         && gq_dtls12_replay_ok (&e, 37));
}

int
main (void)
{
  gq_crypto_init ();
  test_framing ();
  test_roundtrip (GQ_AEAD_AES_128_GCM);
  test_roundtrip (GQ_AEAD_AES_256_GCM);
  test_roundtrip (GQ_AEAD_CHACHA20_POLY1305);
  test_wire_nonce ();
  test_misc ();
  TST_DONE ();
}
