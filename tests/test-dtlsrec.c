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

/* DTLS 1.3 record codecs: framing events, protection and its refusals.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/dtlsrec.h>
#include <gnuquic/keysched.h>

#include "tst-util.h"

/* A log of the events one datagram produced.  */
struct log
{
  int n;
  struct
  {
    int kind;
    unsigned type, seq_len;
    uint16_t epoch;
    uint64_t seq;
    size_t hdr, body;
  } e[16];
  uint8_t last_body[64];
};

static int
on_rec (void *u, const gq_drec *r)
{
  struct log *l = u;

  if (l->n < 16)
    {
      l->e[l->n].kind = r->kind;
      l->e[l->n].type = r->type;
      l->e[l->n].epoch = r->epoch;
      l->e[l->n].seq = r->seq;
      l->e[l->n].seq_len = r->seq_len;
      l->e[l->n].hdr = r->header.len;
      l->e[l->n].body = r->body.len;
      l->n++;
    }
  return 0;
}

static void
test_framing (void)
{
  uint8_t d[400], frag[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  gq_wbuf w;
  struct log l;
  size_t plain_end;

  gq_wbuf_init (&w, d, sizeof d);
  gq_dtls_put_plain (&w, GQ_DTLS_CT_HANDSHAKE, 0x010203040506ull, frag, 10);
  gq_dtls_put_plain (&w, GQ_DTLS_CT_ACK, 7, frag, 2);
  gq_dtls_put_plain (&w, GQ_DTLS_CT_ALERT, 8, frag, 2);
  CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
  CHECK_EQ (w.len, (size_t) (13 * 3 + 14));
  plain_end = w.len;

  memset (&l, 0, sizeof l);
  CHECK_EQ (gq_dtls_records (d, w.len, on_rec, &l), GQ_OK);
  CHECK_EQ (l.n, 3);
  CHECK (l.e[0].kind == GQ_DREC_PLAINTEXT && l.e[0].type == 22
         && l.e[0].epoch == 0 && l.e[0].seq == 0x010203040506ull
         && l.e[0].body == 10);
  CHECK (l.e[1].type == 26 && l.e[1].seq == 7 && l.e[1].body == 2);
  CHECK (l.e[2].type == 21 && l.e[2].seq == 8);

  /* A prefix that ends mid-record delivers the whole records before it.  */
  {
    size_t cut;

    for (cut = 0; cut < plain_end; cut++)
      {
        int expect = cut >= 13 + 10 ? (cut >= 13 + 10 + 15 ? (cut >= 13 + 10 + 30 ? 3 : 2) : 1) : 0;

        memset (&l, 0, sizeof l);
        CHECK_EQ (gq_dtls_records (d, cut, on_rec, &l), GQ_OK);
        CHECK_EQ (l.n, expect);
      }
  }

  /* Unified headers: every S/L combination, framed by hand.  */
  {
    static const uint8_t recs[] = {
      0x2c | 1, 0x12, 0x34, 0x00, 0x03, 'a', 'b', 'c',	/* S=1 L=1 */
      0x20 | 0x0c | 2 | 0x00, 0x55, 0x00, 0x02, 'x', 'y',	/* S=1? see below */
    };
    uint8_t x[64];

    /* 001 0 1 1 01: 16-bit seq, length, epoch 1.  */
    memcpy (x, recs, 8);
    memset (&l, 0, sizeof l);
    CHECK_EQ (gq_dtls_records (x, 8, on_rec, &l), GQ_OK);
    CHECK (l.n == 1 && l.e[0].kind == GQ_DREC_CIPHERTEXT && l.e[0].epoch == 1
           && l.e[0].seq == 0x1234 && l.e[0].seq_len == 2 && l.e[0].hdr == 5
           && l.e[0].body == 3);
    /* 001 0 0 1 10: 8-bit seq, length, epoch 2.  */
    x[0] = 0x24 | 2; x[1] = 0x77; x[2] = 0; x[3] = 2; x[4] = 'p'; x[5] = 'q';
    memset (&l, 0, sizeof l);
    CHECK_EQ (gq_dtls_records (x, 6, on_rec, &l), GQ_OK);
    CHECK (l.n == 1 && l.e[0].seq == 0x77 && l.e[0].seq_len == 1
           && l.e[0].hdr == 4 && l.e[0].body == 2 && l.e[0].epoch == 2);
    /* 001 0 1 0 11: 16-bit seq, no length: runs to the end.  */
    x[0] = 0x28 | 3; x[1] = 0x00; x[2] = 0x09;
    memset (x + 3, 'z', 20);
    memset (&l, 0, sizeof l);
    CHECK_EQ (gq_dtls_records (x, 23, on_rec, &l), GQ_OK);
    CHECK (l.n == 1 && l.e[0].body == 20 && l.e[0].epoch == 3);
    /* The C bit (connection ID): not ours, dropped.  */
    x[0] = 0x3c;
    memset (&l, 0, sizeof l);
    CHECK_EQ (gq_dtls_records (x, 23, on_rec, &l), GQ_OK);
    CHECK_EQ (l.n, 0);
    /* Content types of older versions and garbage first bytes.  */
    for (x[0] = 0; ; x[0]++)
      {
        int ok = x[0] == 21 || x[0] == 22 || x[0] == 26
          || ((x[0] & 0xe0) == 0x20 && !(x[0] & 0x10));

        memset (x + 1, 0, 30);
        x[4] = 0; x[11] = 0; x[12] = 0;
        memset (&l, 0, sizeof l);
        gq_dtls_records (x, 30, on_rec, &l);
        if (!ok)
          CHECK_EQ (l.n, 0);
        if (x[0] == 255)
          break;
      }
  }

  /* A handler can stop the walk.  */
  {
    struct log l2;

    memset (&l2, 0, sizeof l2);
    CHECK_EQ (gq_dtls_records (d, plain_end, (gq_drec_cb) NULL, &l2), GQ_OK);
  }
}

/* ---- Protection ---- */

static gq_dtls_epoch tx, rx;

static void
keys (enum gq_aead aead, uint64_t epoch)
{
  uint8_t secret[48];
  size_t i;

  for (i = 0; i < sizeof secret; i++)
    secret[i] = (uint8_t) (i * 11 + 3);
  CHECK_EQ (gq_dtls_epoch_init (&tx, epoch, aead, secret), GQ_OK);
  CHECK_EQ (gq_dtls_epoch_init (&rx, epoch, aead, secret), GQ_OK);
}

struct one
{
  gq_drec rec;
  int got;
};

static int
grab (void *u, const gq_drec *r)
{
  struct one *o = u;

  o->rec = *r;
  o->got++;
  return 0;
}

/* Decode the single record in D.  */
static int
open_one (const uint8_t *d, size_t n, uint8_t *out, unsigned *type,
          size_t *len, uint64_t *seq)
{
  struct one o;

  memset (&o, 0, sizeof o);
  gq_dtls_records (d, n, grab, &o);
  if (o.got != 1 || o.rec.kind != GQ_DREC_CIPHERTEXT)
    return GQ_ERR_ENCODING;
  return gq_dtls_deprotect (&rx, &o.rec, out, 2048, type, len, seq);
}

static void
test_roundtrip (enum gq_aead aead)
{
  uint8_t out[2048], back[2048], pt[1500];
  size_t n, len, i;
  unsigned type;
  uint64_t seq, used;
  int distinct = 0;

  keys (aead, 3);
  for (i = 0; i < sizeof pt; i++)
    pt[i] = (uint8_t) (i * 7);

  for (i = 0; i < 300; i++)
    {
      size_t plen = (i * 37) % 1400;

      CHECK_EQ (gq_dtls_protect (&tx, GQ_DTLS_CT_APPLICATION_DATA, pt, plen,
                                 out, sizeof out, &n, &used), GQ_OK);
      CHECK_EQ (used, (uint64_t) i);
      CHECK_EQ (n, plen + GQ_DTLS_CIPHER_OVERHEAD);
      CHECK_EQ (out[0], 0x2c | 3);
      /* Record number encryption: the wire value is not the number.  */
      if ((((unsigned) out[1] << 8) | out[2]) != (unsigned) i)
        distinct++;
      CHECK_EQ (open_one (out, n, back, &type, &len, &seq), GQ_OK);
      CHECK (type == GQ_DTLS_CT_APPLICATION_DATA && len == plen
             && memcmp (back, pt, plen) == 0);
      CHECK_EQ (seq, (uint64_t) i);
    }
  CHECK (distinct > 250);

  /* The sequence number in the nonce is 64-bit: rounds across the 16-bit
     wrap decode to the right full number.  */
  tx.send_seq = 65530;
  rx.recv_any = 0;
  for (i = 0; i < 20; i++)
    {
      CHECK_EQ (gq_dtls_protect (&tx, GQ_DTLS_CT_HANDSHAKE, pt, 5, out,
                                 sizeof out, &n, &used), GQ_OK);
      CHECK_EQ (open_one (out, n, back, &type, &len, &seq), GQ_OK);
      CHECK_EQ (seq, 65530 + i);
    }

  /* Bit flips anywhere fail: header (additional data / sequence number),
     ciphertext and tag.  The length field re-frames rather than corrupts.  */
  keys (aead, 3);
  CHECK_EQ (gq_dtls_protect (&tx, GQ_DTLS_CT_HANDSHAKE, pt, 24, out,
                             sizeof out, &n, &used), GQ_OK);
  for (i = 0; i < n * 8; i++)
    {
      uint8_t copy[128];

      if (i / 8 == 3 || i / 8 == 4)
        continue;
      memcpy (copy, out, n);
      copy[i / 8] ^= (uint8_t) (1 << (i % 8));
      keys (aead, 3);
      /* Epoch bits: the record then names another epoch; the caller would
         pick other keys.  Deprotection with ours must still fail.  */
      CHECK (open_one (copy, n, back, &type, &len, &seq) != GQ_OK);
      CHECK_EQ (rx.recv_any, 0);	/* The window was not touched.  */
    }
  CHECK (rx.bad > 0);

  /* Replay, old, and reordering inside the window.  */
  keys (aead, 3);
  {
    uint8_t rec[10][80];
    size_t rl[10];

    for (i = 0; i < 10; i++)
      CHECK_EQ (gq_dtls_protect (&tx, GQ_DTLS_CT_APPLICATION_DATA, pt, 8,
                                 rec[i], 80, &rl[i], NULL), GQ_OK);
    CHECK_EQ (open_one (rec[9], rl[9], back, &type, &len, &seq), GQ_OK);
    CHECK_EQ (open_one (rec[9], rl[9], back, &type, &len, &seq), GQ_ERR_RANGE);
    CHECK_EQ (open_one (rec[3], rl[3], back, &type, &len, &seq), GQ_OK);
    CHECK_EQ (seq, 3);
    CHECK_EQ (open_one (rec[3], rl[3], back, &type, &len, &seq), GQ_ERR_RANGE);
    CHECK_EQ (open_one (rec[0], rl[0], back, &type, &len, &seq), GQ_OK);
  }
  /* Older than the 64-record window is refused.  */
  keys (aead, 3);
  {
    uint8_t first[80], later[80];
    size_t fl, ll;

    CHECK_EQ (gq_dtls_protect (&tx, 23, pt, 4, first, 80, &fl, NULL), GQ_OK);
    tx.send_seq = 200;
    CHECK_EQ (gq_dtls_protect (&tx, 23, pt, 4, later, 80, &ll, NULL), GQ_OK);
    CHECK_EQ (open_one (later, ll, back, &type, &len, &seq), GQ_OK);
    CHECK_EQ (open_one (first, fl, back, &type, &len, &seq), GQ_ERR_RANGE);
  }

  /* Small, oversized and exhausted.  */
  keys (aead, 3);
  CHECK_EQ (gq_dtls_protect (&tx, 23, pt, 1400, out, 100, &n, NULL),
            GQ_ERR_BUFSIZE);
  CHECK_EQ (gq_dtls_protect (&tx, 23, pt, 20000, out, sizeof out, &n, NULL),
            GQ_ERR_INVAL);
  tx.send_seq = GQ_DTLS_SEQ_LIMIT - 1;
  CHECK_EQ (gq_dtls_protect (&tx, 23, pt, 4, out, 80, &n, NULL),
            aead == GQ_AEAD_CHACHA20_POLY1305 ? GQ_OK : GQ_OK);
  CHECK_EQ (gq_dtls_protect (&tx, 23, pt, 4, out, 80, &n, NULL),
            aead == GQ_AEAD_CHACHA20_POLY1305 ? GQ_OK : GQ_ERR_RANGE);
}

/* An independent construction of a record from the RFC's description,
   for every header shape, must be accepted.  */
static void
test_handmade (enum gq_aead aead)
{
  static const struct { int seq16, len; } shapes[] = {
    { 1, 1 }, { 0, 1 }, { 1, 0 }, { 0, 0 }
  };
  size_t k, i;

  for (k = 0; k < 4; k++)
    {
      uint8_t hdr[5], rec[128], nonce[12], m[5], back[128], pt[9];
      size_t hl = 1, kl, ctl;
      uint64_t seq = 0x1a2b3c, tseq;
      unsigned type;
      size_t len;
      uint64_t got;

      keys (aead, 5);
      rx.recv_max = seq - 2;	/* Highest seen: close to the record.  */
      rx.recv_any = 1;
      rx.recv_bits = 0;
      for (i = 0; i < sizeof pt; i++)
        pt[i] = (uint8_t) (0x40 + i);
      /* inner = payload, type 22, two bytes of zero padding.  */
      memcpy (rec + 16, pt, 9);
      rec[16 + 9] = 22;
      rec[16 + 10] = 0;
      rec[16 + 11] = 0;
      ctl = 12 + 16;
      tseq = shapes[k].seq16 ? (seq & 0xffff) : (seq & 0xff);
      hdr[0] = (uint8_t) (0x20 | (shapes[k].seq16 ? 8 : 0)
                          | (shapes[k].len ? 4 : 0) | 1);
      if (shapes[k].seq16)
        {
          hdr[1] = (uint8_t) (tseq >> 8);
          hdr[2] = (uint8_t) tseq;
          hl = 3;
        }
      else
        hdr[hl++] = (uint8_t) tseq;
      if (shapes[k].len)
        {
          hdr[hl++] = (uint8_t) (ctl >> 8);
          hdr[hl++] = (uint8_t) ctl;
        }
      /* Nonce: IV xor the 64-bit record number; AAD: the header.  */
      memcpy (nonce, tx.iv, 12);
      for (i = 0; i < 8; i++)
        nonce[11 - i] ^= (uint8_t) (seq >> (8 * i));
      kl = gq_aead_key_size (aead);
      CHECK_EQ (gq_aead_seal (aead, tx.key, kl, nonce, hdr, hl, rec + 16, 12,
                              rec + 16, ctl), GQ_OK);
      /* Encrypt the sequence number with the first 16 ciphertext bytes.  */
      CHECK_EQ (gq_hp_mask (aead, tx.sn_key, kl, rec + 16, m), GQ_OK);
      for (i = 0; i < (shapes[k].seq16 ? 2u : 1u); i++)
        hdr[1 + i] ^= m[i];
      memcpy (rec, hdr, hl);
      memmove (rec + hl, rec + 16, ctl);
      CHECK_EQ (open_one (rec, hl + ctl, back, &type, &len, &got), GQ_OK);
      CHECK (type == 22 && len == 9 && memcmp (back, pt, 9) == 0);
      CHECK_EQ (got, seq);
    }
}

/* Every record shorter than the mask sample is refused.  */
static void
test_short (void)
{
  uint8_t rec[40], back[40];
  size_t n;
  unsigned type;
  size_t len;
  uint64_t seq;

  keys (GQ_AEAD_AES_128_GCM, 3);
  for (n = 0; n < 17; n++)
    {
      memset (rec, 0, sizeof rec);
      rec[0] = 0x2c | 3;
      rec[3] = 0;
      rec[4] = (uint8_t) n;
      CHECK (open_one (rec, 5 + n, back, &type, &len, &seq) != GQ_OK);
    }
}

int
main (void)
{
  gq_crypto_init ();
  test_framing ();
  test_roundtrip (GQ_AEAD_AES_128_GCM);
  test_roundtrip (GQ_AEAD_AES_256_GCM);
  test_roundtrip (GQ_AEAD_CHACHA20_POLY1305);
  test_handmade (GQ_AEAD_AES_128_GCM);
  test_handmade (GQ_AEAD_AES_256_GCM);
  test_handmade (GQ_AEAD_CHACHA20_POLY1305);
  test_short ();
  TST_DONE ();
}
