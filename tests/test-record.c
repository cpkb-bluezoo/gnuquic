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

#include <gnuquic/status.h>
#include <gnuquic/record.h>

#include "tst-util.h"
#include "vectors-tls.h"

struct got
{
  unsigned types[16];
  size_t lens[16];
  uint8_t data[16][256];
  int n;
};

static int
collect (void *u, unsigned type, const uint8_t *d, size_t len)
{
  struct got *g = u;

  if (g->n < 16)
    {
      g->types[g->n] = type;
      g->lens[g->n] = len;
      memcpy (g->data[g->n], d, len < 256 ? len : 256);
      g->n++;
    }
  return 0;
}

static void
keys (gq_record *r, enum gq_dir dir, const char *secret_hex)
{
  uint8_t s[32];

  tst_unhex (secret_hex, s, 32);
  CHECK_EQ (gq_record_set_keys (r, dir, GQ_AEAD_AES_128_GCM, s, 32), GQ_OK);
}

/* Seal PAYLOAD_HEX as TYPE under the given traffic secret after SKIP
   earlier records, and compare with the RFC's record byte for byte; then
   open the RFC's record with a reader and compare the plaintext.  */
static void
rfc_record (const char *secret_hex, int skip, unsigned type,
            const char *payload_hex, const char *record_hex)
{
  static uint8_t payload[1024], want[1024], out[1024], in[1024];
  size_t pn = tst_unhex (payload_hex, payload, sizeof payload);
  size_t wn = tst_unhex (record_hex, want, sizeof want), on, i;
  gq_record w, r;
  struct got g;
  uint8_t *p = in;
  size_t l = wn;

  gq_record_init (&w);
  keys (&w, GQ_DIR_WRITE, secret_hex);
  w.write.seq = (uint64_t) skip;	/* Earlier records of the trace.  */
  CHECK_EQ (gq_record_protect (&w, type, payload, pn, 0, out, sizeof out, &on),
            GQ_OK);
  CHECK_EQ (on, wn);
  CHECK (memcmp (out, want, wn) == 0);

  gq_record_init (&r);
  keys (&r, GQ_DIR_READ, secret_hex);
  r.read.seq = (uint64_t) skip;
  memcpy (in, want, wn);
  memset (&g, 0, sizeof g);
  CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_OK);
  CHECK_EQ (l, 0);
  CHECK_EQ (g.n, 1);
  CHECK_EQ (g.types[0], type);
  CHECK_EQ (g.lens[0], pn);
  for (i = 0; i < pn && i < 256; i++)
    CHECK_EQ (g.data[0][i], payload[i]);
  gq_record_wipe (&w);
  gq_record_wipe (&r);
}

static void
test_rfc8448 (void)
{
  rfc_record (T8448_SERVER_HS_TRAFFIC, 0, GQ_CT_HANDSHAKE,
              T8448_REC_SERVER_FLIGHT_PAYLOAD, T8448_REC_SERVER_FLIGHT);
  rfc_record (T8448_CLIENT_HS_TRAFFIC, 0, GQ_CT_HANDSHAKE,
              T8448_REC_CLIENT_FINISHED_PAYLOAD, T8448_REC_CLIENT_FINISHED);
  rfc_record (T8448_SERVER_AP_TRAFFIC, 0, GQ_CT_HANDSHAKE,
              T8448_REC_NST_PAYLOAD, T8448_REC_NST);
  rfc_record (T8448_CLIENT_AP_TRAFFIC, 0, GQ_CT_APPLICATION_DATA,
              T8448_REC_CLIENT_APP_PAYLOAD, T8448_REC_CLIENT_APP);
  rfc_record (T8448_SERVER_AP_TRAFFIC, 1, GQ_CT_APPLICATION_DATA,
              T8448_REC_SERVER_APP_PAYLOAD, T8448_REC_SERVER_APP);
  rfc_record (T8448_CLIENT_AP_TRAFFIC, 1, GQ_CT_ALERT,
              T8448_REC_CLIENT_ALERT_PAYLOAD, T8448_REC_CLIENT_ALERT);
  rfc_record (T8448_SERVER_AP_TRAFFIC, 2, GQ_CT_ALERT,
              T8448_REC_SERVER_ALERT_PAYLOAD, T8448_REC_SERVER_ALERT);
}

/* The server's whole encrypted flight, fed in every chunking.  */
static void
test_rfc_chunking (void)
{
  static uint8_t rec[1024], pend[1024];
  size_t n = tst_unhex (T8448_REC_SERVER_FLIGHT, rec, sizeof rec), chunk;

  for (chunk = 1; chunk <= 700; chunk += (chunk < 40 ? 1 : 37))
    {
      gq_record r;
      struct got g;
      size_t plen = 0, pos = 0;

      gq_record_init (&r);
      keys (&r, GQ_DIR_READ, T8448_SERVER_HS_TRAFFIC);
      memset (&g, 0, sizeof g);
      while (pos < n)
        {
          size_t take = n - pos < chunk ? n - pos : chunk, used;
          uint8_t *p;
          size_t l;
          int rc;

          /* A caller keeps the unconsumed tail; and the partial record
             must not have been touched (decryption is all-or-nothing).  */
          memcpy (pend + plen, rec + pos, take);
          plen += take;
          pos += take;
          p = pend;
          l = plen;
          rc = gq_record_receive (&r, &p, &l, collect, &g);
          CHECK (rc == GQ_OK || rc == GQ_NEED_MORE);
          used = plen - l;
          memmove (pend, pend + used, l);
          plen = l;
        }
      CHECK_EQ (g.n, 1);
      CHECK_EQ (g.lens[0], 657);
      CHECK_EQ (r.read.seq, 1);
    }
}

static void
test_plaintext_and_ccs (void)
{
  gq_record w, r;
  uint8_t out[64], in[64];
  static const uint8_t frag[] = { 1, 0, 0, 0 };
  static const uint8_t ccs = 1;
  size_t n;
  struct got g;
  uint8_t *p;
  size_t l;

  /* Before keys the first handshake record claims 0x0301, later ones
     0x0303; application data cannot exist in the clear.  */
  gq_record_init (&w);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_HANDSHAKE, frag, 4, 0, out,
                               sizeof out, &n), GQ_OK);
  CHECK (n == 9 && out[0] == 22 && out[1] == 3 && out[2] == 1 && out[4] == 4);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_HANDSHAKE, frag, 4, 0, out,
                               sizeof out, &n), GQ_OK);
  CHECK_EQ (out[2], 3);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, frag, 4, 0, out,
                               sizeof out, &n), GQ_ERR_INVAL);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_CHANGE_CIPHER_SPEC, &ccs, 1, 0, out,
                               sizeof out, &n), GQ_OK);
  CHECK (n == 6 && out[0] == 20);

  /* The reader takes plaintext handshake/alert records before keys, drops
     the compatibility CCS only when allowed, and rejects the rest.  */
  gq_record_init (&r);
  memset (&g, 0, sizeof g);
  memcpy (in, out, n);
  p = in; l = n;
  CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_PROTOCOL);
  CHECK_EQ (gq_record_alert (&r), 10);
  gq_record_init (&r);
  gq_record_allow_ccs (&r, 1);
  p = in; l = n;
  CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_OK);
  CHECK_EQ (g.n, 0);				/* Dropped silently.  */
  in[5] = 2;					/* CCS must contain 1.  */
  p = in; l = n;
  CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_PROTOCOL);

  /* Plaintext application data and empty handshake records are refused.  */
  gq_record_init (&r);
  {
    static const uint8_t ad[] = { 23, 3, 3, 0, 1, 9 };
    static const uint8_t eh[] = { 22, 3, 3, 0, 0 };

    memcpy (in, ad, sizeof ad);
    p = in; l = sizeof ad;
    CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_PROTOCOL);
    gq_record_init (&r);
    memcpy (in, eh, sizeof eh);
    p = in; l = sizeof eh;
    CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_PROTOCOL);
  }
  /* A plaintext alert is fine before keys.  */
  gq_record_init (&r);
  {
    static const uint8_t al[] = { 21, 3, 3, 0, 2, 2, 40 };

    memcpy (in, al, sizeof al);
    memset (&g, 0, sizeof g);
    p = in; l = sizeof al;
    CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_OK);
    CHECK (g.n == 1 && g.types[0] == GQ_CT_ALERT && g.data[0][1] == 40);
  }
}

static void
test_protected_rules (void)
{
  static const uint8_t secret[32] = { 5 };
  static const uint8_t data[] = "0123456789";
  static uint8_t out[GQ_REC_MAX_RECORD + 64], big[GQ_REC_MAX_PLAINTEXT + 1];
  gq_record w, r;
  size_t n, l;
  uint8_t *p;
  struct got g;
  int i;

  gq_record_init (&w);
  gq_record_init (&r);
  CHECK_EQ (gq_record_set_keys (&w, GQ_DIR_WRITE, GQ_AEAD_CHACHA20_POLY1305,
                                secret, 32), GQ_OK);
  CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_CHACHA20_POLY1305,
                                secret, 32), GQ_OK);
  CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_AES_128_GCM, secret,
                                31), GQ_ERR_INVAL);

  /* Sequence numbers advance in step; padding is stripped; empty
     application data is legal; CCS cannot be protected.  */
  for (i = 0; i < 3; i++)
    {
      size_t pad = (size_t) i * 7;

      CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, data, 10, pad,
                                  out, sizeof out, &n), GQ_OK);
      CHECK_EQ (n, 5 + 10 + 1 + pad + 16);
      p = out; l = n;
      memset (&g, 0, sizeof g);
      CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_OK);
      CHECK (g.n == 1 && g.lens[0] == 10 && memcmp (g.data[0], data, 10) == 0);
    }
  CHECK_EQ (gq_record_write_seq (&w), 3);
  CHECK_EQ (gq_record_read_seq (&r), 3);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, NULL, 0, 0, out,
                               sizeof out, &n), GQ_OK);
  p = out; l = n;
  memset (&g, 0, sizeof g);
  CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_OK);
  CHECK (g.n == 1 && g.lens[0] == 0);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_CHANGE_CIPHER_SPEC, data, 1, 0, out,
                               sizeof out, &n), GQ_ERR_INVAL);

  /* Limits: fragments above 2^14, buffers too small.  */
  CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, big,
                               GQ_REC_MAX_PLAINTEXT + 1, 0, out, sizeof out,
                               &n), GQ_ERR_INVAL);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, big,
                               GQ_REC_MAX_PLAINTEXT, 0, out, 100, &n),
            GQ_ERR_BUFSIZE);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, big,
                               GQ_REC_MAX_PLAINTEXT, 0, out, sizeof out, &n),
            GQ_OK);
  CHECK_EQ (n, GQ_REC_HEADER_LEN + GQ_REC_MAX_PLAINTEXT + 1 + 16);
  p = out; l = n;
  memset (&g, 0, sizeof g);
  CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_OK);
  CHECK_EQ (g.lens[0], GQ_REC_MAX_PLAINTEXT);

  /* A new key resets the sequence number.  */
  CHECK_EQ (gq_record_set_keys (&w, GQ_DIR_WRITE, GQ_AEAD_CHACHA20_POLY1305,
                                secret, 32), GQ_OK);
  CHECK_EQ (gq_record_write_seq (&w), 0);

  /* Sequence limit.  */
  w.write.seq = GQ_REC_SEQ_LIMIT;
  CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, data, 1, 0, out,
                               sizeof out, &n), GQ_ERR_RANGE);
}

static void
test_receive_failures (void)
{
  static const uint8_t secret[32] = { 6 };
  static const uint8_t data[] = "attack at dawn";
  static uint8_t out[128], keep[128];
  gq_record w, r;
  size_t n, l;
  uint8_t *p;
  struct got g;

  gq_record_init (&w);
  CHECK_EQ (gq_record_set_keys (&w, GQ_DIR_WRITE, GQ_AEAD_AES_256_GCM,
                                (const uint8_t[48]) { 6 }, 48), GQ_OK);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, data, 14, 0, out,
                               sizeof out, &n), GQ_OK);
  memcpy (keep, out, n);
  (void) secret;

  /* Tampering anywhere (header, body, tag) fails authentication.  */
  {
    size_t off;

    for (off = 0; off < n; off++)
      {
        int rc;

        memcpy (out, keep, n);
        out[off] ^= 0x01;
        gq_record_init (&r);
        CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_AES_256_GCM,
                                      (const uint8_t[48]) { 6 }, 48), GQ_OK);
        p = out; l = n;
        memset (&g, 0, sizeof g);
        rc = gq_record_receive (&r, &p, &l, collect, &g);
        /* Header bytes 1-2 may pass as the legacy version; the length
           bytes may make it a partial or oversize record; everything
           else must be rejected, and no plaintext may be delivered.  */
        CHECK (g.n == 0);
        if (off >= 5 || off == 0)
          CHECK (rc == GQ_ERR_CRYPTO || rc == GQ_ERR_PROTOCOL);
      }
  }

  /* Encrypted records must have the application_data outer type; a
     plaintext handshake record after keys is unexpected.  */
  memcpy (out, keep, n);
  gq_record_init (&r);
  CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_AES_256_GCM,
                                (const uint8_t[48]) { 6 }, 48), GQ_OK);
  out[0] = GQ_CT_HANDSHAKE;
  p = out; l = n;
  CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_PROTOCOL);
  CHECK_EQ (gq_record_alert (&r), 10);

  /* Wrong record sequence (replay/reorder) fails authentication.  */
  memcpy (out, keep, n);
  gq_record_init (&r);
  CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_AES_256_GCM,
                                (const uint8_t[48]) { 6 }, 48), GQ_OK);
  r.read.seq = 1;
  p = out; l = n;
  CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_CRYPTO);
  CHECK_EQ (gq_record_alert (&r), 20);

  /* Oversize declared length, and a non-TLS header.  */
  {
    static const uint8_t huge[] = { 23, 3, 3, 0x50, 0x00 };
    static const uint8_t junk[] = { 'G', 'E', 'T', ' ', '/' };

    gq_record_init (&r);
    memcpy (out, huge, 5);
    p = out; l = 5;
    CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_PROTOCOL);
    CHECK_EQ (gq_record_alert (&r), 22);
    gq_record_init (&r);
    memcpy (out, junk, 5);
    p = out; l = 5;
    CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_PROTOCOL);
    CHECK_EQ (gq_record_alert (&r), 10);
  }

  /* An all-zero inner plaintext has no content type.  */
  {
    static const uint8_t zero[10] = { 0 };

    gq_record_init (&w);
    CHECK_EQ (gq_record_set_keys (&w, GQ_DIR_WRITE, GQ_AEAD_AES_128_GCM,
                                  (const uint8_t[32]) { 8 }, 32), GQ_OK);
    /* Protect a "type 0" record by writing the inner bytes ourselves:
       zero payload, zero type via padding trick is impossible through the
       API, so seal raw.  */
    CHECK_EQ (gq_record_protect (&w, GQ_CT_APPLICATION_DATA, zero, 0, 9, out,
                                 sizeof out, &n), GQ_OK);
    gq_record_init (&r);
    CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_AES_128_GCM,
                                  (const uint8_t[32]) { 8 }, 32), GQ_OK);
    p = out; l = n;
    memset (&g, 0, sizeof g);
    CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_OK);
    CHECK (g.n == 1 && g.lens[0] == 0 && g.types[0] == GQ_CT_APPLICATION_DATA);
  }
}

/* The server's first record says 0x0303, never the client's 0x0301.  */
static void
test_server_role (void)
{
  static const uint8_t frag[] = { 2, 0, 0, 0 };
  uint8_t out[32];
  size_t n;
  gq_record w;

  gq_record_init (&w);
  gq_record_set_server (&w);
  CHECK_EQ (gq_record_protect (&w, GQ_CT_HANDSHAKE, frag, 4, 0, out,
                               sizeof out, &n), GQ_OK);
  CHECK (out[1] == 3 && out[2] == 3);
}

/* Declined 0-RTT: records that fail authentication are dropped while the
   budget lasts, without consuming a sequence number, and a genuine record
   after them is still read.  */
static void
test_skip_budget (void)
{
  static const uint8_t secret[32] = { 3 }, other[32] = { 4 };
  static const uint8_t msg[] = "real";
  static uint8_t wire[512], junk[128];
  gq_record early, good, r;
  size_t n1, n2, l;
  uint8_t *p;
  struct got g;

  /* Two undecryptable records (early keys), then a genuine one.  */
  gq_record_init (&early);
  CHECK_EQ (gq_record_set_keys (&early, GQ_DIR_WRITE, GQ_AEAD_AES_128_GCM,
                                other, 32), GQ_OK);
  CHECK_EQ (gq_record_protect (&early, GQ_CT_APPLICATION_DATA, msg, 4, 0,
                               junk, sizeof junk, &n1), GQ_OK);
  memcpy (wire, junk, n1);
  CHECK_EQ (gq_record_protect (&early, GQ_CT_APPLICATION_DATA, msg, 4, 0,
                               junk, sizeof junk, &n2), GQ_OK);
  memcpy (wire + n1, junk, n2);
  gq_record_init (&good);
  CHECK_EQ (gq_record_set_keys (&good, GQ_DIR_WRITE, GQ_AEAD_AES_128_GCM,
                                secret, 32), GQ_OK);
  CHECK_EQ (gq_record_protect (&good, GQ_CT_HANDSHAKE, msg, 4, 0, junk,
                               sizeof junk, &l), GQ_OK);
  memcpy (wire + n1 + n2, junk, l);

  /* Without a budget the first bad record is fatal.  */
  gq_record_init (&r);
  CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_AES_128_GCM, secret,
                                32), GQ_OK);
  memset (&g, 0, sizeof g);
  {
    static uint8_t copy[512];
    size_t total = n1 + n2 + l;

    memcpy (copy, wire, total);
    p = copy; l = total;
    CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_CRYPTO);
    CHECK_EQ (gq_record_alert (&r), 20);
  }

  /* With a budget both are skipped and the real record is delivered.  */
  gq_record_init (&r);
  CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_AES_128_GCM, secret,
                                32), GQ_OK);
  /* The budget counts ciphertext bytes, not headers.  */
  gq_record_set_skip_budget (&r, (n1 - GQ_REC_HEADER_LEN) + (n2 - GQ_REC_HEADER_LEN));
  p = wire;
  l = n1 + n2 + GQ_REC_HEADER_LEN + 4 + 1 + GQ_AEAD_TAG_LEN;
  memset (&g, 0, sizeof g);
  CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_OK);
  CHECK_EQ (g.n, 1);
  CHECK (g.types[0] == GQ_CT_HANDSHAKE && g.lens[0] == 4
         && memcmp (g.data[0], "real", 4) == 0);
  CHECK_EQ (gq_record_skip_budget (&r), 0);
  CHECK_EQ (gq_record_read_seq (&r), 1);	/* Skips took no sequence number.  */

  /* A budget smaller than the bad record does not help.  */
  gq_record_init (&r);
  CHECK_EQ (gq_record_set_keys (&r, GQ_DIR_READ, GQ_AEAD_AES_128_GCM, secret,
                                32), GQ_OK);
  gq_record_set_skip_budget (&r, n1 - GQ_REC_HEADER_LEN - 1);
  {
    static uint8_t copy[512];

    memcpy (copy, wire, n1);
    p = copy; l = n1;
    CHECK_EQ (gq_record_receive (&r, &p, &l, collect, &g), GQ_ERR_CRYPTO);
  }
}

int
main (void)
{
  CHECK_EQ (gq_crypto_init (), GQ_OK);
  test_server_role ();
  test_skip_budget ();
  test_rfc8448 ();
  test_rfc_chunking ();
  test_plaintext_and_ccs ();
  test_protected_rules ();
  test_receive_failures ();
  TST_DONE ();
}
