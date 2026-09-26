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

/* Address validation tokens: round trips, address binding, expiry, key
   rotation and tampering.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>
#include <gnuquic/crypto.h>
#include <gnuquic/token.h>

#include "tst-util.h"

static gq_cid
mkcid (uint8_t len, uint8_t seed)
{
  gq_cid c;
  uint8_t i;

  memset (&c, 0, sizeof c);
  c.len = len;
  for (i = 0; i < len; i++)
    c.data[i] = (uint8_t) (seed + i);
  return c;
}

int
main (void)
{
  gq_token_keys k;
  uint8_t tok[GQ_TOKEN_MAX], addr[6] = { 10, 0, 0, 1, 0x11, 0x5c };
  uint8_t other[6] = { 10, 0, 0, 2, 0x11, 0x5c };
  size_t len, i;
  gq_token_info in;
  gq_cid od = mkcid (8, 1), sc = mkcid (20, 100);

  gq_crypto_init ();
  CHECK_EQ (gq_token_keys_init (&k), GQ_OK);

  /* Retry token round trip.  */
  CHECK_EQ (gq_token_make (&k, GQ_TOKEN_RETRY, addr, 6, &od, &sc, 1000, tok,
                           &len), GQ_OK);
  CHECK (len <= GQ_TOKEN_MAX);
  CHECK_EQ (gq_token_check (&k, addr, 6, tok, len, 1005, 10, 86400, &in),
            GQ_OK);
  CHECK (in.kind == GQ_TOKEN_RETRY && in.issued == 1000);
  CHECK (in.odcid.len == 8 && !memcmp (in.odcid.data, od.data, 8));
  CHECK (in.scid.len == 20 && !memcmp (in.scid.data, sc.data, 20));
  /* Wrong address, expired, from the future.  */
  CHECK_EQ (gq_token_check (&k, other, 6, tok, len, 1005, 10, 86400, &in),
            GQ_ERR_CRYPTO);
  CHECK_EQ (gq_token_check (&k, addr, 6, tok, len, 1011, 10, 86400, &in),
            GQ_ERR_RANGE);
  CHECK_EQ (gq_token_check (&k, addr, 6, tok, len, 999, 10, 86400, &in),
            GQ_ERR_RANGE);
  /* Every single-bit change is rejected, and so is every truncation.  */
  for (i = 0; i < len * 8; i++)
    {
      uint8_t t2[GQ_TOKEN_MAX];

      memcpy (t2, tok, len);
      t2[i / 8] ^= (uint8_t) (1 << (i % 8));
      CHECK_EQ (gq_token_check (&k, addr, 6, t2, len, 1005, 10, 86400, &in),
                GQ_ERR_CRYPTO);
    }
  for (i = 0; i < len; i++)
    CHECK (gq_token_check (&k, addr, 6, tok, i, 1005, 10, 86400, &in) != GQ_OK);

  /* NEW_TOKEN tokens use their own lifetime.  */
  CHECK_EQ (gq_token_make (&k, GQ_TOKEN_NEW_TOKEN, addr, 6, NULL, NULL, 50, tok,
                           &len), GQ_OK);
  CHECK_EQ (gq_token_check (&k, addr, 6, tok, len, 50 + 3600, 10, 86400, &in),
            GQ_OK);
  CHECK (in.kind == GQ_TOKEN_NEW_TOKEN && in.odcid.len == 0);
  CHECK_EQ (gq_token_check (&k, addr, 6, tok, len, 50 + 90000, 10, 86400,
                            &in), GQ_ERR_RANGE);

  /* One rotation keeps old tokens valid; two do not.  */
  CHECK_EQ (gq_token_keys_rotate (&k), GQ_OK);
  CHECK_EQ (gq_token_check (&k, addr, 6, tok, len, 60, 10, 86400, &in),
            GQ_OK);
  CHECK_EQ (gq_token_keys_rotate (&k), GQ_OK);
  CHECK_EQ (gq_token_check (&k, addr, 6, tok, len, 60, 10, 86400, &in),
            GQ_ERR_CRYPTO);
  /* Tokens differ even for identical inputs (random nonce).  */
  {
    uint8_t a[GQ_TOKEN_MAX], b[GQ_TOKEN_MAX];
    size_t la, lb;

    gq_token_make (&k, GQ_TOKEN_NEW_TOKEN, addr, 6, NULL, NULL, 1, a, &la);
    gq_token_make (&k, GQ_TOKEN_NEW_TOKEN, addr, 6, NULL, NULL, 1, b, &lb);
    CHECK (la == lb && memcmp (a, b, la) != 0);
  }
  CHECK_EQ (gq_token_make (&k, GQ_TOKEN_RETRY, addr, 6, NULL, NULL, 1, tok,
                           &len), GQ_ERR_INVAL);
  gq_token_keys_wipe (&k);
  TST_DONE ();
}
