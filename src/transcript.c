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

#include <gcrypt.h>

#include <gnuquic/status.h>
#include <gnuquic/transcript.h>
#include <gnuquic/tlsmsg.h>

struct gq_transcript
{
  gcry_md_hd_t md;
  enum gq_hash alg;
  int algo;
};

int
gq_transcript_new (gq_transcript **out, enum gq_hash alg)
{
  gq_transcript *t;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (out == NULL)
    return GQ_ERR_INVAL;
  if (gq_hash_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  t = calloc (1, sizeof *t);
  if (t == NULL)
    return GQ_ERR_NOMEM;
  t->alg = alg;
  t->algo = alg == GQ_HASH_SHA256 ? GCRY_MD_SHA256 : GCRY_MD_SHA384;
  if (gcry_md_open (&t->md, t->algo, 0))
    {
      free (t);
      return GQ_ERR_NOMEM;
    }
  *out = t;
  return GQ_OK;
}

void
gq_transcript_free (gq_transcript *t)
{
  if (t == NULL)
    return;
  gcry_md_close (t->md);
  free (t);
}

int
gq_transcript_update (gq_transcript *t, const void *data, size_t len)
{
  if (t == NULL || (data == NULL && len > 0))
    return GQ_ERR_INVAL;
  gcry_md_write (t->md, data, len);
  return GQ_OK;
}

int
gq_transcript_copy (const gq_transcript *t, gq_transcript **out)
{
  gq_transcript *c;

  if (t == NULL || out == NULL)
    return GQ_ERR_INVAL;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  *c = *t;
  if (gcry_md_copy (&c->md, t->md))
    {
      free (c);
      return GQ_ERR_NOMEM;
    }
  *out = c;
  return GQ_OK;
}

int
gq_transcript_hash (const gq_transcript *t, uint8_t *out, size_t outlen)
{
  gcry_md_hd_t c;
  const uint8_t *d;

  if (t == NULL || out == NULL || outlen != gq_hash_size (t->alg))
    return GQ_ERR_INVAL;
  /* Reading finalizes a context, so read a copy.  */
  if (gcry_md_copy (&c, t->md))
    return GQ_ERR_NOMEM;
  d = gcry_md_read (c, t->algo);
  memcpy (out, d, outlen);
  gcry_md_close (c);
  return GQ_OK;
}

int
gq_transcript_hello_retry (gq_transcript *t)
{
  uint8_t msg[4 + 48];
  size_t hl;
  int r;

  if (t == NULL)
    return GQ_ERR_INVAL;
  hl = gq_hash_size (t->alg);
  msg[0] = GQ_HS_MESSAGE_HASH;
  msg[1] = 0;
  msg[2] = 0;
  msg[3] = (uint8_t) hl;
  r = gq_transcript_hash (t, msg + 4, hl);
  if (r != GQ_OK)
    return r;
  gcry_md_reset (t->md);
  gcry_md_write (t->md, msg, 4 + hl);
  return GQ_OK;
}
