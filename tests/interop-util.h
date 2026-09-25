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

/* Helpers shared by the interoperability test programs.  */

#ifndef GQ_INTEROP_UTIL_H
#define GQ_INTEROP_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <gnuquic/frame.h>

/* PEM certificate file to DER slices.  */
static int
load_chain (const char *path, gq_slice **out, size_t *n)
{
  gnutls_datum_t pem;
  gnutls_x509_crt_t *crts;
  unsigned count, i;
  FILE *f = fopen (path, "rb");
  uint8_t buf[65536];
  size_t got;

  if (!f)
    return -1;
  got = fread (buf, 1, sizeof buf, f);
  fclose (f);
  pem.data = buf;
  pem.size = (unsigned) got;
  if (gnutls_x509_crt_list_import2 (&crts, &count, &pem, GNUTLS_X509_FMT_PEM,
                                    0) < 0)
    return -1;
  *out = calloc (count, sizeof **out);
  for (i = 0; i < count; i++)
    {
      gnutls_datum_t d;
      uint8_t *copy;

      gnutls_x509_crt_export2 (crts[i], GNUTLS_X509_FMT_DER, &d);
      copy = malloc (d.size);
      memcpy (copy, d.data, d.size);
      (*out)[i].data = copy;
      (*out)[i].len = d.size;
      gnutls_free (d.data);
    }
  *n = count;
  return 0;
}

#endif
