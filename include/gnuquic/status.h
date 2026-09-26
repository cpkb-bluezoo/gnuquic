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

/* Status codes shared by every GNU QUIC module.

   The library never aborts and never writes to stderr; every failure is
   reported to the caller as a negative gq_status value.  */

#ifndef GNUQUIC_STATUS_H
#define GNUQUIC_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

enum gq_status
{
  GQ_OK = 0,

  /* Push parsers: the input ended in the middle of a syntactic unit.
     The caller must keep the unconsumed tail and present it again,
     followed by more data.  Not a protocol error by itself.  */
  GQ_NEED_MORE = 1,

  GQ_ERR_INVAL = -1,		/* Bad argument (programmer error).  */
  GQ_ERR_NOMEM = -2,		/* Allocation failed.  */
  GQ_ERR_ENCODING = -3,		/* Malformed wire data.  */
  GQ_ERR_RANGE = -4,		/* Value outside the permitted range.  */
  GQ_ERR_BUFSIZE = -5,		/* Output buffer too small.  */
  GQ_ERR_CRYPTO = -6,		/* Primitive failed (bad tag, bad key...).  */
  GQ_ERR_UNSUPPORTED = -7,	/* Algorithm not offered by policy.  */
  GQ_ERR_HANDLER = -8,		/* A handler callback asked to abort.  */
  GQ_ERR_CERT = -9,		/* Certificate rejected (see gq_trust).  */
  GQ_ERR_UNAVAILABLE = -10,	/* Feature not compiled in.  */
  GQ_ERR_PROTOCOL = -11,	/* Well-formed but illegal (illegal_parameter).  */
  GQ_ERR_TIMEOUT = -12		/* Retransmissions exhausted (DTLS).  */
};

/* Return a static, untranslated description of STATUS.  */
const char *gq_strerror (int status);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_STATUS_H */
