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

/* Internal declarations shared by the DTLS 1.3 and 1.2 cookie code.  */

#ifndef GQ_DTLS_INT_H
#define GQ_DTLS_INT_H

#include <stdint.h>

/* The rotating secrets behind gq_dtls_cookies (dtlscookie.h).  */
struct gq_dtls_cookies
{
  uint8_t cur[32], prev[32];
  int have_prev;
};

#endif
