## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of GNU QUIC.
##
## GNU QUIC is free software: you can redistribute it and/or modify it
## under the terms of the GNU Lesser General Public License as published
## by the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## GNU QUIC is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this program.  If not, see
## <https://www.gnu.org/licenses/>.

lib_LTLIBRARIES = libgnuquic.la

libgnuquic_la_SOURCES = \
  crypto.c \
  gettext.h \
  frame.c \
  keysched.c \
  kx.c \
  packet.c \
  policy.c \
  protect.c \
  record.c \
  replay.c \
  sign.c \
  status.c \
  tickets.c \
  tls.c \
  tls_int.h \
  tls_server.c \
  tlsconn.c \
  tlsmsg.c \
  tparams.c \
  transcript.c \
  trust.c \
  varint.c \
  version.h

libgnuquic_la_CPPFLAGS = -I$(top_srcdir)/include \
  -DLOCALEDIR=\"$(localedir)\"
libgnuquic_la_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS) $(LIBGCRYPT_CFLAGS) $(GNUTLS_CFLAGS)
libgnuquic_la_LIBADD = $(LIBGCRYPT_LIBS) $(GNUTLS_LIBS) $(LTLIBINTL)
libgnuquic_la_LDFLAGS = -version-info $(LIBGNUQUIC_LTVERSION) \
  -export-symbols-regex '^gq_'

gnuquicincludedir = $(includedir)/gnuquic
gnuquicinclude_HEADERS = \
  $(top_srcdir)/include/gnuquic/crypto.h \
  $(top_srcdir)/include/gnuquic/frame.h \
  $(top_srcdir)/include/gnuquic/keysched.h \
  $(top_srcdir)/include/gnuquic/kx.h \
  $(top_srcdir)/include/gnuquic/packet.h \
  $(top_srcdir)/include/gnuquic/policy.h \
  $(top_srcdir)/include/gnuquic/protect.h \
  $(top_srcdir)/include/gnuquic/record.h \
  $(top_srcdir)/include/gnuquic/replay.h \
  $(top_srcdir)/include/gnuquic/sign.h \
  $(top_srcdir)/include/gnuquic/status.h \
  $(top_srcdir)/include/gnuquic/tickets.h \
  $(top_srcdir)/include/gnuquic/tls.h \
  $(top_srcdir)/include/gnuquic/tlsconn.h \
  $(top_srcdir)/include/gnuquic/tlsmsg.h \
  $(top_srcdir)/include/gnuquic/tparams.h \
  $(top_srcdir)/include/gnuquic/transcript.h \
  $(top_srcdir)/include/gnuquic/trust.h \
  $(top_srcdir)/include/gnuquic/varint.h
