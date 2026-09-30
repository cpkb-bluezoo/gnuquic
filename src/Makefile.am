## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of quickstep.
##
## quickstep is free software: you can redistribute it and/or modify it
## under the terms of the GNU Lesser General Public License as published
## by the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## quickstep is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this program.  If not, see
## <https://www.gnu.org/licenses/>.

lib_LTLIBRARIES = libquickstep.la

libquickstep_la_SOURCES = \
  crypto.c \
  dtls.c \
  endpoint.c \
  conn_int.h \
  dtls_int.h \
  dtls12.c \
  dtls12cookie.c \
  dtls12rec.c \
  dtlscookie.c \
  dtlsauto.c \
  quiclb.c \
  dtlshs.c \
  dtlsrec.c \
  gettext.h \
  frame.c \
  keysched.c \
  kx.c \
  packet.c \
  policy.c \
  protect.c \
  listen.c \
  ranges.c \
  conn.c \
  conn_datagram.c \
  conn_loss.c \
  conn_path.c \
  conn_recv.c \
  conn_send.c \
  conn_stream.c \
  stream.c \
  token.c \
  record.c \
  record12.c \
  replay.c \
  sign.c \
  status.c \
  tickets.c \
  tls12.c \
  tls12_int.h \
  tls12_server.c \
  tls12conn.c \
  tls12ks.c \
  tlsauto.c \
  tls12msg.c \
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

libquickstep_la_CPPFLAGS = -I$(top_srcdir)/include \
  -DLOCALEDIR=\"$(localedir)\"
libquickstep_la_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS) $(LIBGCRYPT_CFLAGS) $(GNUTLS_CFLAGS)
libquickstep_la_LIBADD = $(LIBGCRYPT_LIBS) $(GNUTLS_LIBS) $(LTLIBINTL)
libquickstep_la_LDFLAGS = -version-info $(LIBQUICKSTEP_LTVERSION) \
  -export-symbols-regex '^gq_'

quickstepincludedir = $(includedir)/quickstep
quickstepinclude_HEADERS = \
  $(top_srcdir)/include/quickstep/crypto.h \
  $(top_srcdir)/include/quickstep/dtls.h \
  $(top_srcdir)/include/quickstep/dtls12.h \
  $(top_srcdir)/include/quickstep/dtls12cookie.h \
  $(top_srcdir)/include/quickstep/dtls12rec.h \
  $(top_srcdir)/include/quickstep/dtlscookie.h \
  $(top_srcdir)/include/quickstep/dtlsauto.h \
  $(top_srcdir)/include/quickstep/quiclb.h \
  $(top_srcdir)/include/quickstep/dtlshs.h \
  $(top_srcdir)/include/quickstep/dtlsrec.h \
  $(top_srcdir)/include/quickstep/frame.h \
  $(top_srcdir)/include/quickstep/keysched.h \
  $(top_srcdir)/include/quickstep/kx.h \
  $(top_srcdir)/include/quickstep/packet.h \
  $(top_srcdir)/include/quickstep/policy.h \
  $(top_srcdir)/include/quickstep/protect.h \
  $(top_srcdir)/include/quickstep/conn.h \
  $(top_srcdir)/include/quickstep/endpoint.h \
  $(top_srcdir)/include/quickstep/listen.h \
  $(top_srcdir)/include/quickstep/ranges.h \
  $(top_srcdir)/include/quickstep/stream.h \
  $(top_srcdir)/include/quickstep/token.h \
  $(top_srcdir)/include/quickstep/record.h \
  $(top_srcdir)/include/quickstep/record12.h \
  $(top_srcdir)/include/quickstep/replay.h \
  $(top_srcdir)/include/quickstep/sign.h \
  $(top_srcdir)/include/quickstep/status.h \
  $(top_srcdir)/include/quickstep/tickets.h \
  $(top_srcdir)/include/quickstep/tls.h \
  $(top_srcdir)/include/quickstep/tls12.h \
  $(top_srcdir)/include/quickstep/tls12conn.h \
  $(top_srcdir)/include/quickstep/tlsauto.h \
  $(top_srcdir)/include/quickstep/tls12ks.h \
  $(top_srcdir)/include/quickstep/tls12msg.h \
  $(top_srcdir)/include/quickstep/tlsconn.h \
  $(top_srcdir)/include/quickstep/tlsmsg.h \
  $(top_srcdir)/include/quickstep/tparams.h \
  $(top_srcdir)/include/quickstep/transcript.h \
  $(top_srcdir)/include/quickstep/trust.h \
  $(top_srcdir)/include/quickstep/varint.h
