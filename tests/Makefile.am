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

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS) $(GNUTLS_CFLAGS)
LDADD = $(top_builddir)/src/libgnuquic.la $(GNUTLS_LIBS)

UNIT_TESTS = test-varint test-frame test-crypto test-policy test-trust \
  test-packet test-protect test-tparams test-kx test-sign \
  test-tlsmsg test-keysched test-tls-client test-record test-tlsconn test-tls-server \
  test-resume test-tickets test-early test-tls12ks test-record12 test-tls12 \
  test-tls12conn test-dtlsrec test-dtlshs test-dtls test-dtls12rec test-dtls12 test-ranges test-stream test-conn test-token

# Interoperability against independent servers (skipped if none installed).
if HAVE_GNUTLS
INTEROP = interop.sh interop-quic.sh
INTEROP_PROGS = interop-client interop-server interop-dtls interop-quic
endif

# DTLS 1.3 against wolfSSL, if it is installed with DTLS 1.3.
if HAVE_WOLFSSL
if HAVE_GNUTLS
INTEROP += interop-dtls.sh interop-dtls12.sh
INTEROP_PROGS += wolf-dtls
endif
endif

TESTS = $(UNIT_TESTS) $(INTEROP)
check_PROGRAMS = $(UNIT_TESTS) $(INTEROP_PROGS)
TESTS_ENVIRONMENT = INTEROP_CLIENT=./interop-client; export INTEROP_CLIENT; \
  INTEROP_SERVER=./interop-server; export INTEROP_SERVER; \
  INTEROP_DTLS=./interop-dtls; export INTEROP_DTLS; \
  INTEROP_QUIC=./interop-quic; export INTEROP_QUIC; \
  WOLF_DTLS=./wolf-dtls; export WOLF_DTLS;

wolf_dtls_SOURCES = wolf-dtls.c
interop_dtls_SOURCES = interop-dtls.c
interop_quic_SOURCES = interop-quic.c
wolf_dtls_CFLAGS = $(AM_CFLAGS) $(WOLFSSL_CFLAGS)
wolf_dtls_LDADD = $(WOLFSSL_LIBS)

EXTRA_DIST = interop-quic.sh interop-dtls.sh interop-dtls12.sh interop.sh interop-util.h tst-util.h tst-x509.h tst-fix12.h tst-tlspeer.h vectors.h vectors-tls.h vectors-resume.h
