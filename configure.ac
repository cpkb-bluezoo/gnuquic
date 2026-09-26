dnl Process this file with autoconf to produce a configure script.
dnl
dnl Copyright (C) 2026 Chris Burdess <dog@gnu.org>
dnl
dnl This file is part of GNU QUIC.
dnl
dnl GNU QUIC is free software: you can redistribute it and/or modify it
dnl under the terms of the GNU Lesser General Public License as published
dnl by the Free Software Foundation, either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl GNU QUIC is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this program.  If not, see
dnl <https://www.gnu.org/licenses/>.

AC_PREREQ([2.71])
AC_INIT([GNU QUIC], [0.0.1], [bug-gnuquic@gnu.org], [gnuquic],
        [https://www.gnu.org/software/gnuquic/])
AC_CONFIG_SRCDIR([src/varint.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.16 -Wall -Werror foreign subdir-objects
                  color-tests parallel-tests])
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS

dnl GNU QUIC is written in ISO C99 and is built with -std=c99 so that
dnl nothing newer sneaks in.  Fail early if the compiler cannot do it.
AC_MSG_CHECKING([whether $CC supports -std=c99])
gq_save_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -std=c99"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if !defined __STDC_VERSION__ || __STDC_VERSION__ != 199901L
# error not C99
#endif
]])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   AC_MSG_ERROR([a C99 compiler is required])])
CFLAGS=$gq_save_CFLAGS
STD_CFLAGS=-std=c99
AC_SUBST([STD_CFLAGS])
AM_PROG_AR
LT_INIT([win32-dll])

dnl Libtool interface versioning: current:revision:age.  Bump per the
dnl libtool manual before each release.
LIBGNUQUIC_LTVERSION=0:0:0
AC_SUBST([LIBGNUQUIC_LTVERSION])

dnl Message translation with GNU gettext.  The library is a plain
dnl consumer of the system gettext (glibc or an installed libintl).
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.21])

PKG_PROG_PKG_CONFIG

dnl Crypto floor.  All primitives come from libgcrypt; we never
dnl implement a cipher, hash, KEM or signature scheme ourselves.
PKG_CHECK_MODULES([LIBGCRYPT], [libgcrypt >= 1.11.0],
  [], [AC_MSG_ERROR([libgcrypt >= 1.11.0 is required])])

dnl Certificate loading and path validation.  GnuTLS is the first
dnl backend behind the gq_trust interface (src/trust.h); the interface
dnl is designed so that it can later be replaced by an in-tree
dnl implementation.
AC_ARG_WITH([gnutls],
  [AS_HELP_STRING([--with-gnutls],
     [use GnuTLS for X.509 loading and validation @<:@default=yes@:>@])],
  [], [with_gnutls=yes])
AS_IF([test "x$with_gnutls" != xno],
  [PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.8.0],
     [AC_DEFINE([HAVE_GNUTLS], [1], [Define to use the GnuTLS trust backend])],
     [AC_MSG_ERROR([GnuTLS >= 3.8.0 not found; use --without-gnutls to build without certificate validation])])])
GNUTLS_PC_REQUIRES=
AS_IF([test "x$with_gnutls" != xno], [GNUTLS_PC_REQUIRES=gnutls])
AC_SUBST([GNUTLS_PC_REQUIRES])
AM_CONDITIONAL([HAVE_GNUTLS], [test "x$with_gnutls" != xno])

dnl wolfSSL is an optional test dependency: an independent DTLS 1.3 peer for
dnl the interoperability tests (tests/interop-dtls.sh).  The library itself
dnl never uses it.
AC_ARG_WITH([wolfssl],
  [AS_HELP_STRING([--with-wolfssl],
     [build the DTLS 1.3 interoperability peer against wolfSSL @<:@default=check@:>@])],
  [], [with_wolfssl=check])
have_wolfssl=no
AS_IF([test "x$with_wolfssl" != xno],
  [PKG_CHECK_MODULES([WOLFSSL], [wolfssl],
     [have_wolfssl=yes],
     [AS_IF([test "x$with_wolfssl" = xyes],
        [AC_MSG_ERROR([wolfSSL not found])])])])
AM_CONDITIONAL([HAVE_WOLFSSL], [test "x$have_wolfssl" = xyes])

dnl Warnings.  GNU QUIC is expected to build with zero warnings.
AC_ARG_ENABLE([warnings],
  [AS_HELP_STRING([--disable-warnings], [do not add extra compiler warnings])],
  [], [enable_warnings=yes])
WARN_CFLAGS=
AS_IF([test "x$enable_warnings" = xyes],
  [for flag in -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes \
               -Wmissing-prototypes -Wcast-qual -Wwrite-strings \
               -Wformat=2 -Wundef -pedantic; do
     GQ_CHECK_CFLAG([$flag])
   done])
AC_SUBST([WARN_CFLAGS])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 po/Makefile.in
                 doc/Makefile
                 tests/Makefile
                 gnuquic.pc])
AC_OUTPUT
