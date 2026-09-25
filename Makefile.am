## Process this file with automake to produce Makefile.in
##
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

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = po src doc tests

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gnuquic.pc

EXTRA_DIST = COPYING.LESSER HACKING build-aux/config.rpath
