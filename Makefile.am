## Process this file with automake to produce Makefile.in
##
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

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = po src doc tests

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = quickstep.pc

EXTRA_DIST = COPYING.LESSER HACKING build-aux/config.rpath

## The committed ChangeLog is a placeholder (see its own text); a release
## tarball gets a real one generated from the git history instead, newest
## first, in the traditional format.  Do nothing to it in a checkout that
## is not a git repository (a rebuild from an already-unpacked tarball).
.PHONY: gen-ChangeLog
gen-ChangeLog:
	@if test -d "$(top_srcdir)/.git"; then \
	  (cd "$(top_srcdir)" \
	   && git log --date=short \
	        --pretty='%ad  %an  <%ae>%n%n%w(76,8,8)* %s%n%+b') \
	    > "$(distdir)/cl-t" \
	  && rm -f "$(distdir)/ChangeLog" \
	  && mv "$(distdir)/cl-t" "$(distdir)/ChangeLog"; \
	fi
dist-hook: gen-ChangeLog
