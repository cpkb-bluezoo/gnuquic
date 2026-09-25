# gq_cflags.m4 - probe for compiler warning flags.
#
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

# GQ_CHECK_CFLAG(FLAG)
# --------------------
# Append FLAG to WARN_CFLAGS if the C compiler accepts it.
AC_DEFUN([GQ_CHECK_CFLAG],
[AC_MSG_CHECKING([whether $CC accepts $1])
 gq_save_CFLAGS=$CFLAGS
 CFLAGS="$CFLAGS $1 -Werror"
 AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
   [AC_MSG_RESULT([yes])
    WARN_CFLAGS="$WARN_CFLAGS $1"],
   [AC_MSG_RESULT([no])])
 CFLAGS=$gq_save_CFLAGS])
