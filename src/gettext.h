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

/* Message translation.  Every user-visible string in the library is
   marked with _() and looked up in the "gnuquic" domain.  Without NLS the
   macros vanish.  */

#ifndef GQ_GETTEXT_H
#define GQ_GETTEXT_H

#ifdef ENABLE_NLS
# include <libintl.h>
# define GQ_TEXTDOMAIN "gnuquic"
# define _(msgid) dgettext (GQ_TEXTDOMAIN, msgid)
#else
# define _(msgid) (msgid)
#endif

/* Mark a string for extraction without translating it here.  */
#define N_(msgid) (msgid)

/* Bind the message domain to the installed catalogues.  Idempotent; called
   from gq_crypto_init.  */
void gqi_i18n_init (void);

#endif /* GQ_GETTEXT_H */
