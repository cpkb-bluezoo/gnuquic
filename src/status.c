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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gnuquic/status.h>

#include "gettext.h"

const char *
gq_strerror (int status)
{
  switch (status)
    {
    case GQ_OK:			return _("success");
    case GQ_NEED_MORE:		return _("more input needed");
    case GQ_ERR_INVAL:		return _("invalid argument");
    case GQ_ERR_NOMEM:		return _("out of memory");
    case GQ_ERR_ENCODING:	return _("malformed wire data");
    case GQ_ERR_RANGE:		return _("value out of range");
    case GQ_ERR_BUFSIZE:	return _("output buffer too small");
    case GQ_ERR_CRYPTO:		return _("cryptographic operation failed");
    case GQ_ERR_UNSUPPORTED:	return _("algorithm not permitted by policy");
    case GQ_ERR_HANDLER:	return _("handler aborted processing");
    case GQ_ERR_CERT:		return _("certificate rejected");
    case GQ_ERR_UNAVAILABLE:	return _("feature not compiled in");
    case GQ_ERR_PROTOCOL:	return _("protocol violation");
    default:			return _("unknown status");
    }
}

void
gqi_i18n_init (void)
{
#ifdef ENABLE_NLS
  static int done;

  if (!done)
    {
      bindtextdomain (GQ_TEXTDOMAIN, LOCALEDIR);
      bind_textdomain_codeset (GQ_TEXTDOMAIN, "UTF-8");
      done = 1;
    }
#endif
}
