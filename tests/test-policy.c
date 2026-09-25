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

#include <gnuquic/policy.h>

#include "tst-util.h"

int
main (void)
{
  size_t n, i;
  const uint16_t *l;

  CHECK (gq_policy_allows_version (GQ_TLS_1_3));
  CHECK (gq_policy_allows_version (GQ_DTLS_1_2));
  CHECK (!gq_policy_allows_version (0x0301));	/* TLS 1.0.  */
  CHECK (!gq_policy_allows_version (0x0302));	/* TLS 1.1.  */
  CHECK (!gq_policy_allows_version (0x0300));	/* SSL 3.0.  */
  CHECK (!gq_policy_allows_version (0xfeff));	/* DTLS 1.0.  */

  /* Suites are scoped to the version generation.  */
  CHECK (gq_policy_allows_suite (GQ_TLS_1_3, GQ_TLS_AES_128_GCM_SHA256));
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_2, GQ_TLS_AES_128_GCM_SHA256));
  CHECK (gq_policy_allows_suite (GQ_TLS_1_2,
                                 GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_3,
                                  GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_2, 0xc013));	/* CBC.  */
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_2, 0x009c));	/* Static RSA GCM.  */
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_2, 0x0005));	/* RC4.  */

  CHECK (gq_policy_allows_group (GQ_GROUP_X25519_MLKEM768));
  CHECK (!gq_policy_allows_group (0x0100));		/* ffdhe2048.  */
  CHECK (!gq_policy_allows_group (0x0019));		/* secp521r1.  */

  CHECK (gq_policy_allows_sigscheme (GQ_TLS_1_3, GQ_SIG_MLDSA65));
  CHECK (!gq_policy_allows_sigscheme (GQ_TLS_1_2, GQ_SIG_MLDSA65));
  CHECK (!gq_policy_allows_sigscheme (GQ_TLS_1_3, 0x0201));	/* RSA SHA-1.  */
  CHECK (!gq_policy_allows_sigscheme (GQ_TLS_1_3, 0x0401));	/* PKCS1 SHA256.  */

  /* Every default is itself permitted, and PQ hybrids lead.  */
  l = gq_policy_default_groups (&n);
  CHECK (n > 0 && l[0] == GQ_GROUP_X25519_MLKEM768);
  for (i = 0; i < n; i++)
    CHECK (gq_policy_allows_group (l[i]));
  l = gq_policy_default_suites (GQ_TLS_1_3, &n);
  for (i = 0; i < n; i++)
    CHECK (gq_policy_allows_suite (GQ_TLS_1_3, l[i]));
  l = gq_policy_default_suites (GQ_DTLS_1_2, &n);
  for (i = 0; i < n; i++)
    CHECK (gq_policy_allows_suite (GQ_DTLS_1_2, l[i]));
  l = gq_policy_default_suites (0x0301, &n);
  CHECK (l == NULL && n == 0);

  TST_DONE ();
}
