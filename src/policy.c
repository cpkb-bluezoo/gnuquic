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

#include <stddef.h>

#include <gnuquic/policy.h>

#define ARRAY_LEN(a) (sizeof (a) / sizeof (a)[0])

static const uint16_t suites13[] = {
  GQ_TLS_AES_256_GCM_SHA384,
  GQ_TLS_CHACHA20_POLY1305_SHA256,
  GQ_TLS_AES_128_GCM_SHA256
};

static const uint16_t suites12[] = {
  GQ_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
  GQ_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  GQ_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  GQ_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
  GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
};

/* Hybrid post-quantum first, then classical.  */
static const uint16_t groups[] = {
  GQ_GROUP_X25519_MLKEM768,
  GQ_GROUP_SECP256R1_MLKEM768,
  GQ_GROUP_SECP384R1_MLKEM1024,
  GQ_GROUP_X25519,
  GQ_GROUP_SECP256R1,
  GQ_GROUP_SECP384R1
};

static const uint16_t sigs[] = {
  GQ_SIG_MLDSA65,
  GQ_SIG_MLDSA87,
  GQ_SIG_MLDSA44,
  GQ_SIG_ED25519,
  GQ_SIG_ECDSA_SECP256R1_SHA256,
  GQ_SIG_ECDSA_SECP384R1_SHA384,
  GQ_SIG_RSA_PSS_RSAE_SHA256,
  GQ_SIG_RSA_PSS_RSAE_SHA384,
  GQ_SIG_RSA_PSS_RSAE_SHA512
};

static int
is_13 (unsigned version)
{
  return version == GQ_TLS_1_3 || version == GQ_DTLS_1_3;
}

static int
in_list (const uint16_t *list, size_t n, unsigned v)
{
  size_t i;

  for (i = 0; i < n; i++)
    if (list[i] == v)
      return 1;
  return 0;
}

int
gq_policy_allows_version (unsigned version)
{
  return version == GQ_TLS_1_2 || version == GQ_TLS_1_3
    || version == GQ_DTLS_1_2 || version == GQ_DTLS_1_3;
}

const uint16_t *
gq_policy_default_suites (unsigned version, size_t *n)
{
  if (!gq_policy_allows_version (version))
    {
      *n = 0;
      return NULL;
    }
  if (is_13 (version))
    {
      *n = ARRAY_LEN (suites13);
      return suites13;
    }
  *n = ARRAY_LEN (suites12);
  return suites12;
}

int
gq_policy_allows_suite (unsigned version, unsigned suite)
{
  size_t n;
  const uint16_t *l = gq_policy_default_suites (version, &n);

  return l != NULL && in_list (l, n, suite);
}

const uint16_t *
gq_policy_default_groups (size_t *n)
{
  *n = ARRAY_LEN (groups);
  return groups;
}

int
gq_policy_allows_group (unsigned group)
{
  return in_list (groups, ARRAY_LEN (groups), group);
}

const uint16_t *
gq_policy_default_sigschemes (size_t *n)
{
  *n = ARRAY_LEN (sigs);
  return sigs;
}

int
gq_policy_allows_sigscheme (unsigned version, unsigned scheme)
{
  if (!gq_policy_allows_version (version)
      || !in_list (sigs, ARRAY_LEN (sigs), scheme))
    return 0;
  /* ML-DSA is defined for TLS 1.3 / DTLS 1.3 only.  */
  if (scheme >= GQ_SIG_MLDSA44 && scheme <= GQ_SIG_MLDSA87)
    return is_13 (version);
  return 1;
}
