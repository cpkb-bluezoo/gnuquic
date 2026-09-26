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

/* Internals shared by the client and server halves of the TLS 1.3 engine.
   Not installed; nothing here is part of the public API.  */

#ifndef GQ_TLS_INT_H
#define GQ_TLS_INT_H

#include <gnuquic/tls.h>
#include <gnuquic/tlsmsg.h>
#include <gnuquic/transcript.h>

#define MAX_SUITES 8
#define MAX_GROUPS 16
#define MAX_SIGS 32
#define MAX_COOKIE 4096
#define MAX_CHAIN 16
#define CH_BUF 16384

enum state
{
  ST_NEW,
  /* Client.  */
  ST_WAIT_SH, ST_WAIT_SH2, ST_WAIT_EE, ST_WAIT_CR_OR_CERT, ST_WAIT_CERT,
  ST_WAIT_CV, ST_WAIT_FIN,
  /* Server.  */
  ST_S_WAIT_CH1, ST_S_WAIT_CH2, ST_S_WAIT_EOED, ST_S_WAIT_CCERT, ST_S_WAIT_CCV, ST_S_WAIT_FIN,
  /* Both.  */
  ST_CONNECTED, ST_FAILED
};

enum role { ROLE_CLIENT = 1, ROLE_SERVER };

struct gq_tls
{
  enum role role;
  gq_tls_config cfg;		/* Client config; parts reused by servers.  */
  gq_tls_server_config scfg;
  gq_tls_sink sink;
  enum state st;
  int quic;
  int dtls;			/* DTLS 1.3 (RFC 9147).  */
  int primed;			/* Server: continuing a stateless retry.  */
  gq_tls_dtls_prime prime;
  int ku_busy;			/* DTLS: a KeyUpdate of ours is unacknowledged.  */

  /* Negotiable parameters after policy filtering.  */
  uint16_t suites[MAX_SUITES];
  size_t n_suites;
  uint16_t groups[MAX_GROUPS];
  size_t n_groups;
  uint16_t sigs[MAX_SIGS];
  size_t n_sigs;

  /* ClientHello state, kept so a second ClientHello can repeat it.  */
  uint8_t random[32];
  uint8_t sid[32];
  size_t sid_len;
  gq_kx_key kx[2];
  size_t n_kx;
  uint16_t suites12[16];	/* also_tls12: what a 1.2 client would offer.  */
  size_t n_suites12;
  uint16_t sigs12[16];
  size_t n_sigs12;
  const gq_tls_session *offered;	/* Session offered for resumption.  */
  int resumed;				/* A PSK was accepted.  */
  int hrr_seen;
  uint16_t hrr_suite;
  uint8_t cookie[MAX_COOKIE];
  size_t cookie_len;

  /* Transcript: both hashes until the suite is known.  */
  gq_transcript *t256, *t384, *tr;
  enum gq_hash hash;
  size_t hlen;
  enum gq_aead aead;
  uint16_t suite;
  gq_ks ks;

  /* Secrets kept for later stages.  */
  uint8_t chs[GQ_MAX_HASH_LEN], shs[GQ_MAX_HASH_LEN];
  uint8_t cas[GQ_MAX_HASH_LEN], sas[GQ_MAX_HASH_LEN];
  uint8_t exp[GQ_MAX_HASH_LEN], resm[GQ_MAX_HASH_LEN];

  /* Server authentication.  */
  gq_pubkey *peer_key;
  int cert_req;
  uint8_t cr_ctx[255];
  size_t cr_ctx_len;
  uint16_t cr_sigs[MAX_SIGS];
  size_t n_cr_sigs;

  /* Handshake message reassembly.  */
  uint8_t *msg;
  size_t msg_len, msg_cap;
  enum gq_level msg_level;

  /* Server state.  */
  uint8_t ch_random[32];		/* ClientHello1, checked against 2.  */
  uint8_t ch_suites_hash[32];	/* SHA-256 of the offered suite list.  */
  uint8_t cli_sigs_raw[MAX_SIGS * 2];
  uint16_t cli_sigs[MAX_SIGS];
  size_t n_cli_sigs;
  uint16_t hrr_group;
  uint8_t hrr_cookie[32];
  int hrr_cookie_sent;
  const gq_tls_credentials *creds;
  uint16_t sign_scheme;
  int early_offered;			/* Client: we offered it.  Server: it was.  */
  int early_accepted;
  int early_candidate;			/* Server: eligible, pending replay check.  */
  int hs_write_deferred;		/* Client: hold handshake write keys until
					   EndOfEarlyData has been sent.  */
  int hs_read_deferred;			/* Server: hold handshake read keys until
					   EndOfEarlyData has arrived.  */
  uint8_t hash_ch[GQ_MAX_HASH_LEN];	/* Server: Hash (ClientHello1).  */
  uint32_t psk_age;			/* Server: obfuscated age from the client.  */
  char sni[256];
  size_t sni_len;
  int chosen_alpn;
  uint8_t alpn_out[255];
  size_t alpn_out_len;
  int client_verified;
  gq_session_state sess;		/* Server: state behind the accepted PSK.  */
  size_t psk_index;
  uint8_t psk_id_hash[32];
  int cli_psk_dhe;			/* Client offered psk_dhe_ke.  */

  gq_tls_info info;
  int alert;
};


/* Helpers implemented in tls.c and used by tls_server.c.  */
int gqi_fail (gq_tls *t, unsigned alert, int status);
int gqi_fail_parse (gq_tls *t, int status);
int gqi_suite_params (unsigned suite, enum gq_aead *aead, enum gq_hash *hash);
int gqi_rnd (gq_tls *t, void *buf, size_t n);
int gqi_emit (gq_tls *t, enum gq_level level, const uint8_t *data, size_t len);
int gqi_emit_secret (gq_tls *t, enum gq_level level, enum gq_dir dir,
                     const uint8_t *secret);
int gqi_emit_secret_as (gq_tls *t, enum gq_level level, enum gq_dir dir,
                        enum gq_aead aead, enum gq_hash hash,
                        const uint8_t *secret);
int gqi_tr_update (gq_tls *t, gq_slice msg);
int gqi_tr_hash (gq_tls *t, uint8_t *out);
int gqi_in_list (const uint16_t *l, size_t n, unsigned v);
size_t gqi_cv_content (uint8_t *out, int server, const uint8_t *th,
                       size_t hlen);
unsigned gqi_cert_error_alert (enum gq_cert_error e);
int gqi_send_hs (gq_tls *t, const gq_wbuf *w);
uint64_t gqi_now_ms (const gq_tls *t);
void gqi_filter_lists (gq_tls *t, const uint16_t *suites, size_t n_suites,
                       const uint16_t *groups, size_t n_groups,
                       const uint16_t *sigs, size_t n_sigs);
int gqi_on_key_update (gq_tls *t, gq_slice body);
int gqi_server_dispatch (gq_tls *t, enum gq_level level, gq_slice msg);

#endif
