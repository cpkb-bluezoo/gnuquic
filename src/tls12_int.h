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

/* Internal declarations shared by tls12.c (common code and the client)
   and tls12_server.c.  Not installed.  */

#ifndef GQ_TLS12_INT_H
#define GQ_TLS12_INT_H

#include <gnuquic/tls12.h>
#include <gnuquic/tls12msg.h>
#include <gnuquic/keysched.h>

#define T12_MAX_SUITES 8
#define T12_MAX_SIGS 16
#define T12_MAX_CHAIN 16
#define T12_TB_MAX (1u << 20)	/* Bound on the buffered transcript.  */

enum st12
{
  S12_NEW,
  /* Client.  */
  S12_C_WAIT_SH, S12_C_WAIT_CERT, S12_C_WAIT_SKE, S12_C_WAIT_CR_OR_SHD,
  S12_C_WAIT_SHD, S12_C_WAIT_TICKET_OR_CCS, S12_C_WAIT_CCS, S12_C_WAIT_FIN,
  /* Server.  */
  S12_S_WAIT_CH, S12_S_WAIT_CCERT, S12_S_WAIT_CKE, S12_S_WAIT_CV,
  S12_S_WAIT_CCS, S12_S_WAIT_FIN,
  /* Both.  */
  S12_DONE, S12_FAILED
};

struct gq_tls12
{
  int server;
  int dtls;			/* DTLS 1.2: transcript in DTLS form.  */
  uint16_t tx_seq, rx_seq;	/* DTLS message_seq of the next message.  */
  uint8_t cookie[255];		/* Client: from HelloVerifyRequest.  */
  size_t cookie_len;
  int hvr_seen;
  int tls13_offered;		/* Client: our hello also offered TLS 1.3.  */
  uint8_t *adopted;		/* DTLS: that hello, to repeat with a cookie.  */
  size_t adopted_len;
  gq_tls_config cfg;		/* Client config; parts reused by servers.  */
  gq_tls_server_config scfg;
  gq_tls12_sink sink;
  enum st12 st;

  /* Preferences after policy filtering.  */
  uint16_t suites[T12_MAX_SUITES];
  size_t n_suites;
  uint16_t sigs[T12_MAX_SIGS];
  size_t n_sigs;

  uint8_t client_random[32], server_random[32];
  uint8_t sid[32];		/* Session ID we sent (client) or echo.  */
  size_t sid_len;
  uint16_t suite;
  enum gq_aead aead;
  enum gq_hash hash;
  uint8_t master[GQ_TLS12_MASTER_LEN];
  gq_tls12_keys keys;		/* Derived, wiped once installed.  */
  int have_keys;

  uint16_t kx_group;		/* Its group; 0 means secp256r1.  */
  gq_kx_key kx;			/* Our ephemeral key.  */
  int have_kx;
  uint8_t pms[GQ_KX_SHARED_MAX];
  size_t pms_len;

  /* Every handshake message sent or received, in order.  Needed whole for
     CertificateVerify (RFC 5246 section 7.4.8); the hashes are taken
     from it on demand.  */
  uint8_t *tb;
  size_t tb_len, tb_cap;

  /* Partial incoming message.  */
  uint8_t *msg;
  size_t msg_len, msg_cap;

  gq_pubkey *peer_key;
  int peer_cert;		/* The peer presented a certificate.  */
  int cert_req;			/* Client: the server asked for one.  */
  uint8_t cr_sigs[64];		/* Client: raw list from CertificateRequest.  */
  size_t cr_sigs_len;

  /* Resumption.  */
  const gq_tls_session *offered;	/* Client.  */
  int resumed;
  int ticket_expected;		/* A NewSessionTicket is due.  */
  uint8_t nst[GQ_TICKET_MAX];	/* Client: ticket held until completion.  */
  size_t nst_len;
  uint32_t nst_lifetime;
  gq_session_state sess;	/* Server: state behind an accepted ticket.  */

  /* Server.  */
  const gq_tls_credentials *creds;
  uint16_t sign_scheme;
  uint16_t req_sigs[T12_MAX_SIGS];	/* What we put in CertificateRequest.  */
  size_t n_req_sigs;
  char sni[256];
  size_t sni_len;
  int client_verified;

  gq_tls_info info;
  int alert;
};

int g12_fail (gq_tls12 *t, unsigned alert, int status);
int g12_fail_parse (gq_tls12 *t, int status);
int g12_rnd (gq_tls12 *t, void *buf, size_t n);
uint64_t g12_now_ms (const gq_tls12 *t);
int g12_in_list (const uint16_t *l, size_t n, unsigned v);
int g12_gen_kx (gq_tls12 *t);
/* Add a received (g12_tb_add) or sent (g12_tb_add_tx) handshake message,
   TLS form, to the transcript.  In DTLS the transcript holds the 12-byte
   DTLS header with the message_seq and no fragmentation (RFC 6347
   section 4.2.6).  */
int g12_tb_add (gq_tls12 *t, const uint8_t *data, size_t len);
int g12_tb_add_tx (gq_tls12 *t, const uint8_t *data, size_t len);
int g12_tb_hash (const gq_tls12 *t, uint8_t *out);
/* Send the message in W and add it to the transcript.  */
int g12_send (gq_tls12 *t, const gq_wbuf *w);
/* Master secret from the premaster over the transcript so far (which must
   end at ClientKeyExchange), then wipe the premaster and ephemeral key.  */
int g12_derive_master (gq_tls12 *t);
int g12_derive_keys (gq_tls12 *t);
int g12_install_write (gq_tls12 *t);
int g12_install_read (gq_tls12 *t);
int g12_send_finished (gq_tls12 *t);
int g12_check_finished (gq_tls12 *t, gq_slice msg, gq_slice body);
int g12_complete (gq_tls12 *t);
/* Choose the scheme to sign with: ours, allowed by the peer's LIST (raw
   uint16 list) and fitting KEY.  0 if none.  */
unsigned g12_pick_scheme (const gq_tls12 *t, const gq_privkey *key,
                          gq_slice peer_list);
/* Server: handle one message; the client's messages are in tls12.c.  */
int g12_server_dispatch (gq_tls12 *t, gq_slice msg, gq_slice body);
int g12_server_ccs (gq_tls12 *t);
void g12_filter (gq_tls12 *t, const uint16_t *suites, size_t n_suites,
                 const uint16_t *sigs, size_t n_sigs);

#endif
