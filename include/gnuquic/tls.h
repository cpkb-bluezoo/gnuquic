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

/* TLS 1.3 handshake engine (RFC 8446).

   The engine is a reactive state machine.  It owns no socket, thread or
   timer and performs no I/O.  The embedding transport feeds it the bytes
   it receives and the engine reports what to do through the callbacks of
   a gq_tls_sink, all invoked synchronously from inside gq_tls_start and
   gq_tls_feed:

     send     handshake bytes to transmit, tagged with the encryption
              level whose keys must protect them;
     secret   a traffic secret to install for one direction of a level;
     ...

   The same engine serves QUIC (RFC 9001: handshake data travels in CRYPTO
   frames, one stream per level, and packet keys are derived from the
   secrets with gq_packet_keys_derive), TLS over TCP (a record layer maps
   levels to keys, and gq_traffic_keys derives them) and, later, DTLS 1.3.
   Only this module knows the handshake; the transport never inspects a
   handshake message.

   Levels: bytes at GQ_LEVEL_INITIAL are unprotected (ClientHello,
   ServerHello), GQ_LEVEL_EARLY is 0-RTT, GQ_LEVEL_HANDSHAKE covers
   EncryptedExtensions to Finished, GQ_LEVEL_APPLICATION everything after
   (tickets, KeyUpdate).  The engine checks that each message arrives at
   the right level and that no message straddles a key change.

   Failure: when the handshake cannot continue the engine calls
   sink->alert with the TLS alert code to send (RFC 8446 section 6.2; in
   QUIC the CRYPTO_ERROR is 0x100 plus that code), returns a negative
   status from the call that detected it, and refuses all further input.

   Ownership: the configuration is copied shallowly.  Every pointer in it
   (trust store, key, strings, arrays) must outlive the engine.  Slices
   handed to callbacks are valid only during the callback.  */

#ifndef GNUQUIC_TLS_H
#define GNUQUIC_TLS_H

#include <stddef.h>
#include <stdint.h>

#include <gnuquic/crypto.h>
#include <gnuquic/frame.h>	/* gq_slice */
#include <gnuquic/keysched.h>
#include <gnuquic/kx.h>
#include <gnuquic/replay.h>
#include <gnuquic/sign.h>
#include <gnuquic/tickets.h>
#include <gnuquic/trust.h>

#ifdef __cplusplus
extern "C" {
#endif

enum gq_level
{
  GQ_LEVEL_INITIAL = 0,
  GQ_LEVEL_EARLY = 1,
  GQ_LEVEL_HANDSHAKE = 2,
  GQ_LEVEL_APPLICATION = 3
};

enum gq_dir
{
  GQ_DIR_READ = 1,		/* Protects data we receive.  */
  GQ_DIR_WRITE = 2		/* Protects data we send.  */
};

/* TLS alert codes (RFC 8446 section 6.2) the engine may send.  */
enum gq_alert
{
  GQ_ALERT_CLOSE_NOTIFY = 0,
  GQ_ALERT_UNEXPECTED_MESSAGE = 10,
  GQ_ALERT_BAD_RECORD_MAC = 20,
  GQ_ALERT_HANDSHAKE_FAILURE = 40,
  GQ_ALERT_BAD_CERTIFICATE = 42,
  GQ_ALERT_UNSUPPORTED_CERTIFICATE = 43,
  GQ_ALERT_CERTIFICATE_REVOKED = 44,
  GQ_ALERT_CERTIFICATE_EXPIRED = 45,
  GQ_ALERT_CERTIFICATE_UNKNOWN = 46,
  GQ_ALERT_ILLEGAL_PARAMETER = 47,
  GQ_ALERT_UNKNOWN_CA = 48,
  GQ_ALERT_DECODE_ERROR = 50,
  GQ_ALERT_DECRYPT_ERROR = 51,
  GQ_ALERT_PROTOCOL_VERSION = 70,
  GQ_ALERT_INSUFFICIENT_SECURITY = 71,
  GQ_ALERT_INTERNAL_ERROR = 80,
  GQ_ALERT_NO_RENEGOTIATION = 100,	/* TLS 1.2 only.  */
  GQ_ALERT_MISSING_EXTENSION = 109,
  GQ_ALERT_UNSUPPORTED_EXTENSION = 110,
  GQ_ALERT_NO_APPLICATION_PROTOCOL = 120
};

/* A traffic secret for one direction at one level.  */
typedef struct gq_tls_secret
{
  enum gq_level level;
  enum gq_dir dir;
  enum gq_aead aead;		/* Negotiated AEAD.  */
  enum gq_hash hash;		/* Its hash (secret length).  */
  size_t len;
  uint8_t secret[GQ_MAX_HASH_LEN];
} gq_tls_secret;

/* Outcome of a completed handshake.  */
typedef struct gq_tls_info
{
  uint16_t cipher_suite;
  uint16_t group;		/* Key exchange group used.  */
  uint8_t alpn[255];		/* Selected protocol, alpn_len bytes.  */
  size_t alpn_len;
  int hello_retry;		/* A HelloRetryRequest happened.  */
  int resumed;			/* The session was resumed from a ticket (PSK),
				   so no certificates were exchanged.  */
  int client_auth_requested;	/* Server asked for a client certificate.  */
  int client_auth_sent;		/* ...and we sent one (client), or the peer
				   sent one that we verified (server).  */
  int early_data_accepted;	/* 0-RTT data was accepted (both roles).  */
  /* Server side: the host name the client asked for, if any.  */
  char server_name[256];
  size_t server_name_len;
} gq_tls_info;

/* A session ticket received from the server, with the PSK derived for
   it, ready to be stored for a later resumption.  */
typedef struct gq_tls_ticket
{
  gq_slice ticket;
  uint32_t lifetime;		/* Seconds.  */
  uint32_t age_add;
  uint32_t max_early_data;	/* 0 if 0-RTT is not offered.  */
  uint64_t received_ms;		/* When it arrived, by the engine's clock.  */
  uint16_t cipher_suite;
  enum gq_hash hash;
  size_t psk_len;
  uint8_t psk[GQ_MAX_HASH_LEN];
  uint8_t alpn[255];		/* Protocol of the connection it came from:  */
  size_t alpn_len;		/* early data is only valid for the same one.  */
} gq_tls_ticket;

/* A session ready to be stored and offered again: everything in a
   gq_tls_ticket, but with the ticket bytes copied into fixed storage so
   the value can be kept after the callback returns.  It contains the
   resumption PSK, a secret; wipe it with gq_tls_session_wipe.  */
typedef struct gq_tls_session
{
  uint8_t ticket[GQ_TICKET_MAX];
  size_t ticket_len;
  uint16_t cipher_suite;
  enum gq_hash hash;
  uint8_t psk[GQ_MAX_HASH_LEN];
  size_t psk_len;
  uint32_t lifetime;
  uint32_t age_add;
  uint32_t max_early_data;
  uint64_t received_ms;
  uint8_t alpn[255];
  size_t alpn_len;
} gq_tls_session;

/* Copy TICKET (as delivered by the ticket callback) into S.  Returns
   GQ_ERR_BUFSIZE if the server's ticket is larger than GQ_TICKET_MAX.  */
int gq_tls_session_store (gq_tls_session *s, const gq_tls_ticket *ticket);
void gq_tls_session_wipe (gq_tls_session *s);

/* Flat encoding for saving a session to disk or a database; the result
   is sensitive.  Decoding validates its input.  */
int gq_tls_session_serialize (const gq_tls_session *s, uint8_t *out,
                              size_t cap, size_t *out_len);
int gq_tls_session_deserialize (gq_tls_session *s, const uint8_t *data,
                                size_t len);

/* Callbacks.  All are optional except send and secret.  Return 0 to
   continue, nonzero to abort the handshake (the engine then fails with
   GQ_ERR_HANDLER and an internal_error alert).  */
typedef struct gq_tls_sink
{
  void *user;
  int (*send) (void *user, enum gq_level level, const uint8_t *data,
               size_t len);
  int (*secret) (void *user, const gq_tls_secret *secret);
  /* The peer's quic_transport_parameters (QUIC mode only).  */
  int (*peer_params) (void *user, const uint8_t *data, size_t len);
  /* Certificate validation.  If set, replaces the built-in check against
     the configured trust store; return 0 to accept the chain.  */
  int (*verify_peer) (void *user, const gq_slice *chain, size_t n,
                      const char *server_name);
  int (*ticket) (void *user, const gq_tls_ticket *ticket);
  /* Client: the server accepted (1) or rejected (0) the early data we
     offered.  Called when it is known (EncryptedExtensions, or a
     HelloRetryRequest, which always rejects).  On rejection everything
     sent as early data must be sent again under the handshake keys.  */
  int (*early_data) (void *user, int accepted);
  int (*complete) (void *user, const gq_tls_info *info);
  /* The engine is about to fail with this alert (sending it is the
     transport's job).  */
  int (*alert) (void *user, unsigned code);
} gq_tls_sink;

/* Overridable crypto inputs.  Real deployments leave these NULL; tests
   and platforms with their own entropy source use them.  */
typedef struct gq_tls_hooks
{
  void *user;
  int (*random) (void *user, void *buf, size_t len);
  int (*kx_generate) (void *user, unsigned group, gq_kx_key *key);
  /* Wall clock in milliseconds, used for ticket ages.  NULL uses time().  */
  uint64_t (*now_ms) (void *user);
} gq_tls_hooks;

typedef struct gq_tls_config
{
  /* Server name for SNI and host name verification.  NULL: no SNI, and no
     name check (the caller must then authenticate the peer otherwise).  */
  const char *server_name;
  /* ALPN protocols in preference order.  Required for QUIC.  */
  const gq_slice *alpn;
  size_t n_alpn;
  /* Preferences; NULL selects the policy defaults.  Anything outside the
     policy is silently dropped.  */
  const uint16_t *suites;
  size_t n_suites;
  const uint16_t *groups;
  size_t n_groups;
  const uint16_t *sigschemes;
  size_t n_sigschemes;
  /* Trust anchors, used unless sink->verify_peer is set.  */
  const gq_trust *trust;
  /* QUIC: our encoded transport parameters.  Setting this selects QUIC
     mode (no compatibility session ID, no KeyUpdate, ALPN mandatory).  */
  const uint8_t *transport_params;
  size_t transport_params_len;
  int quic;
  /* Client authentication: certificate chain (DER, leaf first) and key.
     Sent only if the server asks and the key fits an acceptable scheme.  */
  const gq_slice *client_chain;
  size_t n_client_chain;
  const gq_privkey *client_key;
  /* Offer this session for resumption.  Used only if it has not expired,
     its cipher suite is one we offer, and (after a HelloRetryRequest) the
     server still agrees on its hash; otherwise a full handshake runs.
     The server may decline: gq_tls_info.resumed says what happened.  */
  const gq_tls_session *resume;
  /* Offer 0-RTT data with the resumed session (if it allows any).  Early
     data can be replayed by an attacker, so send only what is safe to
     process twice.  The early write keys arrive through the sink's secret
     callback at GQ_LEVEL_EARLY; the amount is limited by the session's
     max_early_data.  */
  int early_data;
  /* TLS 1.3 client only, over a byte stream or datagrams (DTLS 1.3 also
     offers DTLS 1.2): also offer TLS 1.2 in this
     ClientHello (its suites, the version, and the extensions of the TLS 1.2
     profile), so a server that lacks TLS 1.3 can answer in TLS 1.2 within the
     same handshake.  Set by gq_tlsauto, which continues with a TLS 1.2
     engine if the server picks it; a bare engine would fail.  Refused with
     quic.  */
  int also_tls12;
  /* DTLS (RFC 9147 for the 1.3 engine, RFC 6347 for the 1.2 engine of
     tls12.h): set by gq_dtls and gq_dtls12, not by applications.  For 1.3:
     version 0xfefc, the legacy_cookie field, no compatibility session ID,
     "dtls13" HKDF labels.  Refused together with quic and early_data.  */
  int dtls;
  /* Largest handshake message body accepted.  0 selects 65536.  */
  size_t max_message_len;
  gq_tls_hooks hooks;
} gq_tls_config;

/* Credentials a server presents: a DER chain (leaf first) and the private
   key for the leaf.  */
typedef struct gq_tls_credentials
{
  const gq_slice *chain;
  size_t n_chain;
  const gq_privkey *key;
} gq_tls_credentials;

enum gq_client_auth
{
  GQ_CLIENT_AUTH_NONE = 0,
  GQ_CLIENT_AUTH_OPTIONAL,	/* Ask; accept a client that sends nothing.  */
  GQ_CLIENT_AUTH_REQUIRED	/* Ask; refuse a client that sends nothing.  */
};

typedef struct gq_tls_server_config
{
  /* Default credentials, used when select_credentials is NULL or when the
     client sent no server name and the callback returns them.  */
  gq_tls_credentials credentials;
  /* Choose credentials for a requested server name (NULL: none given).
     Return NULL to refuse (the client gets unrecognized_name).  */
  const gq_tls_credentials *(*select_credentials) (void *user,
                                                   const char *server_name);
  void *select_user;
  /* ALPN protocols in server preference order.  If set and the client
     offers ALPN with no overlap the handshake fails with
     no_application_protocol; if the client offers none, no protocol is
     selected (except in QUIC, where that is an error).  */
  const gq_slice *alpn;
  size_t n_alpn;
  /* Preferences in server order; NULL selects the policy defaults.  */
  const uint16_t *suites;
  size_t n_suites;
  const uint16_t *groups;
  size_t n_groups;
  const uint16_t *sigschemes;
  size_t n_sigschemes;
  /* QUIC: our transport parameters; setting them selects QUIC mode.  */
  const uint8_t *transport_params;
  size_t transport_params_len;
  int quic;
  /* Client authentication.  Verification uses client_trust, or
     sink->verify_peer if set (called with a NULL server name).  */
  enum gq_client_auth client_auth;
  const gq_trust *client_trust;
  /* Require the client to echo a random cookie in its second ClientHello
     after a HelloRetryRequest.  */
  int hello_retry_cookie;
  /* Resumption.  With a key ring the server issues stateless tickets
     after each handshake (TICKETS per handshake, default 2) valid for
     TICKET_LIFETIME seconds (default 86400, at most 604800) and accepts
     them.  A ticket is honoured only if it decrypts, is unexpired, names
     a cipher suite the client offers and we allow, was issued for the
     same server name, and (when client certificates are required) came
     from an authenticated session.  */
  gq_ticket_keys *ticket_keys;
  uint32_t ticket_lifetime;
  unsigned n_tickets;
  /* 0-RTT.  MAX_EARLY_DATA (bytes; 0 disables) is advertised in tickets.
     Early data is accepted only if REPLAY_CHECK is set and returns nonzero
     for the ticket (see replay.h; gq_replay_cache_check fits), if the
     ticket is the first identity, the ALPN matches the original
     connection's, no HelloRetryRequest is needed, and the client's ticket
     age agrees with ours within EARLY_DATA_WINDOW_MS (default 10000).  */
  uint32_t max_early_data;
  uint32_t early_data_window_ms;
  int (*replay_check) (void *user, const uint8_t id_hash[32],
                       uint64_t expires_ms, uint64_t now_ms);
  void *replay_user;
  /* Optional external lookup: given a PSK identity, fill STATE and return
     0 to accept it (used for tickets kept in a database, or for tests).
     Tried when the key ring does not recognise the identity.  */
  int (*psk_lookup) (void *user, const uint8_t *identity, size_t len,
                     gq_session_state *state);
  void *psk_user;
  size_t max_message_len;
  /* TLS 1.2 server only: this endpoint also serves TLS 1.3, so the
     ServerHello random ends with the downgrade sentinel of RFC 8446
     section 4.1.3, which lets a TLS 1.3 client that was tricked into TLS 1.2
     notice.  Set by gq_tlsauto; leave zero otherwise.  */
  int tls13_sentinel;
  /* DTLS 1.3 server: as gq_tls_config.dtls.  Refused with quic; early
     data is off and hello_retry_cookie is ignored (the address-bound
     stateless cookie of dtlscookie.h is used instead).  */
  int dtls;
  gq_tls_hooks hooks;
} gq_tls_server_config;

/* What a DTLS server that answered ClientHello1 statelessly (with a
   cookie) needs to continue when ClientHello2 arrives; see dtlscookie.h.
   HRR is the exact HelloRetryRequest message that was sent.  */
#define GQ_DTLS_HRR_MAX 320
typedef struct gq_tls_dtls_prime
{
  uint16_t suite;			/* Selected in the HelloRetryRequest.  */
  uint16_t group;			/* Group it asked for, or 0.  */
  uint8_t ch1_hash[GQ_MAX_HASH_LEN];	/* Hash of ClientHello1, by suite.  */
  uint8_t hrr[GQ_DTLS_HRR_MAX];		/* The message as sent (TLS form).  */
  size_t hrr_len;
} gq_tls_dtls_prime;


typedef struct gq_tls gq_tls;

/* Server, DTLS only, before the first gq_tls_feed: continue a handshake
   whose ClientHello1 and HelloRetryRequest were handled statelessly.  The
   transcript is restarted from message_hash (ClientHello1) and the
   retry, as if this engine had sent it.  ClientHello2 is then fed as the
   first message; it must pick the suite of the prime, and cannot cause a
   second retry.  */
int gq_tls_server_prime (gq_tls *tls, const gq_tls_dtls_prime *prime);

/* DTLS: tell the engine a KeyUpdate of ours is unacknowledged.  While set,
   an update_requested from the peer is ignored instead of answered
   (RFC 9147 section 8: never two KeyUpdates in flight).  */
void gq_tls_set_key_update_busy (gq_tls *tls, int busy);

/* Create a server engine.  It sends nothing until the ClientHello
   arrives through gq_tls_feed; gq_tls_start does not apply to servers.
   The sink's send and secret callbacks are required.  */
int gq_tls_server_new (gq_tls **out, const gq_tls_server_config *config,
                       const gq_tls_sink *sink);

/* Server: replace the ticket key ring.  QUIC does this from the
   peer_params callback (which runs before tickets are read) to select the
   ring bound to the QUIC version in use.  */
void gq_tls_server_set_ticket_keys (gq_tls *tls, gq_ticket_keys *keys);

/* Server: nonzero if the client offered 0-RTT data and this engine
   declined it.  The transport should then discard the undecryptable early
   records that follow (see gq_record_set_skip_budget).  */
int gq_tls_early_data_offered (const gq_tls *tls);

/* Either role: nonzero if 0-RTT data was accepted.  */
int gq_tls_early_data_accepted (const gq_tls *tls);

/* Create a client engine.  Nothing is sent until gq_tls_start.  */
int gq_tls_client_new (gq_tls **out, const gq_tls_config *config,
                       const gq_tls_sink *sink);
void gq_tls_free (gq_tls *tls);

/* Begin the handshake: builds the ClientHello and sends it at
   GQ_LEVEL_INITIAL.  */
int gq_tls_start (gq_tls *tls);

/* Feed handshake bytes received at LEVEL.  Consumes the whole buffer
   (partial messages are held internally, bounded by max_message_len), so
   *BUF and *LEN are advanced to the end.  Returns GQ_OK or a negative
   status after which the engine has failed.  */
int gq_tls_feed (gq_tls *tls, enum gq_level level, const uint8_t **buf,
                 size_t *len);

int gq_tls_is_complete (const gq_tls *tls);
int gq_tls_is_failed (const gq_tls *tls);

/* The alert the engine failed with, or -1.  */
int gq_tls_alert (const gq_tls *tls);

/* Request a key update of our sending keys (TLS over TCP only, RFC 8446
   section 4.6.3).  If REQUEST_PEER is nonzero the peer is asked to update
   its keys too.  The new write secret is delivered through the sink.  */
int gq_tls_key_update (gq_tls *tls, int request_peer);

/* Keying material exporter (RFC 8446 section 7.5, RFC 5705).  Valid once
   the handshake is complete.  */
int gq_tls_export (const gq_tls *tls, const char *label,
                   const uint8_t *context, size_t context_len,
                   uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* GNUQUIC_TLS_H */
