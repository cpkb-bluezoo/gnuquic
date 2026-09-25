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

/* A scripted TLS 1.3 server peer for testing the client engine.

   It is built from the library's own message codecs, key schedule and
   signing, but it is not the server engine: it takes whole messages,
   makes fixed decisions, and exposes every secret so tests can compare
   both ends.  Faults are injected by the tests by editing the messages it
   returns.  */

#ifndef GQ_TST_TLSPEER_H
#define GQ_TST_TLSPEER_H

#include <gnuquic/status.h>
#include <gnuquic/policy.h>
#include <gnuquic/tlsmsg.h>
#include <gnuquic/transcript.h>
#include <gnuquic/keysched.h>
#include <gnuquic/kx.h>
#include <gnuquic/sign.h>

#include "tst-util.h"

#define FLIGHT_MAX 8

/* A flight is a list of whole handshake messages.  */
struct flight
{
  uint8_t data[16384];
  size_t off[FLIGHT_MAX], len[FLIGHT_MAX];
  int n;
  size_t used;
};

static inline void
flight_add (struct flight *f, const uint8_t *m, size_t n)
{
  memcpy (f->data + f->used, m, n);
  f->off[f->n] = f->used;
  f->len[f->n] = n;
  f->n++;
  f->used += n;
}

struct tst_peer
{
  gq_transcript *tr;
  enum gq_hash hash;
  enum gq_aead aead;
  uint16_t suite;
  size_t hlen;
  gq_ks ks;
  uint8_t chs[48], shs[48], cas[48], sas[48], exp[48], resm[48];

  /* Configuration.  */
  const gq_privkey *key;
  gq_slice chain[2];
  size_t n_chain;
  int quic;
  gq_slice tp;
  gq_slice alpn_pick;		/* Empty: send no ALPN.  */
  int force_hrr;
  unsigned hrr_group;
  int hrr_cookie;
  int request_cert;
  unsigned pick_suite;		/* 0: server preference.  */
  unsigned pick_group;		/* 0: the client's first offered share.  */

  /* Observed.  */
  int hrr_done;
  uint8_t sid[32];
  size_t sid_len;
  gq_slice client_tp;
  uint8_t client_tp_buf[512];
  size_t client_tp_len;
  int client_sent_cert;
  uint16_t chosen_group;
};

static inline int
peer_suite_params (unsigned s, enum gq_aead *a, enum gq_hash *h)
{
  switch (s)
    {
    case GQ_TLS_AES_128_GCM_SHA256:
      *a = GQ_AEAD_AES_128_GCM; *h = GQ_HASH_SHA256; return 1;
    case GQ_TLS_AES_256_GCM_SHA384:
      *a = GQ_AEAD_AES_256_GCM; *h = GQ_HASH_SHA384; return 1;
    case GQ_TLS_CHACHA20_POLY1305_SHA256:
      *a = GQ_AEAD_CHACHA20_POLY1305; *h = GQ_HASH_SHA256; return 1;
    default:
      return 0;
    }
}

static inline void
peer_finish_wbuf (gq_wbuf *w, struct flight *f, gq_transcript *tr)
{
  CHECK_EQ (gq_wbuf_status (w), GQ_OK);
  if (tr)
    gq_transcript_update (tr, w->p, w->len);
  flight_add (f, w->p, w->len);
}

static inline size_t
peer_cv_content (uint8_t *out, int server, const uint8_t *th, size_t hlen)
{
  memset (out, 0x20, 64);
  memcpy (out + 64, server ? "TLS 1.3, server CertificateVerify"
                           : "TLS 1.3, client CertificateVerify", 33);
  out[97] = 0;
  memcpy (out + 98, th, hlen);
  return 98 + hlen;
}

/* Handle a ClientHello.  Fills INITIAL with ServerHello (or a
   HelloRetryRequest) and HS with the server's handshake flight.  */
static inline int
peer_handle_ch (struct tst_peer *p, const uint8_t *ch, size_t chlen,
                struct flight *initial, struct flight *hs)
{
  gq_client_hello c;
  gq_slice v, shares, kx, list;
  uint16_t group = 0, g;
  uint8_t buf[8192], th[48], shared[GQ_KX_SHARED_MAX], sh_kx[GQ_KX_SHARE_MAX];
  size_t i, slen, sharedlen;
  gq_wbuf w;
  gq_sh_params sp;
  gq_slice sid_echo;
  int r;
  static const uint16_t pref[] = { GQ_TLS_AES_128_GCM_SHA256,
                                   GQ_TLS_CHACHA20_POLY1305_SHA256,
                                   GQ_TLS_AES_256_GCM_SHA384 };

  memset (initial, 0, sizeof *initial);
  memset (hs, 0, sizeof *hs);
  r = gq_client_hello_parse ((gq_slice) { ch + 4, chlen - 4 }, &c);
  if (r != GQ_OK)
    return r;
  p->sid_len = c.session_id.len;
  memcpy (p->sid, c.session_id.data, c.session_id.len);
  sid_echo = c.session_id;

  if (!gq_ext_find (c.extensions, GQ_EXT_SUPPORTED_VERSIONS, &v)
      || gq_list_u16 (v, 1, &list) != GQ_OK || !gq_u16_contains (list, 0x0304))
    return GQ_ERR_PROTOCOL;
  if (gq_ext_find (c.extensions, GQ_EXT_QUIC_TRANSPORT_PARAMETERS, &v))
    {
      memcpy (p->client_tp_buf, v.data, v.len);
      p->client_tp_len = v.len;
    }

  if (p->suite == 0)
    {
      if (p->pick_suite && gq_u16_contains (c.cipher_suites, p->pick_suite))
        p->suite = (uint16_t) p->pick_suite;
      else
        for (i = 0; i < 3 && p->suite == 0; i++)
          if (gq_u16_contains (c.cipher_suites, pref[i]))
            p->suite = pref[i];
      if (p->suite == 0 || !peer_suite_params (p->suite, &p->aead, &p->hash))
        return GQ_ERR_UNSUPPORTED;
      p->hlen = gq_hash_size (p->hash);
      gq_transcript_new (&p->tr, p->hash);
    }
  gq_transcript_update (p->tr, ch, chlen);

  /* HelloRetryRequest on demand, before looking at any share.  */
  if (p->force_hrr && !p->hrr_done)
    {
      uint8_t ck[] = { 0xc0, 0x0c, 0x1e };

      memset (&sp, 0, sizeof sp);
      sp.hello_retry_request = 1;
      sp.session_id_echo = sid_echo;
      sp.cipher_suite = p->suite;
      sp.group = (uint16_t) p->hrr_group;
      if (p->hrr_cookie)
        sp.cookie = (gq_slice) { ck, sizeof ck };
      gq_wbuf_init (&w, buf, sizeof buf);
      gq_build_server_hello (&w, &sp);
      gq_transcript_hello_retry (p->tr);
      peer_finish_wbuf (&w, initial, p->tr);
      p->hrr_done = 1;
      return GQ_OK;
    }

  /* Key share choice: the group we insisted on after a retry, else the
     configured one, else whatever the client listed first.  */
  if (!gq_ext_find (c.extensions, GQ_EXT_KEY_SHARE, &v)
      || gq_ext_key_share_client (v, &shares) != GQ_OK)
    return GQ_ERR_PROTOCOL;
  {
    gq_slice rest = shares;
    unsigned want = p->hrr_done ? p->hrr_group : p->pick_group;
    int found = 0;

    while (!found && gq_key_share_next (&rest, &g, &kx) == 1)
      if (want == 0 || g == want)
        {
          group = g;
          found = 1;
        }
    if (!found)
      return GQ_ERR_PROTOCOL;
  }
  p->chosen_group = group;

  r = gq_kx_respond (group, kx.data, kx.len, sh_kx, sizeof sh_kx,
                     &slen, shared, sizeof shared, &sharedlen);
  if (r != GQ_OK)
    return r;

  /* ServerHello.  */
  memset (&sp, 0, sizeof sp);
  {
    uint8_t rnd[32];

    gq_random (rnd, 32);
    sp.random = rnd;
    sp.session_id_echo = sid_echo;
    sp.cipher_suite = p->suite;
    sp.group = group;
    sp.key_exchange = (gq_slice) { sh_kx, slen };
    gq_wbuf_init (&w, buf, sizeof buf);
    gq_build_server_hello (&w, &sp);
    peer_finish_wbuf (&w, initial, p->tr);
  }
  gq_ks_early (&p->ks, p->hash, NULL, 0);
  gq_ks_handshake (&p->ks, shared, sharedlen);
  gq_transcript_hash (p->tr, th, p->hlen);
  gq_ks_handshake_traffic (&p->ks, th, p->chs, p->shs);

  /* EncryptedExtensions.  */
  {
    gq_ext exts[4];
    size_t n = 0;
    uint8_t alpn[300], tpx[600];
    gq_wbuf a;

    if (p->alpn_pick.len)
      {
        gq_wbuf_init (&a, alpn, sizeof alpn);
        gq_wbuf_open (&a, 2);
        gq_wbuf_open (&a, 1);
        gq_wbuf_slice (&a, p->alpn_pick);
        gq_wbuf_close (&a);
        gq_wbuf_close (&a);
        exts[n].type = GQ_EXT_ALPN;
        exts[n].value = (gq_slice) { alpn, a.len };
        n++;
      }
    if (p->quic)
      {
        memcpy (tpx, p->tp.data, p->tp.len);
        exts[n].type = GQ_EXT_QUIC_TRANSPORT_PARAMETERS;
        exts[n].value = (gq_slice) { tpx, p->tp.len };
        n++;
      }
    gq_wbuf_init (&w, buf, sizeof buf);
    gq_build_encrypted_extensions (&w, exts, n);
    peer_finish_wbuf (&w, hs, p->tr);
  }

  if (p->request_cert)
    {
      gq_wbuf_init (&w, buf, sizeof buf);
      gq_wbuf_hs_open (&w, GQ_HS_CERTIFICATE_REQUEST);
      gq_wbuf_open (&w, 1);
      gq_wbuf_u8 (&w, 0x5a);
      gq_wbuf_u8 (&w, 0xa5);
      gq_wbuf_close (&w);
      gq_wbuf_open (&w, 2);
      gq_wbuf_ext_open (&w, GQ_EXT_SIGNATURE_ALGORITHMS);
      gq_wbuf_open (&w, 2);
      gq_wbuf_u16 (&w, GQ_SIG_ED25519);
      gq_wbuf_u16 (&w, GQ_SIG_ECDSA_SECP256R1_SHA256);
      gq_wbuf_close (&w);
      gq_wbuf_close (&w);
      gq_wbuf_close (&w);
      gq_wbuf_close (&w);
      peer_finish_wbuf (&w, hs, p->tr);
    }

  gq_wbuf_init (&w, buf, sizeof buf);
  gq_build_certificate (&w, (gq_slice) { NULL, 0 }, p->chain, p->n_chain);
  peer_finish_wbuf (&w, hs, p->tr);

  {
    uint8_t content[200], sig[GQ_SIGNATURE_MAX];
    size_t cn, siglen;

    gq_transcript_hash (p->tr, th, p->hlen);
    cn = peer_cv_content (content, 1, th, p->hlen);
    r = gq_privkey_sign (p->key, GQ_SIG_ECDSA_SECP256R1_SHA256, content, cn,
                         sig, sizeof sig, &siglen);
    if (r != GQ_OK)
      return r;
    gq_wbuf_init (&w, buf, sizeof buf);
    gq_build_certificate_verify (&w, GQ_SIG_ECDSA_SECP256R1_SHA256,
                                 (gq_slice) { sig, siglen });
    peer_finish_wbuf (&w, hs, p->tr);
  }

  {
    uint8_t vd[48];

    gq_transcript_hash (p->tr, th, p->hlen);
    gq_finished_verify_data (p->hash, p->shs, th, vd);
    gq_wbuf_init (&w, buf, sizeof buf);
    gq_build_finished (&w, (gq_slice) { vd, p->hlen });
    peer_finish_wbuf (&w, hs, p->tr);
  }
  gq_transcript_hash (p->tr, th, p->hlen);
  gq_ks_master (&p->ks);
  gq_ks_app_traffic (&p->ks, th, p->cas, p->sas);
  gq_ks_exporter_master (&p->ks, th, p->exp);
  return GQ_OK;
}

/* Process the client's final flight: [Certificate [CertificateVerify]]
   Finished.  Returns GQ_OK, GQ_ERR_CRYPTO on a bad Finished/signature or
   GQ_ERR_PROTOCOL on a structural problem.  */
static inline int
peer_handle_client_flight (struct tst_peer *p, const uint8_t *d, size_t len)
{
  const uint8_t *q = d;
  size_t l = len;
  uint8_t th[48], want[48];
  gq_pubkey *leaf = NULL;
  int r = GQ_OK;

  p->client_sent_cert = 0;
  while (l >= 4)
    {
      size_t n = 4 + (((size_t) q[1] << 16) | ((size_t) q[2] << 8) | q[3]);
      gq_slice body = { q + 4, n - 4 };

      if (n > l)
        return GQ_ERR_PROTOCOL;
      if (q[0] == GQ_HS_CERTIFICATE)
        {
          gq_slice ctx, entries, der, ex;

          if (gq_certificate_parse (body, &ctx, &entries) != GQ_OK
              || ctx.len != 2 || ctx.data[0] != 0x5a)
            return GQ_ERR_PROTOCOL;
          if (gq_cert_entry_next (&entries, &der, &ex) == 1)
            {
              p->client_sent_cert = 1;
              if (gq_pubkey_from_cert (&leaf, der.data, der.len) != GQ_OK)
                return GQ_ERR_CERT;
            }
        }
      else if (q[0] == GQ_HS_CERTIFICATE_VERIFY)
        {
          uint16_t scheme;
          gq_slice sig;
          uint8_t content[200];
          size_t cn;

          if (!leaf
              || gq_certificate_verify_parse (body, &scheme, &sig) != GQ_OK)
            return GQ_ERR_PROTOCOL;
          gq_transcript_hash (p->tr, th, p->hlen);
          cn = peer_cv_content (content, 0, th, p->hlen);
          r = gq_pubkey_verify (leaf, scheme, content, cn, sig.data, sig.len);
          if (r != GQ_OK)
            return GQ_ERR_CRYPTO;
        }
      else if (q[0] == GQ_HS_FINISHED)
        {
          gq_transcript_hash (p->tr, th, p->hlen);
          gq_finished_verify_data (p->hash, p->chs, th, want);
          if (body.len != p->hlen || !gq_ct_equal (want, body.data, p->hlen))
            r = GQ_ERR_CRYPTO;
        }
      else
        return GQ_ERR_PROTOCOL;
      gq_transcript_update (p->tr, q, n);
      q += n;
      l -= n;
    }
  gq_pubkey_free (leaf);
  if (r == GQ_OK)
    {
      gq_transcript_hash (p->tr, th, p->hlen);
      gq_ks_resumption_master (&p->ks, th, p->resm);
    }
  return r;
}

#endif
