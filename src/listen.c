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

#include <string.h>

#include <gnuquic/status.h>
#include <gnuquic/crypto.h>
#include <gnuquic/packet.h>
#include <gnuquic/listen.h>

static void
set_cid (gq_cid *c, const uint8_t *d, size_t n)
{
  c->len = (uint8_t) n;
  memcpy (c->data, d, n);
}

int
gq_quic_admit (const gq_token_keys *keys, const gq_admit_config *cfg,
               const uint8_t *addr, size_t addr_len, const uint8_t *data,
               size_t len, uint64_t now_s, uint8_t *out, size_t cap,
               size_t *reply_len, gq_conn_accept *acc)
{
  gq_long_header h;
  gq_token_info info;
  uint32_t retry_life = cfg && cfg->retry_lifetime_s ? cfg->retry_lifetime_s
                                                       : 10;
  uint32_t new_life = cfg && cfg->new_token_lifetime_s
                      ? cfg->new_token_lifetime_s : 86400;
  int r, have_token = 0;

  *reply_len = 0;
  memset (acc, 0, sizeof *acc);
  if (addr_len > sizeof acc->addr)
    return GQ_ERR_INVAL;
  if (len < GQ_MIN_INITIAL_DATAGRAM || !(data[0] & 0x80))
    return GQ_ADMIT_DROP;
  r = gq_long_header_parse (data, len, &h);
  if (r == GQ_ERR_UNSUPPORTED)
    {
      /* Never answer a Version Negotiation packet with another.  */
      static const uint32_t ours[2] = { GQ_VERSION_1, GQ_VERSION_2 };
      uint8_t bits = 0;

      if (h.version == GQ_VERSION_NEGOTIATION)
        return GQ_ADMIT_DROP;
      gq_random (&bits, 1);
      if (gq_vn_build (h.scid.data, h.scid.len, h.dcid.data, h.dcid.len, ours,
                       2, bits, out, cap, reply_len) != GQ_OK)
        return GQ_ADMIT_DROP;
      return GQ_ADMIT_REPLY;
    }
  if (r != GQ_OK || h.type != GQ_PKT_INITIAL || h.dcid.len < 8)
    return GQ_ADMIT_DROP;

  if (keys && h.token.len
      && gq_token_check (keys, addr, addr_len, h.token.data, h.token.len,
                         now_s, retry_life, new_life, &info) == GQ_OK)
    {
      if (info.kind == GQ_TOKEN_RETRY)
        {
          /* The client must now address us by the ID we chose.  */
          if (h.dcid.len == info.scid.len
              && memcmp (h.dcid.data, info.scid.data, h.dcid.len) == 0)
            {
              acc->odcid = info.odcid;
              acc->retry_scid = info.scid;
              have_token = 1;
            }
        }
      else
        have_token = 1;
    }
  if (have_token)
    acc->validated = 1;
  else if (cfg && cfg->require_retry && keys)
    {
      gq_cid odcid, scid;
      uint8_t token[GQ_TOKEN_MAX], bits = 0;
      size_t tl, n = cfg->retry_cid_len ? cfg->retry_cid_len : 8;

      if (n > GQ_MAX_CID_LEN)
        n = GQ_MAX_CID_LEN;
      set_cid (&odcid, h.dcid.data, h.dcid.len);
      scid.len = (uint8_t) n;
      if (gq_random (scid.data, n) != GQ_OK
          || gq_token_make (keys, GQ_TOKEN_RETRY, addr, addr_len, &odcid,
                            &scid, now_s, token, &tl) != GQ_OK)
        return GQ_ERR_CRYPTO;
      gq_random (&bits, 1);
      if (gq_retry_build (h.version, h.scid.data, h.scid.len, scid.data,
                          scid.len, token, tl, h.dcid.data, h.dcid.len, bits,
                          out, cap, reply_len) != GQ_OK)
        return GQ_ERR_BUFSIZE;
      return GQ_ADMIT_REPLY;
    }
  acc->token_keys = keys;
  memcpy (acc->addr, addr, addr_len);
  acc->addr_len = addr_len;
  return GQ_ADMIT_ACCEPT;
}
