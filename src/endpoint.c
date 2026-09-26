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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <gnuquic/status.h>
#include <gnuquic/crypto.h>
#include <gnuquic/packet.h>
#include <gnuquic/endpoint.h>

#define MAX_REPLIES 16
#define MAX_ENTRY_CIDS 14
#define MAX_ENTRY_TOKENS 20
#define REPLY_MAX 1500

struct entry
{
  gq_endpoint *ep;
  gq_conn *c;
  int woken, dead;
  unsigned timers;		/* Heap items naming this entry.  */
  uint64_t deadline;		/* Last scheduled; 0: none.  */
  unsigned gen;
  size_t index;			/* In ep->conns.  */
  gq_cid cids[MAX_ENTRY_CIDS];	/* What is registered for it.  */
  size_t n_cids;
  uint8_t toks[MAX_ENTRY_TOKENS][GQ_RESET_TOKEN_LEN];
  size_t n_toks;
};

struct slot
{
  uint8_t state;		/* 0 empty, 1 used, 2 deleted.  */
  uint8_t len;
  uint8_t cid[GQ_MAX_CID_LEN];
  struct entry *e;
};

struct table
{
  struct slot *tab;
  size_t cap, used, dead;
};

struct timer
{
  uint64_t at;
  struct entry *e;
  unsigned gen;
};

struct reply
{
  gq_path to;
  size_t len;
  uint8_t data[REPLY_MAX];
};

struct gq_endpoint
{
  gq_endpoint_config cfg;
  gq_endpoint_events ev;
  int serving, closed;
  size_t cid_len;
  gq_token_keys keys;
  gq_tls_server_config scfg;	/* The server's, with our tickets and 0-RTT.  */
  gq_ticket_keys *ticket_ring;
  gq_replay_cache *replay;
  uint64_t seed;
  /* Connection IDs, and the peers' stateless reset tokens (as keys of
     their own length).  */
  struct table cids, tokens;
  /* Connections.  */
  struct entry **conns;
  size_t n_conns, cap_conns;
  /* Connections with something to send, in turn.  */
  struct entry **wake;
  size_t wake_head, wake_n, wake_cap;
  /* Deadlines.  */
  struct timer *heap;
  size_t heap_n, heap_cap;
  /* Answers of our own.  */
  struct reply replies[MAX_REPLIES];
  size_t reply_head, reply_n;
  /* Stateless reset rate limit.  */
  uint64_t reset_window;
  unsigned resets_in_window;
};

/* ---- Hashing and the ID table ---- */

static uint64_t
hash_cid (const gq_endpoint *ep, const uint8_t *cid, size_t len)
{
  uint64_t h = 1469598103934665603ULL ^ ep->seed;
  size_t i;

  for (i = 0; i < len; i++)
    {
      h ^= cid[i];
      h *= 1099511628211ULL;
    }
  h ^= h >> 33;
  h *= 0xff51afd7ed558ccdULL;
  h ^= h >> 33;
  return h;
}

static int
tab_grow (const gq_endpoint *ep, struct table *t)
{
  size_t ncap = t->cap ? t->cap * 2 : 64, i;
  struct slot *nt = calloc (ncap, sizeof *nt);

  if (nt == NULL)
    return GQ_ERR_NOMEM;
  for (i = 0; i < t->cap; i++)
    if (t->tab[i].state == 1)
      {
        size_t k = (size_t) hash_cid (ep, t->tab[i].cid, t->tab[i].len)
                   & (ncap - 1);

        while (nt[k].state)
          k = (k + 1) & (ncap - 1);
        nt[k] = t->tab[i];
      }
  free (t->tab);
  t->tab = nt;
  t->cap = ncap;
  t->dead = 0;
  return GQ_OK;
}

static struct slot *
tab_find (const gq_endpoint *ep, const struct table *t, const uint8_t *key,
          size_t len)
{
  size_t k;

  if (t->cap == 0)
    return NULL;
  k = (size_t) hash_cid (ep, key, len) & (t->cap - 1);
  while (t->tab[k].state)
    {
      if (t->tab[k].state == 1 && t->tab[k].len == len
          && memcmp (t->tab[k].cid, key, len) == 0)
        return &t->tab[k];
      k = (k + 1) & (t->cap - 1);
    }
  return NULL;
}

static struct entry *
lookup (const gq_endpoint *ep, const uint8_t *cid, size_t len)
{
  struct slot *s = tab_find (ep, &ep->cids, cid, len);

  return s ? s->e : NULL;
}

static int
tab_insert (const gq_endpoint *ep, struct table *t, struct entry *e,
            const uint8_t *key, size_t len)
{
  size_t k;

  if (tab_find (ep, t, key, len))
    return 0;			/* Taken (astronomically unlikely).  */
  if ((t->used + t->dead + 1) * 2 > t->cap && tab_grow (ep, t) != GQ_OK)
    return 0;
  k = (size_t) hash_cid (ep, key, len) & (t->cap - 1);
  while (t->tab[k].state == 1)
    k = (k + 1) & (t->cap - 1);
  if (t->tab[k].state == 2)
    t->dead--;
  t->tab[k].state = 1;
  t->tab[k].len = (uint8_t) len;
  memcpy (t->tab[k].cid, key, len);
  t->tab[k].e = e;
  t->used++;
  return 1;
}

static void
tab_remove (const gq_endpoint *ep, struct table *t, struct entry *e,
            const uint8_t *key, size_t len)
{
  struct slot *s = tab_find (ep, t, key, len);

  if (s == NULL || s->e != e)
    return;
  s->state = 2;
  t->used--;
  t->dead++;
}

static void
register_cid (gq_endpoint *ep, struct entry *e, const uint8_t *cid, size_t len)
{
  if (len == 0 || len > GQ_MAX_CID_LEN || e->n_cids >= MAX_ENTRY_CIDS)
    return;
  if (!tab_insert (ep, &ep->cids, e, cid, len))
    return;
  e->cids[e->n_cids].len = (uint8_t) len;
  memcpy (e->cids[e->n_cids].data, cid, len);
  e->n_cids++;
}

static void
unregister_cid (gq_endpoint *ep, struct entry *e, const uint8_t *cid,
                size_t len)
{
  size_t i;

  tab_remove (ep, &ep->cids, e, cid, len);
  for (i = 0; i < e->n_cids; i++)
    if (e->cids[i].len == len && memcmp (e->cids[i].data, cid, len) == 0)
      {
        e->cids[i] = e->cids[--e->n_cids];
        break;
      }
}

/* ---- Timers and the wake list ---- */

static void
heap_push (gq_endpoint *ep, uint64_t at, struct entry *e, unsigned gen)
{
  size_t i;

  if (ep->heap_n == ep->heap_cap)
    {
      size_t cap = ep->heap_cap ? ep->heap_cap * 2 : 64;
      struct timer *nh = realloc (ep->heap, cap * sizeof *nh);

      if (nh == NULL)
        return;
      ep->heap = nh;
      ep->heap_cap = cap;
    }
  i = ep->heap_n++;
  while (i > 0 && ep->heap[(i - 1) / 2].at > at)
    {
      ep->heap[i] = ep->heap[(i - 1) / 2];
      i = (i - 1) / 2;
    }
  ep->heap[i].at = at;
  ep->heap[i].e = e;
  ep->heap[i].gen = gen;
  e->timers++;
}

static void
heap_pop (gq_endpoint *ep)
{
  struct timer last;
  struct entry *gone;
  size_t i = 0;

  if (ep->heap_n == 0)
    return;
  gone = ep->heap[0].e;
  last = ep->heap[--ep->heap_n];
  while (1)
    {
      size_t l = 2 * i + 1, r = l + 1, m = i;
      uint64_t best = last.at;

      if (l < ep->heap_n && ep->heap[l].at < best)
        {
          m = l;
          best = ep->heap[l].at;
        }
      if (r < ep->heap_n && ep->heap[r].at < best)
        m = r;
      if (m == i)
        break;
      ep->heap[i] = ep->heap[m];
      i = m;
    }
  if (ep->heap_n)
    ep->heap[i] = last;
  /* A finished connection's entry lives until its timers have drained.  */
  if (--gone->timers == 0 && gone->dead)
    free (gone);
}

static void
reschedule (gq_endpoint *ep, struct entry *e)
{
  uint64_t d = gq_conn_timeout (e->c);

  if (d == e->deadline)
    return;
  e->deadline = d;
  e->gen++;
  if (d)
    heap_push (ep, d, e, e->gen);
}

static void
mark_woken (gq_endpoint *ep, struct entry *e)
{
  if (e->woken)
    return;
  if (ep->wake_head + ep->wake_n == ep->wake_cap)
    {
      if (ep->wake_head)
        {
          memmove (ep->wake, ep->wake + ep->wake_head,
                   ep->wake_n * sizeof *ep->wake);
          ep->wake_head = 0;
        }
      else
        {
          size_t cap = ep->wake_cap ? ep->wake_cap * 2 : 64;
          struct entry **nw = realloc (ep->wake, cap * sizeof *nw);

          if (nw == NULL)
            return;
          ep->wake = nw;
          ep->wake_cap = cap;
        }
    }
  ep->wake[ep->wake_head + ep->wake_n++] = e;
  e->woken = 1;
}

/* ---- Router hooks ---- */

static void
r_issued (void *user, gq_conn *c, const uint8_t *cid, size_t len)
{
  struct entry *e = user;

  (void) c;
  register_cid (e->ep, e, cid, len);
}

static void
r_retired (void *user, gq_conn *c, const uint8_t *cid, size_t len)
{
  struct entry *e = user;

  (void) c;
  unregister_cid (e->ep, e, cid, len);
}

static void
r_wake (void *user, gq_conn *c)
{
  struct entry *e = user;

  (void) c;
  mark_woken (e->ep, e);
}

static void
r_token (void *user, gq_conn *c, const uint8_t token[GQ_RESET_TOKEN_LEN])
{
  struct entry *e = user;

  (void) c;
  if (e->n_toks >= MAX_ENTRY_TOKENS)
    return;
  if (tab_insert (e->ep, &e->ep->tokens, e, token, GQ_RESET_TOKEN_LEN))
    memcpy (e->toks[e->n_toks++], token, GQ_RESET_TOKEN_LEN);
}

static void
reset_token (void *user, const uint8_t *cid, size_t len,
             uint8_t token[GQ_RESET_TOKEN_LEN])
{
  const gq_endpoint *ep = user;
  uint8_t mac[32];

  gq_hmac (GQ_HASH_SHA256, ep->cfg.reset_key, sizeof ep->cfg.reset_key, cid,
           len, mac, sizeof mac);
  memcpy (token, mac, GQ_RESET_TOKEN_LEN);
}

/* ---- Connections ---- */

static void
detach (gq_endpoint *ep, struct entry *e)
{
  size_t i;

  while (e->n_cids)
    {
      gq_cid c = e->cids[e->n_cids - 1];

      unregister_cid (ep, e, c.data, c.len);
    }
  while (e->n_toks)
    {
      e->n_toks--;
      tab_remove (ep, &ep->tokens, e, e->toks[e->n_toks], GQ_RESET_TOKEN_LEN);
    }
  for (i = ep->wake_head; i < ep->wake_head + ep->wake_n; i++)
    if (ep->wake[i] == e)
      {
        memmove (ep->wake + i, ep->wake + i + 1,
                 (ep->wake_head + ep->wake_n - i - 1) * sizeof *ep->wake);
        ep->wake_n--;
        break;
      }
  e->gen++;			/* Pending timers are stale now.  */
  ep->conns[e->index] = ep->conns[--ep->n_conns];
  ep->conns[e->index]->index = e->index;
}

static void
reap (gq_endpoint *ep, struct entry *e)
{
  gq_conn *c = e->c;

  detach (ep, e);
  if (ep->ev.done)
    ep->ev.done (ep->ev.user, c);
  gq_conn_free (c);
  /* Stale heap items may still name the entry: it is freed with the last.  */
  e->c = NULL;
  e->dead = 1;
  if (e->timers == 0)
    free (e);
}

static struct entry *
adopt (gq_endpoint *ep, gq_conn *c)
{
  struct entry *e;
  gq_conn_router r;
  gq_cid cids[MAX_ENTRY_CIDS];
  size_t i, n;

  if (ep->n_conns == ep->cap_conns)
    {
      size_t cap = ep->cap_conns ? ep->cap_conns * 2 : 64;
      struct entry **nc = realloc (ep->conns, cap * sizeof *nc);

      if (nc == NULL)
        return NULL;
      ep->conns = nc;
      ep->cap_conns = cap;
    }
  e = calloc (1, sizeof *e);
  if (e == NULL)
    return NULL;
  e->ep = ep;
  e->c = c;
  e->index = ep->n_conns;
  ep->conns[ep->n_conns++] = e;
  memset (&r, 0, sizeof r);
  r.user = e;
  r.cid_issued = r_issued;
  r.cid_retired = r_retired;
  r.wake = r_wake;
  r.peer_token = r_token;
  gq_conn_set_router (c, &r);
  n = gq_conn_local_cids (c, cids, MAX_ENTRY_CIDS);
  for (i = 0; i < n; i++)
    register_cid (ep, e, cids[i].data, cids[i].len);
  mark_woken (ep, e);
  return e;
}

static void
conn_config (gq_endpoint *ep, const gq_conn_config *base,
             gq_conn_config *out)
{
  *out = base ? *base : ep->cfg.conn;
  out->cid_len = ep->cid_len;
  out->reset_token = reset_token;
  out->reset_user = ep;
}

/* ---- Public interface ---- */

int
gq_endpoint_new (gq_endpoint **out, const gq_endpoint_config *config,
                 const gq_endpoint_events *events)
{
  gq_endpoint *ep;

  if (out == NULL || config == NULL || events == NULL
      || (config->server && events->accept == NULL))
    return GQ_ERR_INVAL;
  *out = NULL;
  if (gq_crypto_init () != GQ_OK)
    return GQ_ERR_CRYPTO;
  ep = calloc (1, sizeof *ep);
  if (ep == NULL)
    return GQ_ERR_NOMEM;
  ep->cfg = *config;
  ep->ev = *events;
  ep->serving = config->server != NULL;
  if (ep->cfg.max_connections == 0)
    ep->cfg.max_connections = 1024;
  if (ep->cfg.max_resets_per_second == 0)
    ep->cfg.max_resets_per_second = 100;
  if (ep->cfg.admit.n_versions == 0 && (ep->cfg.conn.n_versions
                                        || ep->cfg.conn.version))
    {
      /* Offer, in Version Negotiation, what the connections will serve.  */
      if (ep->cfg.conn.n_versions)
        {
          memcpy (ep->cfg.admit.versions, ep->cfg.conn.versions,
                  sizeof ep->cfg.admit.versions);
          ep->cfg.admit.n_versions = ep->cfg.conn.n_versions;
        }
      else
        {
          ep->cfg.admit.versions[0] = ep->cfg.conn.version;
          ep->cfg.admit.n_versions = 1;
        }
    }
  ep->cid_len = config->conn.cid_len ? config->conn.cid_len : 8;
  if (ep->cid_len > GQ_MAX_CID_LEN)
    ep->cid_len = GQ_MAX_CID_LEN;
  if (!config->have_reset_key)
    gq_random (ep->cfg.reset_key, sizeof ep->cfg.reset_key);
  gq_random (&ep->seed, sizeof ep->seed);
  if (gq_token_keys_init (&ep->keys) != GQ_OK)
    {
      free (ep);
      return GQ_ERR_CRYPTO;
    }
  if (config->server)
    {
      ep->scfg = *config->server;
      if (config->tickets && ep->scfg.ticket_keys == NULL)
        {
          if (gq_ticket_keys_new (&ep->ticket_ring) != GQ_OK)
            goto fail;
          ep->scfg.ticket_keys = ep->ticket_ring;
        }
      if (config->early_data && ep->scfg.ticket_keys)
        {
          if (ep->scfg.replay_check == NULL)
            {
              if (gq_replay_cache_new (&ep->replay,
                                       config->replay_capacity
                                       ? config->replay_capacity : 65536)
                  != GQ_OK)
                goto fail;
              ep->scfg.replay_check = gq_replay_cache_check;
              ep->scfg.replay_user = ep->replay;
            }
          if (ep->scfg.max_early_data == 0)
            ep->scfg.max_early_data = 0xffffffffU;
        }
    }
  *out = ep;
  return GQ_OK;
fail:
  gq_ticket_keys_free (ep->ticket_ring);
  gq_replay_cache_free (ep->replay);
  gq_token_keys_wipe (&ep->keys);
  free (ep);
  return GQ_ERR_NOMEM;
}

void
gq_endpoint_free (gq_endpoint *ep)
{
  if (ep == NULL)
    return;
  while (ep->n_conns)
    {
      struct entry *e = ep->conns[ep->n_conns - 1];
      gq_conn *c = e->c;

      detach (ep, e);
      gq_conn_free (c);
      e->dead = 1;
      if (e->timers == 0)
        free (e);
    }
  /* Entries are freed as the heap drains.  */
  while (ep->heap_n)
    heap_pop (ep);
  free (ep->conns);
  free (ep->wake);
  free (ep->heap);
  free (ep->cids.tab);
  free (ep->tokens.tab);
  gq_token_keys_wipe (&ep->keys);
  gq_ticket_keys_free (ep->ticket_ring);
  gq_replay_cache_free (ep->replay);
  memset (ep->cfg.reset_key, 0, sizeof ep->cfg.reset_key);
  free (ep);
}

int
gq_endpoint_connect (gq_endpoint *ep, uint64_t now_us,
                     const gq_tls_config *tls, const gq_conn_config *conn,
                     const gq_path *path, const gq_conn_events *events,
                     gq_conn **out)
{
  gq_conn_config cc;
  gq_conn *c;
  struct entry *e;
  int r;

  if (ep->closed || ep->n_conns >= ep->cfg.max_connections)
    return GQ_ERR_RANGE;
  conn_config (ep, conn, &cc);
  if (path)
    cc.path = *path;
  r = gq_conn_client_new (&c, &cc, tls, events, now_us);
  if (r != GQ_OK)
    return r;
  e = adopt (ep, c);
  if (e == NULL)
    {
      gq_conn_free (c);
      return GQ_ERR_NOMEM;
    }
  if (ep->ev.connection)
    ep->ev.connection (ep->ev.user, c);
  reschedule (ep, e);
  *out = c;
  return GQ_OK;
}

static int
queue_reply (gq_endpoint *ep, const gq_path *to, const uint8_t *d, size_t len)
{
  struct reply *r;

  if (ep->reply_n == MAX_REPLIES || len > REPLY_MAX)
    return 0;
  r = &ep->replies[(ep->reply_head + ep->reply_n++) % MAX_REPLIES];
  r->to = *to;
  r->len = len;
  memcpy (r->data, d, len);
  return 1;
}

/* Datagram for a connection ID we do not know that looks like the start of a
   connection.  */
static int
admit (gq_endpoint *ep, uint64_t now, const gq_path *from, uint8_t *data,
       size_t len)
{
  gq_admit_config ac = ep->cfg.admit;
  gq_conn_accept acc;
  uint8_t reply[REPLY_MAX];
  size_t rl = 0;
  uint64_t wall;
  int act;
  gq_conn_events cev;
  gq_conn_config cc;
  gq_conn *c;
  struct entry *e;
  gq_long_header h;

  if (!ep->serving || ep->closed || from == NULL || from->remote.len == 0)
    return GQ_OK;
  if (ep->cfg.retry_above && ep->n_conns >= ep->cfg.retry_above)
    ac.require_retry = 1;
  wall = ep->cfg.conn.wall_seconds
         ? ep->cfg.conn.wall_seconds (ep->cfg.conn.wall_user)
         : (uint64_t) time (NULL);
  act = gq_quic_admit (&ep->keys, &ac, from->remote.data, from->remote.len,
                       data, len, wall, reply, sizeof reply, &rl, &acc);
  if (act == GQ_ADMIT_REPLY)
    queue_reply (ep, from, reply, rl);
  if (act != GQ_ADMIT_ACCEPT)
    return act < 0 ? act : GQ_OK;
  if (ep->n_conns >= ep->cfg.max_connections)
    return GQ_OK;
  memset (&cev, 0, sizeof cev);
  if (ep->ev.accept (ep->ev.user, from, &cev) != 0)
    return GQ_OK;
  conn_config (ep, NULL, &cc);
  if (gq_conn_server_accept (&c, &cc, &ep->scfg, &cev, now, &acc)
      != GQ_OK)
    return GQ_ERR_NOMEM;
  e = adopt (ep, c);
  if (e == NULL)
    {
      gq_conn_free (c);
      return GQ_ERR_NOMEM;
    }
  /* The client's first Initials name the ID it invented (or the one we gave
     in a Retry, which is ours already).  */
  if (gq_long_header_parse (data, len, &h) == GQ_OK)
    register_cid (ep, e, h.dcid.data, h.dcid.len);
  if (ep->ev.connection)
    ep->ev.connection (ep->ev.user, c);
  gq_conn_recv_path (c, now, from, data, len);
  mark_woken (ep, e);
  reschedule (ep, e);
  return GQ_OK;
}

/* A short header packet for nobody: tell the peer to stop (RFC 9000 10.3).  */
static void
stateless_reset (gq_endpoint *ep, uint64_t now, const gq_path *from,
                 const uint8_t *data, size_t len)
{
  uint8_t token[GQ_RESET_TOKEN_LEN], out[REPLY_MAX];
  size_t n = 0;

  if (ep->cfg.no_stateless_reset || from == NULL || from->remote.len == 0
      || len < 1 + ep->cid_len)
    return;
  if (now - ep->reset_window >= 1000000)
    {
      ep->reset_window = now;
      ep->resets_in_window = 0;
    }
  if (ep->resets_in_window >= ep->cfg.max_resets_per_second)
    return;
  reset_token (ep, data + 1, ep->cid_len, token);
  if (gq_stateless_reset_build (len, token, out, sizeof out, &n) != GQ_OK)
    return;
  if (queue_reply (ep, from, out, n))
    ep->resets_in_window++;
}

int
gq_endpoint_recv (gq_endpoint *ep, uint64_t now_us, const gq_path *from,
                  uint8_t *data, size_t len)
{
  struct entry *e = NULL;

  if (len == 0)
    return GQ_OK;
  if (data[0] & 0x80)
    {
      gq_long_header h;
      int r = gq_long_header_parse (data, len, &h);

      if (r == GQ_OK || r == GQ_ERR_UNSUPPORTED)
        e = lookup (ep, h.dcid.data, h.dcid.len);
      if (e == NULL)
        return admit (ep, now_us, from, data, len);
    }
  else
    {
      if (len < 1 + ep->cid_len)
        return GQ_OK;
      e = lookup (ep, data + 1, ep->cid_len);
      if (e == NULL)
        {
          /* A reset from a peer we talk to?  Its token ends the datagram.  */
          if (len >= GQ_STATELESS_RESET_MIN_LEN)
            {
              struct slot *t = tab_find (ep, &ep->tokens, data + len
                                                          - GQ_RESET_TOKEN_LEN,
                                         GQ_RESET_TOKEN_LEN);

              if (t)
                {
                  gq_conn_stateless_reset (t->e->c, now_us);
                  mark_woken (ep, t->e);
                  reschedule (ep, t->e);
                  return GQ_OK;
                }
            }
          stateless_reset (ep, now_us, from, data, len);
          return GQ_OK;
        }
    }
  gq_conn_recv_path (e->c, now_us, from, data, len);
  mark_woken (ep, e);
  reschedule (ep, e);
  if (gq_conn_state (e->c) == GQ_CONN_DONE)
    reap (ep, e);
  return GQ_OK;
}

int
gq_endpoint_send (gq_endpoint *ep, uint64_t now_us, uint8_t *out, size_t cap,
                  size_t *len, gq_path *to)
{
  *len = 0;
  if (ep->reply_n)
    {
      struct reply *r = &ep->replies[ep->reply_head];

      if (cap < r->len)
        return GQ_ERR_BUFSIZE;
      memcpy (out, r->data, r->len);
      *len = r->len;
      if (to)
        *to = r->to;
      ep->reply_head = (ep->reply_head + 1) % MAX_REPLIES;
      ep->reply_n--;
      return GQ_OK;
    }
  while (ep->wake_n)
    {
      struct entry *e = ep->wake[ep->wake_head];
      int r = gq_conn_send_path (e->c, now_us, out, cap, len, to);

      if (r != GQ_OK)
        return r;
      if (*len)
        {
          /* Others get their turn: to the back of the line.  */
          ep->wake_head++;
          ep->wake_n--;
          e->woken = 0;
          mark_woken (ep, e);
          reschedule (ep, e);
          return GQ_OK;
        }
      ep->wake_head++;
      ep->wake_n--;
      e->woken = 0;
      if (ep->wake_n == 0)
        ep->wake_head = 0;
      reschedule (ep, e);
      if (gq_conn_state (e->c) == GQ_CONN_DONE)
        reap (ep, e);
    }
  return GQ_OK;
}

uint64_t
gq_endpoint_timeout (gq_endpoint *ep)
{
  while (ep->heap_n)
    {
      struct timer *t = &ep->heap[0];

      if (!t->e->dead && t->gen == t->e->gen && t->e->deadline == t->at)
        return t->at;
      heap_pop (ep);
    }
  return 0;
}

void
gq_endpoint_on_timeout (gq_endpoint *ep, uint64_t now_us)
{
  while (ep->heap_n)
    {
      struct timer t = ep->heap[0];
      struct entry *e = t.e;

      int stale = e->dead || t.gen != e->gen || e->deadline != t.at;

      if (t.at > now_us && !stale)
        break;
      /* Popping may free a finished connection's entry: decide first.  */
      heap_pop (ep);
      if (stale)
        continue;
      e->deadline = 0;
      gq_conn_on_timeout (e->c, now_us);
      mark_woken (ep, e);
      reschedule (ep, e);
      if (gq_conn_state (e->c) == GQ_CONN_DONE)
        reap (ep, e);
    }
}

size_t
gq_endpoint_connections (const gq_endpoint *ep)
{
  return ep->n_conns;
}

void
gq_endpoint_close (gq_endpoint *ep, uint64_t now_us, int application,
                   uint64_t error, const char *reason)
{
  size_t i;

  ep->closed = 1;
  for (i = 0; i < ep->n_conns; i++)
    {
      gq_conn_close (ep->conns[i]->c, now_us, application, error, reason);
      mark_woken (ep, ep->conns[i]);
      reschedule (ep, ep->conns[i]);
    }
}

int
gq_endpoint_rotate_keys (gq_endpoint *ep)
{
  if (ep->ticket_ring)
    gq_ticket_keys_rotate (ep->ticket_ring);
  return gq_token_keys_rotate (&ep->keys);
}
