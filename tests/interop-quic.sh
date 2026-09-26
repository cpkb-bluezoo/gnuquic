#!/bin/sh
# QUIC interoperability: the GNU QUIC connection against quiche (its
# quiche-client and quiche-server), in both directions, over real UDP
# sockets, speaking hq-interop (HTTP/0.9 style requests).  Skipped (exit 77)
# when the programs or openssl are missing, or GQ_NO_INTEROP is set.
# Set QUICHE_DIR to the directory holding quiche-client and quiche-server.
# GQ_INTEROP_FILTER=text runs only the scenarios whose names contain it.
#
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
# This file is part of GNU QUIC.
#
# GNU QUIC is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

[ -n "$GQ_NO_INTEROP" ] && exit 77

OURS=${INTEROP_QUIC:-./interop-quic}
QDIR=${QUICHE_DIR:-$(pwd)/../../../quiche/target/release}
[ -x "$OURS" ] || exit 77
[ -x "$QDIR/quiche-client" ] && [ -x "$QDIR/quiche-server" ] || exit 77
case $OURS in /*) ;; *) OURS=$(pwd)/$OURS ;; esac
OPENSSL=${OPENSSL:-$(command -v openssl)}
[ -n "$OPENSSL" ] || exit 77

T=$(mktemp -d "${TMPDIR:-/tmp}/gq-quic.XXXXXX") || exit 77
PIDS=
cleanup ()
{
  [ -n "$PIDS" ] && kill $PIDS 2>/dev/null
  wait 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT INT TERM
cd "$T" || exit 77

"$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.pem -subj "/CN=Interop CA" -days 2 \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign >/dev/null 2>&1 || exit 77
printf 'subjectAltName=DNS:example.test\nextendedKeyUsage=serverAuth\n' > srv.ext
"$OPENSSL" req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ec.key -out ec.csr -subj "/CN=ec" >/dev/null 2>&1 &&
"$OPENSSL" x509 -req -in ec.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out ec.pem -days 2 -extfile srv.ext >/dev/null 2>&1 || exit 77
mkdir root
head -c 1000 /dev/urandom > root/small
head -c 3000000 /dev/urandom > root/big
echo hello > root/hello

fails=0
runs=0
port=$((20000 + $$ % 20000))

want ()
{
  [ -z "$GQ_INTEROP_FILTER" ] || case $1 in *"$GQ_INTEROP_FILTER"*) return 0 ;; *) return 1 ;; esac
}

check_files ()
{
  dir=$1; shift
  for f in "$@"; do
    cmp -s "$dir/$f" "root/$f" || return 1
  done
}

report ()
{
  runs=$((runs + 1))
  if [ "$1" = 0 ]; then echo "ok   $2"; else echo "FAIL $2"; fails=$((fails + 1)); fi
}

# Our server, quiche's client (which starts with a reserved version, so
# every scenario also exercises Version Negotiation).
ours_server ()
{
  name=ours-server-$1; shift
  want "$name" || return 0
  port=$((port + 1))
  mkdir "out-$name"
  "$OURS" server $port --cert ec.pem --key ec.key --root root --timeout 30 \
    "$@" > "srv-$name.log" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"
  sleep 0.5
  case $name in *migrat*) qargs="--enable-active-migration --perform-migration --max-active-cids 4" ;; *) qargs= ;; esac
  "$QDIR/quiche-client" --http-version HTTP/0.9 --no-verify $qargs \
    --idle-timeout 20000 --dump-responses "out-$name" \
    https://127.0.0.1:$port/small https://127.0.0.1:$port/hello \
    https://127.0.0.1:$port/big > "cli-$name.log" 2>&1
  rc=$?
  kill $pid 2>/dev/null
  check_files "out-$name" small hello big || rc=1
  case $name in *migrat*)
    grep -q MIGRATED "srv-$name.log" || rc=1 ;;
  esac
  report $rc "$name"
}

# quiche's server, our client.
ours_client ()
{
  name=ours-client-$1; shift
  want "$name" || return 0
  port=$((port + 1))
  mkdir "out-$name"
  case $name in *retry*) noretry= ;; *) noretry=--no-retry ;; esac
  "$QDIR/quiche-server" --listen 127.0.0.1:$port --cert ec.pem --key ec.key \
    --root root --http-version HTTP/0.9 $noretry \
    --idle-timeout 20000 --enable-active-migration --max-active-cids 4 \
    > "qsrv-$name.log" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"
  sleep 0.5
  "$OURS" client 127.0.0.1 $port --ca ca.pem --out "out-$name" --timeout 40 \
    "$@" /small /hello /big > "cli-$name.log" 2>&1
  rc=$?
  kill $pid 2>/dev/null
  check_files "out-$name" small hello big || rc=1
  case $name in *migrat*)
    grep -q MIGRATED "cli-$name.log" || rc=1 ;;
  esac
  report $rc "$name"
}

ours_server plain
ours_server loss --loss 20 --seed 3
ours_server retry --retry
ours_server migration
ours_server retry-loss --retry --loss 15 --seed 4
ours_client plain
ours_client loss --loss 10 --seed 5
ours_client key-update --key-update
ours_client retry
ours_client migration --migrate
ours_client retry-loss --loss 10 --seed 6

# Several connections to one endpoint at once.
if want ours-server-concurrent; then
  name=ours-server-concurrent
  port=$((port + 1))
  "$OURS" server $port --cert ec.pem --key ec.key --root root --timeout 30 \
    --connections 4 > "srv-$name.log" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"
  sleep 0.5
  rc=0
  for k in 1 2 3 4; do
    mkdir "out-$name-$k"
    ( "$QDIR/quiche-client" --http-version HTTP/0.9 --no-verify \
        --idle-timeout 20000 --dump-responses "out-$name-$k" \
        https://127.0.0.1:$port/big https://127.0.0.1:$port/small \
        > "cli-$name-$k.log" 2>&1 ) &
  done
  wait $(jobs -p | grep -v "^$pid\$") 2>/dev/null
  for k in 1 2 3 4; do
    check_files "out-$name-$k" big small || rc=1
  done
  kill $pid 2>/dev/null
  report $rc "$name"
fi

# DATAGRAM frames (RFC 9221).  quiche only exchanges them under HTTP/3, so
# the request itself is not answered; the datagrams are what counts.
if want ours-server-datagram; then
  name=ours-server-datagram
  port=$((port + 1))
  "$OURS" server $port --cert ec.pem --key ec.key --root root --timeout 15 \
    --connections 1 --dgram 3 --alpn h3 > "srv-$name.log" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"
  sleep 0.5
  RUST_LOG=info "$QDIR/quiche-client" --http-version HTTP/3 --no-verify \
    --idle-timeout 3000 --dgram-proto oneway --dgram-count 3 \
    https://127.0.0.1:$port/small > "cli-$name.log" 2>&1
  wait $pid 2>/dev/null
  rc=0
  [ "$(grep -c '^DATAGRAM' "srv-$name.log")" = 3 ] || rc=1
  [ "$(grep -c 'Received DATAGRAM' "cli-$name.log")" = 3 ] || rc=1
  report $rc "$name"
fi
if want ours-client-datagram; then
  name=ours-client-datagram
  port=$((port + 1))
  RUST_LOG=info "$QDIR/quiche-server" --listen 127.0.0.1:$port --cert ec.pem \
    --key ec.key --root root --http-version HTTP/3 --no-retry \
    --dgram-proto oneway --dgram-count 3 --idle-timeout 4000 \
    > "qsrv-$name.log" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"
  sleep 0.5
  mkdir "out-$name"
  "$OURS" client 127.0.0.1 $port --ca ca.pem --out "out-$name" --timeout 5 \
    --alpn h3 --dgram 3 /small > "cli-$name.log" 2>&1
  kill $pid 2>/dev/null
  rc=0
  [ "$(grep -c '^DATAGRAM' "cli-$name.log")" = 3 ] || rc=1
  [ "$(grep -c 'Received DATAGRAM' "qsrv-$name.log")" = 3 ] || rc=1
  report $rc "$name"
fi

# 0-RTT: a first connection leaves a session; the second speaks in its first
# flight.  quiche's greased first version would send its early data in the
# wrong version (and not again after Version Negotiation), so it starts in v1.
if want ours-server-early; then
  name=ours-server-early
  port=$((port + 1))
  "$OURS" server $port --cert ec.pem --key ec.key --root root --timeout 20 \
    --connections 2 --early > "srv-$name.log" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"
  sleep 0.5
  rc=0
  for k in 1 2; do
    mkdir "out-$name-$k"
    "$QDIR/quiche-client" --wire-version 1 --http-version HTTP/0.9 \
      --no-verify --idle-timeout 4000 --early-data \
      --session-file "sess-$name" --dump-responses "out-$name-$k" \
      https://127.0.0.1:$port/small > "cli-$name-$k.log" 2>&1
    check_files "out-$name-$k" small || rc=1
  done
  wait $pid 2>/dev/null
  grep -q '^EARLY_DATA' "srv-$name.log" || rc=1
  report $rc "$name"
fi
if want ours-client-early; then
  name=ours-client-early
  port=$((port + 1))
  "$QDIR/quiche-server" --listen 127.0.0.1:$port --cert ec.pem --key ec.key \
    --root root --http-version HTTP/0.9 --no-retry --early-data \
    --idle-timeout 20000 > "qsrv-$name.log" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"
  sleep 0.5
  rc=0
  for k in 1 2; do
    mkdir "out-$name-$k"
    "$OURS" client 127.0.0.1 $port --ca ca.pem --out "out-$name-$k" \
      --timeout 10 --early --session-file "sess-$name" /small /hello \
      > "cli-$name-$k.log" 2>&1 || rc=1
    check_files "out-$name-$k" small hello || rc=1
  done
  kill $pid 2>/dev/null
  grep -q 'EARLY accepted=1' "cli-$name-2.log" || rc=1
  report $rc "$name"
fi

echo "$runs scenarios, $fails failed"
[ $fails = 0 ]
