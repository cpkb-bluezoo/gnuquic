#!/bin/sh
# DTLS 1.3 interoperability: the GNU QUIC association against wolfSSL, in
# both directions, over real UDP sockets.  Skipped (exit 77) when the
# programs or openssl are missing, or GQ_NO_INTEROP is set.
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

OURS=${INTEROP_DTLS:-./interop-dtls}
WOLF=${WOLF_DTLS:-./wolf-dtls}
[ -x "$OURS" ] || exit 77
[ -x "$WOLF" ] || exit 77
case $OURS in /*) ;; *) OURS=$(pwd)/$OURS ;; esac
case $WOLF in /*) ;; *) WOLF=$(pwd)/$WOLF ;; esac
OPENSSL=${OPENSSL:-$(command -v openssl)}
[ -n "$OPENSSL" ] || exit 77
"$WOLF" >/dev/null 2>&1
[ $? = 77 ] && exit 77			# built without DTLS 1.3

T=$(mktemp -d "${TMPDIR:-/tmp}/gq-dtls.XXXXXX") || exit 77
SERVER_PID=
cleanup ()
{
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT INT TERM

fails=0
runs=0

cd "$T" || exit 77
gen_ok=1
"$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.pem -subj "/CN=Interop CA" -days 2 \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign >/dev/null 2>&1 || gen_ok=0
"$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca2.key -out ca2.pem -subj "/CN=Other CA" -days 2 \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign >/dev/null 2>&1 || gen_ok=0
printf 'subjectAltName=DNS:example.test\nextendedKeyUsage=serverAuth\n' > srv.ext
printf 'subjectAltName=DNS:client.test\nextendedKeyUsage=clientAuth\n' > cli.ext
mkcert ()
{
  name=$1; shift
  case $name in bad*) issuer=ca2 ;; *) issuer=ca ;; esac
  case $name in *cli*) ext=cli.ext ;; *) ext=srv.ext ;; esac
  "$OPENSSL" req -new -newkey "$@" -nodes -keyout "$name.key" -out "$name.csr" \
    -subj "/CN=$name" >/dev/null 2>&1 &&
  "$OPENSSL" x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" \
    -CAcreateserial -out "$name.pem" -days 2 -extfile "$ext" >/dev/null 2>&1
}
{
  mkcert ec ec -pkeyopt ec_paramgen_curve:P-256 &&
  mkcert rsa rsa:2048 &&
  mkcert bad ec -pkeyopt ec_paramgen_curve:P-256 &&
  mkcert cli ec -pkeyopt ec_paramgen_curve:P-256 &&
  mkcert badcli ec -pkeyopt ec_paramgen_curve:P-256
} || gen_ok=0
[ $gen_ok = 1 ] || { echo "cannot generate certificates" >&2; exit 77; }

free_port ()
{
  python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("127.0.0.1",0));print(s.getsockname()[1])' 2>/dev/null \
    || echo $((20000 + $$ % 20000 + runs))
}

# check_output FILE PATTERN...: every pattern must appear.
check_output ()
{
  f=$1; shift
  for pat in "$@"; do
    grep -q -- "$pat" "$f" || { echo "    missing: $pat"; return 1; }
  done
  return 0
}

# start SERVERCMD ARGS...: start a server in the background on a fresh
# port ($port), retrying if the port is taken; log in server.log.
start ()
{
  attempt=0
  while [ $attempt -lt 5 ]; do
    port=$(free_port)
    cmd=$1; shift
    "$cmd" server "$port" "$@" >server.log 2>&1 &
    SERVER_PID=$!
    n=0
    while ! grep -q listening server.log 2>/dev/null \
          && kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 50 ]; do
      sleep 0.1; n=$((n + 1))
    done
    grep -q listening server.log && return 0
    kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=
    set -- "$cmd" "$@"; shift
    attempt=$((attempt + 1))
  done
  return 1
}

stop ()
{
  [ -n "$SERVER_PID" ] && { kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; }
  SERVER_PID=
}

# ours_client NAME "SERVER ARGS (wolfSSL)" "CLIENT ARGS" WANT PATTERN...
#   Our client against the wolfSSL server.
ours_client ()
{
  name=$1; sargs=$2; cargs=$3; want=$4; shift 4
  case $name in *"${GQ_INTEROP_FILTER:-}"*) ;; *) return ;; esac
  runs=$((runs + 1))
  # shellcheck disable=SC2086
  if ! start "$WOLF" --cert ec.pem --key ec.key $sargs; then
    echo "FAIL $name: server did not start"; cat server.log
    fails=$((fails + 1)); return
  fi
  # shellcheck disable=SC2086
  "$OURS" client 127.0.0.1 "$port" --ca ca.pem --sni example.test $cargs \
    >client.out 2>client.err
  rc=$?
  n=0
  while kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 40 ]; do sleep 0.1; n=$((n + 1)); done
  stop
  ok=1
  [ "$want" = ok ] && [ $rc -ne 0 ] && ok=0
  [ "$want" = fail ] && [ $rc -eq 0 ] && ok=0
  [ $ok = 1 ] && { check_output client.out "$@" || ok=0; }
  if [ $ok = 1 ]; then echo "PASS $name"; else
    echo "FAIL $name (exit $rc)"
    sed 's/^/    client: /' client.out client.err | head -20
    sed 's/^/    server: /' server.log | head -20
    fails=$((fails + 1))
  fi
}

# ours_client_srv NAME SERVERPROG "SERVER ARGS" "CLIENT ARGS" WANT PATTERN...
#   Same with any server program and its full arguments (cert included).
ours_client_srv ()
{
  name=$1; sprog=$2; sargs=$3; cargs=$4; want=$5; shift 5
  case $name in *"${GQ_INTEROP_FILTER:-}"*) ;; *) return ;; esac
  runs=$((runs + 1))
  # shellcheck disable=SC2086
  if ! start "$sprog" $sargs; then
    echo "FAIL $name: server did not start"; cat server.log
    fails=$((fails + 1)); return
  fi
  # shellcheck disable=SC2086
  "$OURS" client 127.0.0.1 "$port" --ca ca.pem --sni example.test $cargs \
    >client.out 2>client.err
  rc=$?
  n=0
  while kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 40 ]; do sleep 0.1; n=$((n + 1)); done
  stop
  ok=1
  [ "$want" = ok ] && [ $rc -ne 0 ] && ok=0
  [ "$want" = fail ] && [ $rc -eq 0 ] && ok=0
  [ $ok = 1 ] && { check_output client.out "$@" || ok=0; }
  if [ $ok = 1 ]; then echo "PASS $name"; else
    echo "FAIL $name (exit $rc)"
    sed 's/^/    client: /' client.out client.err | head -20
    sed 's/^/    server: /' server.log | head -20
    fails=$((fails + 1))
  fi
}

# wolf_client NAME "SERVER ARGS (ours)" "CLIENT ARGS" WANT PATTERN...
#   The wolfSSL client against our server.
wolf_client ()
{
  name=$1; sargs=$2; cargs=$3; want=$4; shift 4
  case $name in *"${GQ_INTEROP_FILTER:-}"*) ;; *) return ;; esac
  runs=$((runs + 1))
  # shellcheck disable=SC2086
  if ! start "$OURS" --cert ec.pem --key ec.key $sargs; then
    echo "FAIL $name: server did not start"; cat server.log
    fails=$((fails + 1)); return
  fi
  # shellcheck disable=SC2086
  "$WOLF" client 127.0.0.1 "$port" --ca ca.pem --sni example.test $cargs \
    >client.out 2>client.err
  rc=$?
  n=0
  while kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 60 ]; do sleep 0.1; n=$((n + 1)); done
  stop
  ok=1
  [ "$want" = ok ] && [ $rc -ne 0 ] && ok=0
  [ "$want" = fail ] && [ $rc -eq 0 ] && ok=0
  cat client.out server.log > both.out
  [ $ok = 1 ] && { check_output both.out "$@" || ok=0; }
  if [ $ok = 1 ] && [ "$want" = ok ]; then
    check_output server.log "result=ok" || ok=0
  fi
  if [ $ok = 1 ]; then echo "PASS $name"; else
    echo "FAIL $name (exit $rc)"
    sed 's/^/    client: /' client.out client.err | head -20
    sed 's/^/    server: /' server.log | head -20
    fails=$((fails + 1))
  fi
}

# ---- our client, wolfSSL server ----
ours_client "dtls/wolf-server: default (negotiates 1.3)" "" "" ok "connected suite=" "echoed=3" "version=fefc" "result=ok"
ours_client "dtls/wolf-server: stateless cookie (negotiates 1.3)" "--stateless" "" ok "hrr=1" "version=fefc" "result=ok"
ours_client "dtls/wolf-server: HelloRetryRequest cookie" "--cookie" "" ok "hrr=1" "result=ok"
ours_client "dtls/wolf-server: stateless cookie" "--stateless" "" ok "hrr=1" "result=ok"
ours_client "dtls/wolf-server: AES-256-GCM" "--cipher TLS13-AES256-GCM-SHA384" "" ok "suite=0x1302"
ours_client "dtls/wolf-server: ChaCha20-Poly1305" "--cipher TLS13-CHACHA20-POLY1305-SHA256" "--suites chacha" ok "suite=0x1303"
ours_client "dtls/wolf-server: secp256r1" "" "--groups p256" ok "group=0x0017"
ours_client "dtls/wolf-server: hybrid X25519MLKEM768" "--cookie --ch-frag" "--groups x25519mlkem768" ok "group=0x11ec" "hrr=1"
ours_client "dtls/wolf-server: several messages" "" "--messages 12" ok "echoed=12"
ours_client "dtls/wolf-server: small MTU (fragmentation)" "" "--mtu 300" ok "result=ok"
ours_client "dtls/wolf-server: client certificate" "--client-auth ca.pem" \
  "--cert cli.pem --key cli.key" ok "client_auth_requested=1" "client_auth=1"
ours_client "dtls/wolf-server: resumption" "--connections 2" "--twice" ok "resumed=0" "resumed=1"
ours_client "dtls/wolf-server: KeyUpdate" "" "--messages 8 --key-update" ok "echoed=8"
ours_client "dtls/wolf-server: 15% loss" "" "--loss 15 --seed 3 --messages 5" ok "result=ok"
ours_client "dtls/wolf-server: 25% loss, cookie" "--cookie" "--loss 25 --seed 11 --messages 5" ok "result=ok"
ours_client_srv "dtls/wolf-server: RSA certificate" "$WOLF" "--cert rsa.pem --key rsa.key" "" ok "result=ok"
ours_client_srv "dtls/wolf-server: untrusted certificate" "$WOLF" "--cert bad.pem --key bad.key" "" fail "result=fail"

# ---- wolfSSL client, our server ----
wolf_client "dtls/our-server: default" "" "" ok "connected version=DTLSv1.3" "echoed=3"
wolf_client "dtls/our-server: cookie" "--cookie" "" ok "echoed=3"
wolf_client "dtls/our-server: hybrid group" "--cookie" "--group x25519mlkem768" ok "echoed=3"
wolf_client "dtls/our-server: several messages" "" "--messages 12" ok "echoed=12"
wolf_client "dtls/our-server: small MTU" "--mtu 300" "" ok "echoed=3"
wolf_client "dtls/our-server: ChaCha20" "--suites chacha" "--cipher TLS13-CHACHA20-POLY1305-SHA256" ok "echoed=3"
wolf_client "dtls/our-server: client certificate" "--client-auth required --ca ca.pem" \
  "--cert cli.pem --key cli.key" ok "client_auth=1"
wolf_client "dtls/our-server: client certificate required, absent" \
  "--client-auth required --ca ca.pem" "" fail "result=fail"
wolf_client "dtls/our-server: resumption" "--connections 2" "--twice" ok "resumed=1"
wolf_client "dtls/our-server: 25% loss during the handshake" \
  "--loss 25 --seed 5 --loss-handshake" "--messages 4" ok "echoed=4"
wolf_client "dtls/our-server: 30% loss during the handshake, cookie" \
  "--cookie --loss 30 --seed 9 --loss-handshake" "--messages 4" ok "echoed=4"

echo "$runs scenarios, $fails failed"
if [ $runs -eq 0 ]; then exit 77; fi
[ $fails -eq 0 ]
