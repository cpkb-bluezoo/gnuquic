#!/bin/sh
# DTLS 1.2 interoperability: the GNU QUIC association against OpenSSL and
# wolfSSL, in both directions, over real UDP sockets.  Skipped (exit 77)
# when the programs or openssl are missing, or GQ_NO_INTEROP is set.
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
case $OURS in /*) ;; *) OURS=$(pwd)/$OURS ;; esac
case $WOLF in /*) ;; *) WOLF=$(pwd)/$WOLF ;; esac
if [ -x "$WOLF" ]; then
  "$WOLF" >/dev/null 2>&1
  [ $? = 77 ] && WOLF=		# built without DTLS 1.3 (and 1.2) support
else
  WOLF=
fi
OPENSSL=${OPENSSL:-$(command -v openssl)}
GNUTLS_SERV=${GNUTLS_SERV:-$(command -v gnutls-serv)}
GNUTLS_CLI=${GNUTLS_CLI:-$(command -v gnutls-cli)}
P12="NORMAL:-VERS-ALL:+VERS-DTLS1.2"
[ -n "$OPENSSL" ] || exit 77
"$OPENSSL" s_client -help 2>&1 | grep -q dtls1_2 || exit 77

T=$(mktemp -d "${TMPDIR:-/tmp}/gq-dtls12.XXXXXX") || exit 77
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

check_output ()
{
  f=$1; shift
  for pat in "$@"; do
    grep -q -- "$pat" "$f" || { echo "    missing: $pat"; return 1; }
  done
  return 0
}

stop ()
{
  [ -n "$SERVER_PID" ] && { kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; }
  SERVER_PID=
}

# start_server KIND ARGS...: KIND is ours, wolf or openssl; sets $port.
start_server ()
{
  kind=$1; shift
  attempt=0
  while [ $attempt -lt 5 ]; do
    port=$(free_port)
    case $kind in
      ours) "$OURS" server "$port" --dtls12 "$@" >server.log 2>&1 & ;;
      wolf) "$WOLF" server "$port" --dtls12 "$@" >server.log 2>&1 & ;;
      # s_server sends what it reads on stdin once the client is connected;
      # a FIFO keeps it an ordinary background process.
      gnutls) "$GNUTLS_SERV" --udp --port="$port" --echo "$@" >server.log 2>&1 & ;;
      openssl) rm -f srvin; mkfifo srvin
               "$OPENSSL" s_server -dtls1_2 -accept "127.0.0.1:$port" -quiet \
                 "$@" <srvin >server.log 2>&1 & ;;
    esac
    SERVER_PID=$!
    n=0
    if [ $kind = gnutls ]; then
      sleep 1
      kill -0 "$SERVER_PID" 2>/dev/null && return 0
    elif [ $kind = openssl ]; then
      echo reply > srvin
      sleep 0.5
      kill -0 "$SERVER_PID" 2>/dev/null && return 0
    else
      while ! grep -q listening server.log 2>/dev/null \
            && kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 50 ]; do
        sleep 0.1; n=$((n + 1))
      done
      grep -q listening server.log && return 0
    fi
    kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=
    attempt=$((attempt + 1))
  done
  return 1
}

report ()
{
  name=$1; ok=$2
  if [ "$ok" = 1 ]; then echo "PASS $name"; else
    echo "FAIL $name (exit $rc)"
    sed 's/^/    client: /' client.out client.err | head -20
    sed 's/^/    server: /' server.log | head -20
    fails=$((fails + 1))
  fi
}

# ours_client NAME SERVERKIND "SERVER ARGS" "CLIENT ARGS" WANT PATTERN...
#   Our client against an OpenSSL or wolfSSL server.
ours_client ()
{
  name=$1; skind=$2; sargs=$3; cargs=$4; want=$5; shift 5
  case $name in *"${GQ_INTEROP_FILTER:-}"*) ;; *) return ;; esac
  [ $skind = wolf ] && [ -z "$WOLF" ] && return
  [ $skind = gnutls ] && [ -z "$GNUTLS_SERV" ] && return
  runs=$((runs + 1))
  # shellcheck disable=SC2086
  if ! start_server "$skind" $sargs; then
    echo "FAIL $name: server did not start"; cat server.log
    fails=$((fails + 1)); return
  fi
  # shellcheck disable=SC2086
  "$OURS" client 127.0.0.1 "$port" --dtls12 --ca ca.pem --sni example.test $cargs \
    >client.out 2>client.err
  rc=$?
  n=0
  [ $skind != openssl ] && while kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 40 ]; do sleep 0.1; n=$((n + 1)); done
  stop
  ok=1
  [ "$want" = ok ] && [ $rc -ne 0 ] && ok=0
  [ "$want" = fail ] && [ $rc -eq 0 ] && ok=0
  [ $ok = 1 ] && { check_output client.out "$@" || ok=0; }
  report "$name" $ok
}

# ours_server NAME CLIENTKIND "SERVER ARGS (ours)" "CLIENT ARGS" WANT PATTERN...
#   An OpenSSL or wolfSSL client against our server.  Patterns are looked
#   for in the server's and the client's output together.
ours_server ()
{
  name=$1; ckind=$2; sargs=$3; cargs=$4; want=$5; shift 5
  case $name in *"${GQ_INTEROP_FILTER:-}"*) ;; *) return ;; esac
  [ $ckind = wolf ] && [ -z "$WOLF" ] && return
  [ $ckind = gnutls ] && [ -z "$GNUTLS_CLI" ] && return
  runs=$((runs + 1))
  limit=; [ $ckind = openssl ] && limit="--max-bytes 6"
  # shellcheck disable=SC2086
  if ! start_server ours --cert ec.pem --key ec.key $limit $sargs; then
    echo "FAIL $name: server did not start"; cat server.log
    fails=$((fails + 1)); return
  fi
  case $ckind in
    openssl)
      # shellcheck disable=SC2086
      (printf 'hello\n'; sleep 2) | "$OPENSSL" s_client -dtls1_2 \
        -connect "127.0.0.1:$port" -CAfile ca.pem -servername example.test \
        -verify_hostname example.test -verify_return_error -quiet $cargs \
        >client.out 2>client.err
      rc=$?
      ;;
    wolf)
      # shellcheck disable=SC2086
      "$WOLF" client 127.0.0.1 "$port" --dtls12 --ca ca.pem --sni example.test \
        $cargs >client.out 2>client.err
      rc=$?
      ;;
    gnutls)
      # shellcheck disable=SC2086
      (printf 'hello\n'; sleep 2) | "$GNUTLS_CLI" --udp --x509cafile=ca.pem \
        --sni-hostname=example.test --verify-hostname=example.test \
        --port="$port" $cargs 127.0.0.1 >client.out 2>client.err
      rc=$?
      ;;
  esac
  n=0
  while kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 80 ]; do sleep 0.1; n=$((n + 1)); done
  stop
  ok=1
  cat client.out server.log > both.out
  [ $ok = 1 ] && { check_output both.out "$@" || ok=0; }
  if [ $ok = 1 ] && [ "$want" = ok ]; then
    check_output server.log "result=ok" || ok=0
  fi
  if [ $ok = 1 ] && [ "$want" = fail ]; then
    check_output server.log "result=fail" || ok=0
  fi
  report "$name" $ok
}

# ---- our client ----
ours_client "dtls12/openssl-server: default" openssl "-cert ec.pem -key ec.key" \
  "--rev" ok "connected suite=0xc0" "result=ok"
ours_client "dtls12/openssl-server: cookie exchange" openssl \
  "-cert ec.pem -key ec.key -listen" "--rev" ok "result=ok"
ours_client "dtls12/openssl-server: RSA certificate" openssl \
  "-cert rsa.pem -key rsa.key" "--rev" ok "result=ok"
ours_client "dtls12/openssl-server: ECDHE-ECDSA-AES256-GCM-SHA384" openssl \
  "-cert ec.pem -key ec.key -cipher ECDHE-ECDSA-AES256-GCM-SHA384" \
  "--rev" ok "suite=0xc02c"
ours_client "dtls12/openssl-server: ECDHE-ECDSA-CHACHA20-POLY1305" openssl \
  "-cert ec.pem -key ec.key -cipher ECDHE-ECDSA-CHACHA20-POLY1305" \
  "--rev --suites ecdsa-chacha" ok "suite=0xcca9"
ours_client "dtls12/openssl-server: ECDHE-RSA-AES128-GCM-SHA256" openssl \
  "-cert rsa.pem -key rsa.key -cipher ECDHE-RSA-AES128-GCM-SHA256" \
  "--rev" ok "suite=0xc02f"
ours_client "dtls12/openssl-server: small MTU" openssl \
  "-cert ec.pem -key ec.key" "--rev --mtu 400" ok "result=ok"
ours_client "dtls12/openssl-server: client certificate" openssl \
  "-cert ec.pem -key ec.key -Verify 1 -CAfile ca.pem" \
  "--rev --cert cli.pem --key cli.key" ok "client_auth=1"
ours_client "dtls12/openssl-server: untrusted certificate" openssl \
  "-cert bad.pem -key bad.key" "--rev --timeout 15" fail "result=fail"
ours_client "dtls12/openssl-server: server without extended master secret" openssl \
  "-cert ec.pem -key ec.key -no_ems" "--rev --timeout 15" fail "result=fail"
ours_client "dtls12/wolf-server: default" wolf "--cert ec.pem --key ec.key" \
  "" ok "echoed=3" "result=ok"
ours_client "dtls12/wolf-server: cookie" wolf "--cert ec.pem --key ec.key --cookie" \
  "" ok "result=ok"
ours_client "dtls12/wolf-server: RSA certificate" wolf "--cert rsa.pem --key rsa.key" \
  "" ok "result=ok"
ours_client "dtls12/wolf-server: resumption" wolf \
  "--cert ec.pem --key ec.key --connections 2" "--twice" ok "resumed=0" "resumed=1"
ours_client "dtls12/wolf-server: client certificate" wolf \
  "--cert ec.pem --key ec.key --client-auth ca.pem" \
  "--cert cli.pem --key cli.key" ok "client_auth=1"
ours_client "dtls12/wolf-server: several messages" wolf "--cert ec.pem --key ec.key" \
  "--messages 12" ok "echoed=12"
ours_client "dtls12/wolf-server: 15% loss" wolf "--cert ec.pem --key ec.key" \
  "--loss 15 --seed 3 --messages 5" ok "result=ok"
ours_client "dtls12/wolf-server: 25% loss, cookie" wolf \
  "--cert ec.pem --key ec.key --cookie" "--loss 25 --seed 11 --messages 5" ok "result=ok"

# ---- our server ----
ours_server "dtls12/openssl-client: default" openssl "" "" ok "connected suite=" "echoed=1"
ours_server "dtls12/openssl-client: cookie exchange" openssl "--cookie" "" ok \
  "cookie-verified" "echoed=1"
ours_server "dtls12/openssl-client: RSA certificate" openssl "--cert rsa.pem --key rsa.key" "" ok "echoed=1"
ours_server "dtls12/openssl-client: ChaCha20" openssl "--suites ecdsa-chacha" \
  "-cipher ECDHE-ECDSA-CHACHA20-POLY1305" ok "suite=0xcca9"
ours_server "dtls12/openssl-client: client certificate" openssl \
  "--client-auth required --ca ca.pem" "-cert cli.pem -key cli.key" ok "client_auth=1"
ours_server "dtls12/openssl-client: client certificate required, absent" openssl \
  "--client-auth required --ca ca.pem" "" fail "alert=40"
ours_server "dtls12/openssl-client: without extended master secret" openssl "" \
  "-no_ems" fail "alert=40"
ours_server "dtls12/openssl-client: CBC-only client" openssl "" \
  "-cipher ECDHE-ECDSA-AES128-SHA" fail "alert=40"
# wolfSSL's client here has no secure renegotiation support, so it sends
# neither renegotiation_info nor the signalling suite value, which RFC 5746
# and our policy require.
ours_server "dtls12/wolf-client: without secure renegotiation is refused" wolf "" "" \
  fail "alert=40"
ours_server "dtls12/gnutls-client: default" gnutls "" "--priority=$P12" ok \
  "connected suite=" "echoed=1"
ours_server "dtls12/gnutls-client: cookie exchange" gnutls "--cookie" "--priority=$P12" ok \
  "cookie-verified" "echoed=1"
ours_server "dtls12/gnutls-client: ChaCha20" gnutls "--suites ecdsa-chacha" \
  "--priority=$P12:-CIPHER-ALL:+CHACHA20-POLY1305" ok "suite=0xcca9"
ours_server "dtls12/gnutls-client: AES-128-GCM, small MTU" gnutls "--suites ecdsa-aes128" \
  "--priority=$P12:-CIPHER-ALL:+AES-128-GCM --mtu=400" ok "suite=0xc02b"
ours_server "dtls12/gnutls-client: client certificate" gnutls \
  "--client-auth required --ca ca.pem" \
  "--priority=$P12 --x509certfile=cli.pem --x509keyfile=cli.key" ok "client_auth=1"
ours_server "dtls12/gnutls-client: resumption (gnutls-cli --resume)" gnutls \
  "--connections 2" "--priority=$P12 --resume" ok "resumed=1"

# ---- gnutls-serv as the server ----
ours_client "dtls12/gnutls-server: default" gnutls \
  "--x509certfile=ec.pem --x509keyfile=ec.key --priority=$P12" "" ok "echoed=3" "result=ok"
ours_client "dtls12/gnutls-server: RSA certificate" gnutls \
  "--x509certfile=rsa.pem --x509keyfile=rsa.key --priority=$P12" "" ok "result=ok"
ours_client "dtls12/gnutls-server: ChaCha20-Poly1305" gnutls \
  "--x509certfile=ec.pem --x509keyfile=ec.key --priority=$P12:-CIPHER-ALL:+CHACHA20-POLY1305" \
  "--suites ecdsa-chacha" ok "suite=0xcca9"
ours_client "dtls12/gnutls-server: client certificate" gnutls \
  "--x509certfile=ec.pem --x509keyfile=ec.key --priority=$P12 --require-client-cert --x509cafile=ca.pem" \
  "--cert cli.pem --key cli.key" ok "client_auth=1"
ours_client "dtls12/gnutls-server: small MTU, several messages" gnutls \
  "--x509certfile=ec.pem --x509keyfile=ec.key --priority=$P12" "--mtu 400 --messages 8" ok "echoed=8"
ours_client "dtls12/gnutls-server: 20% loss" gnutls \
  "--x509certfile=ec.pem --x509keyfile=ec.key --priority=$P12" \
  "--loss 20 --seed 4 --messages 5" ok "result=ok"

echo "$runs scenarios, $fails failed"
if [ $runs -eq 0 ]; then exit 77; fi
[ $fails -eq 0 ]
