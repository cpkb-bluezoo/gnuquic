#!/bin/sh
# GQ_INTEROP_FILTER=text runs only the scenarios whose names contain it.
# Interoperability tests: the GNU QUIC TLS 1.3 and TLS 1.2 clients and servers
# against OpenSSL's s_server/s_client and GnuTLS's gnutls-serv/gnutls-cli.  Skipped (exit 77) when neither server
# is installed or GQ_NO_INTEROP is set.
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

CLIENT=${INTEROP_CLIENT:-./interop-client}
SERVER=${INTEROP_SERVER:-./interop-server}
[ -x "$CLIENT" ] || exit 77
[ -x "$SERVER" ] || exit 77
# The script changes directory; make the program paths absolute.
case $CLIENT in /*) ;; *) CLIENT=$(pwd)/$CLIENT ;; esac
case $SERVER in /*) ;; *) SERVER=$(pwd)/$SERVER ;; esac
OPENSSL=${OPENSSL:-$(command -v openssl)}
GNUTLS_SERV=${GNUTLS_SERV:-$(command -v gnutls-serv)}
[ -n "$OPENSSL" ] || exit 77		# Certificates are made with openssl.
command -v nc >/dev/null 2>&1 || exit 77

T=$(mktemp -d "${TMPDIR:-/tmp}/gq-interop.XXXXXX") || exit 77
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

# ---------------------------------------------------------------- certs
cd "$T" || exit 77
gen_ok=1
{
  "$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ca.key -out ca.pem -subj "/CN=Interop CA" -days 2 \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign &&
  "$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ca2.key -out ca2.pem -subj "/CN=Other CA" -days 2 \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign
} >/dev/null 2>&1 || gen_ok=0

printf 'subjectAltName=DNS:example.test,DNS:other.test\nextendedKeyUsage=serverAuth\n' > srv.ext
printf 'subjectAltName=DNS:client.test\nextendedKeyUsage=clientAuth\n' > cli.ext

# mkcert NAME ALGO-ARGS... : NAME.key / NAME.pem signed by ca (or ca2 for
# names starting with "bad").
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
  mkcert ed ed25519 &&
  mkcert bad ec -pkeyopt ec_paramgen_curve:P-256 &&
  mkcert cli ec -pkeyopt ec_paramgen_curve:P-256 &&
  mkcert cliED ed25519 &&
  mkcert badcli ec -pkeyopt ec_paramgen_curve:P-256
} || gen_ok=0
[ $gen_ok = 1 ] || { echo "cannot generate certificates" >&2; exit 77; }

head -c 200000 /dev/urandom | od -An -tx1 | head -c 200000 > big
BIGSIZE=$(wc -c < big | tr -d ' ')
mkdir www && cp big www/big

# ---------------------------------------------------------------- servers
free_port ()
{
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'
  else
    echo $((20000 + $$ % 20000 + runs))
  fi
}

wait_port ()
{
  n=0
  while [ $n -lt 100 ]; do
    nc -z 127.0.0.1 "$1" >/dev/null 2>&1 && return 0
    n=$((n + 1))
    sleep 0.1
  done
  return 1
}

# start_server KIND PORT ARGS...
start_server ()
{
  kind=$1; port=$2; shift 2
  case $kind in
    openssl)
      case " $* " in *" -tls1_2 "*|*" -tls1_3 "*) proto= ;; *) proto=-tls1_3 ;; esac
      "$OPENSSL" s_server -accept "$port" $proto -quiet "$@" \
        >server.log 2>&1 &
      ;;
    gnutls)
      "$GNUTLS_SERV" --port="$port" "$@" >server.log 2>&1 &
      ;;
  esac
  SERVER_PID=$!
  wait_port "$port"
}

stop_server ()
{
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=
}

# check_output FILE PATTERN... : every pattern must appear.
check_output ()
{
  f=$1; shift
  for pat in "$@"; do
    grep -q -- "$pat" "$f" || { echo "    missing: $pat"; return 1; }
  done
  return 0
}

# scenario NAME KIND "SERVER ARGS" "CLIENT ARGS" WANT-EXIT PATTERN...
scenario ()
{
  name=$1; kind=$2; sargs=$3; cargs=$4; want=$5; shift 5
  case $name in *"${GQ_INTEROP_FILTER:-}"*) ;; *) return ;; esac
  runs=$((runs + 1))
  # Picking a free port and starting the server is racy (another process
  # may take the port in between), so retry with a fresh port.
  attempt=0
  started=0
  while [ $attempt -lt 5 ]; do
    port=$(free_port)
    # shellcheck disable=SC2086
    if start_server "$kind" "$port" $sargs; then started=1; break; fi
    stop_server
    attempt=$((attempt + 1))
  done
  if [ $started = 0 ]; then
    echo "FAIL $name: server did not start"; cat server.log
    fails=$((fails + 1)); return
  fi
  # shellcheck disable=SC2086
  "$CLIENT" 127.0.0.1 "$port" --ca ca.pem --sni example.test $cargs \
    >client.out 2>client.err
  rc=$?
  stop_server
  ok=1
  if [ "$want" = ok ] && [ $rc -ne 0 ]; then ok=0; fi
  if [ "$want" = fail ] && [ $rc -eq 0 ]; then ok=0; fi
  if [ $ok = 1 ]; then
    check_output client.out "$@" || ok=0
  fi
  if [ $ok = 1 ]; then
    echo "PASS $name"
  else
    echo "FAIL $name (exit $rc)"
    sed 's/^/    client: /' client.out client.err
    sed 's/^/    server: /' server.log | head -20
    fails=$((fails + 1))
  fi
}

HTTP200=200

# ---------------------------------------------------------------- OpenSSL
if "$OPENSSL" s_server -help >/dev/null 2>&1; then
  OS="-cert ec.pem -key ec.key -www"
  scenario "openssl: default (hybrid X25519MLKEM768)" openssl "$OS" \
    "--expect $HTTP200" ok "group=0x11ec" "hrr=0" "result=ok" "tickets="
  scenario "openssl: X25519 only" openssl "$OS -groups X25519" \
    "--expect $HTTP200" ok "group=0x001d" "hrr=0"
  scenario "openssl: HelloRetryRequest to secp384r1" openssl "$OS -groups secp384r1" \
    "--expect $HTTP200" ok "group=0x0018" "hrr=1"
  scenario "openssl: HelloRetryRequest to secp256r1" openssl "$OS -groups secp256r1" \
    "--expect $HTTP200" ok "group=0x0017" "hrr=1"
  scenario "openssl: HelloRetryRequest to SecP256r1MLKEM768" openssl "$OS -groups SecP256r1MLKEM768" \
    "--expect $HTTP200" ok "group=0x11eb" "hrr=1"
  scenario "openssl: HelloRetryRequest to SecP384r1MLKEM1024" openssl "$OS -groups SecP384r1MLKEM1024" \
    "--expect $HTTP200" ok "group=0x11ed" "hrr=1"
  scenario "openssl: RSA certificate (rsa_pss_rsae)" openssl "-cert rsa.pem -key rsa.key -www" \
    "--expect $HTTP200" ok "result=ok"
  scenario "openssl: Ed25519 certificate" openssl "-cert ed.pem -key ed.key -www" \
    "--expect $HTTP200" ok "result=ok"
  scenario "openssl: TLS_AES_128_GCM_SHA256" openssl "$OS -ciphersuites TLS_AES_128_GCM_SHA256" \
    "--expect $HTTP200" ok "suite=0x1301"
  scenario "openssl: TLS_AES_256_GCM_SHA384 (SHA-384 schedule)" openssl "$OS -ciphersuites TLS_AES_256_GCM_SHA384" \
    "--expect $HTTP200" ok "suite=0x1302"
  scenario "openssl: TLS_CHACHA20_POLY1305_SHA256" openssl "$OS -ciphersuites TLS_CHACHA20_POLY1305_SHA256" \
    "--expect $HTTP200" ok "suite=0x1303"
  scenario "openssl: ALPN" openssl "$OS -alpn http/1.1,h2" \
    "--alpn h2 --alpn http/1.1 --expect $HTTP200" ok "alpn=http/1.1"
  scenario "openssl: client certificate (ECDSA)" openssl \
    "$OS -Verify 1 -CAfile ca.pem" \
    "--cert cli.pem --key cli.key --expect $HTTP200" ok "client_auth_requested=1" "client_auth_sent=1"
  scenario "openssl: client certificate (Ed25519)" openssl \
    "$OS -Verify 1 -CAfile ca.pem" \
    "--cert cliED.pem --key cliED.key --expect $HTTP200" ok "client_auth_sent=1"
  scenario "openssl: client certificate required but not sent" openssl \
    "$OS -Verify 1 -verify_return_error -CAfile ca.pem" \
    "--expect $HTTP200" fail "client_auth_requested=1" "client_auth_sent=0" "result=fail"
  scenario "openssl: untrusted server certificate" openssl "-cert bad.pem -key bad.key -www" \
    "--expect $HTTP200" fail "result=fail" "alert=48"
  scenario "openssl: wrong host name" openssl "$OS" \
    "--sni nomatch.test --expect $HTTP200" fail "result=fail" "alert=42"
  scenario "openssl: 200 KB download over many records" openssl "-cert ec.pem -key ec.key -WWW" \
    "--path /www/big --expect 0 --min-bytes $BIGSIZE --out got" ok "result=ok"
  if [ -f got ]; then
    tail -c "$BIGSIZE" got | cmp -s - big && echo "PASS openssl: downloaded data identical" \
      || { echo "FAIL openssl: downloaded data differs"; fails=$((fails + 1)); }
    runs=$((runs + 1)); rm -f got
  fi
  scenario "openssl: client-initiated KeyUpdate" openssl "$OS" \
    "--key-update --expect $HTTP200" ok "result=ok"
  scenario "openssl: rekey by record count" openssl "$OS -rev" \
    "--rekey 3 --lines 60 --expect 95-enil --min-bytes 400" ok "result=ok"
  scenario "openssl: session resumption with a stored ticket" openssl "$OS" \
    "--twice --expect $HTTP200" ok "resumed=0" "resumed=1"
  scenario "openssl: resumption after HelloRetryRequest" openssl "$OS -groups secp384r1" \
    "--twice --expect $HTTP200" ok "hrr=1 alpn= client_auth_requested=0 client_auth_sent=0 resumed=1"
  scenario "openssl: resumption with TLS_AES_256_GCM_SHA384" openssl \
    "$OS -ciphersuites TLS_AES_256_GCM_SHA384" "--twice --expect $HTTP200" ok \
    "suite=0x1302.*resumed=1"
  scenario "openssl: resumption with ChaCha20-Poly1305" openssl \
    "$OS -ciphersuites TLS_CHACHA20_POLY1305_SHA256" "--twice --expect $HTTP200" ok \
    "suite=0x1303.*resumed=1"
fi

# ------------------------------------------------- TLS 1.2 vs OpenSSL servers
if "$OPENSSL" s_server -help >/dev/null 2>&1; then
  O12="-tls1_2 -cert ec.pem -key ec.key -www"
  R12="-tls1_2 -cert rsa.pem -key rsa.key -www"
  C12="--tls12 --expect $HTTP200"
  scenario "tls12/openssl: default" openssl "$O12" "$C12" ok \
    "group=0x0017" "resumed=0" "result=ok"
  scenario "tls12/openssl: ECDHE-ECDSA-AES128-GCM-SHA256" openssl \
    "$O12 -cipher ECDHE-ECDSA-AES128-GCM-SHA256" "$C12 --suites ecdsa-aes128" ok "suite=0xc02b"
  scenario "tls12/openssl: ECDHE-ECDSA-AES256-GCM-SHA384" openssl \
    "$O12 -cipher ECDHE-ECDSA-AES256-GCM-SHA384" "$C12 --suites ecdsa-aes256" ok "suite=0xc02c"
  scenario "tls12/openssl: ECDHE-ECDSA-CHACHA20-POLY1305" openssl \
    "$O12 -cipher ECDHE-ECDSA-CHACHA20-POLY1305" "$C12 --suites ecdsa-chacha" ok "suite=0xcca9"
  scenario "tls12/openssl: ECDHE-RSA-AES128-GCM-SHA256" openssl \
    "$R12 -cipher ECDHE-RSA-AES128-GCM-SHA256" "$C12 --suites rsa-aes128" ok "suite=0xc02f"
  scenario "tls12/openssl: ECDHE-RSA-AES256-GCM-SHA384" openssl \
    "$R12 -cipher ECDHE-RSA-AES256-GCM-SHA384" "$C12 --suites rsa-aes256" ok "suite=0xc030"
  scenario "tls12/openssl: ECDHE-RSA-CHACHA20-POLY1305" openssl \
    "$R12 -cipher ECDHE-RSA-CHACHA20-POLY1305" "$C12 --suites rsa-chacha" ok "suite=0xcca8"
  scenario "tls12/openssl: ALPN" openssl "$O12 -alpn http/1.1,h2" \
    "$C12 --alpn h2 --alpn http/1.1" ok "alpn=http/1.1"
  scenario "tls12/openssl: client certificate (ECDSA)" openssl \
    "$O12 -Verify 1 -CAfile ca.pem" "$C12 --cert cli.pem --key cli.key" ok \
    "client_auth_requested=1" "client_auth_sent=1"
  scenario "tls12/openssl: client certificate required but not sent" openssl \
    "$O12 -Verify 1 -verify_return_error -CAfile ca.pem" "$C12" fail \
    "result=fail" "alert=40"
  scenario "tls12/openssl: untrusted server certificate" openssl \
    "-tls1_2 -cert bad.pem -key bad.key -www" "$C12" fail "alert=48"
  scenario "tls12/openssl: wrong host name" openssl "$O12" \
    "$C12 --sni nomatch.test" fail "alert=42"
  scenario "tls12/openssl: 200 KB download over many records" openssl \
    "-tls1_2 -cert ec.pem -key ec.key -WWW" \
    "--tls12 --path /www/big --expect 0 --min-bytes $BIGSIZE --out got" ok "result=ok"
  if [ -f got ]; then
    tail -c "$BIGSIZE" got | cmp -s - big && echo "PASS tls12/openssl: downloaded data identical" \
      || { echo "FAIL tls12/openssl: downloaded data differs"; fails=$((fails + 1)); }
    runs=$((runs + 1)); rm -f got
  fi
  scenario "tls12/openssl: ticket resumption" openssl "$O12" \
    "$C12 --twice" ok "resumed=0" "resumed=1"
  scenario "tls12/openssl: ticket resumption, RSA and ChaCha20" openssl \
    "$R12 -cipher ECDHE-RSA-CHACHA20-POLY1305" "$C12 --twice" ok "suite=0xcca8.*resumed=1"
  # What we refuse.
  scenario "tls12/openssl: CBC-only server is refused" openssl \
    "$R12 -cipher AES128-SHA:ECDHE-RSA-AES128-SHA" "$C12" fail "result=fail"
  scenario "tls12/openssl: server without extended master secret is refused" openssl \
    "$O12 -no_ems" "$C12" fail "alert=40"
  scenario "tls12/openssl: TLS 1.3-only server" openssl \
    "-tls1_3 -cert ec.pem -key ec.key -www" "$C12" fail "result=fail"
fi

# ---------------------------------------------------------------- GnuTLS
if [ -n "$GNUTLS_SERV" ] && "$GNUTLS_SERV" --version >/dev/null 2>&1; then
  GS="--x509certfile=ec.pem --x509keyfile=ec.key --http"
  P13="NORMAL:-VERS-ALL:+VERS-TLS1.3"
  scenario "gnutls: default" gnutls "$GS --priority=$P13" \
    "--expect $HTTP200" ok "result=ok"
  scenario "gnutls: HelloRetryRequest to secp384r1" gnutls \
    "$GS --priority=$P13:-GROUP-ALL:+GROUP-SECP384R1" \
    "--expect $HTTP200" ok "group=0x0018" "hrr=1"
  scenario "gnutls: HelloRetryRequest to secp256r1" gnutls \
    "$GS --priority=$P13:-GROUP-ALL:+GROUP-SECP256R1" \
    "--expect $HTTP200" ok "group=0x0017" "hrr=1"
  scenario "gnutls: AES-256-GCM (SHA-384)" gnutls \
    "$GS --priority=$P13:-CIPHER-ALL:+AES-256-GCM" \
    "--expect $HTTP200" ok "suite=0x1302"
  scenario "gnutls: ChaCha20-Poly1305" gnutls \
    "$GS --priority=$P13:-CIPHER-ALL:+CHACHA20-POLY1305" \
    "--expect $HTTP200" ok "suite=0x1303"
  scenario "gnutls: RSA certificate" gnutls \
    "--x509certfile=rsa.pem --x509keyfile=rsa.key --http --priority=$P13" \
    "--expect $HTTP200" ok "result=ok"
  scenario "gnutls: Ed25519 certificate" gnutls \
    "--x509certfile=ed.pem --x509keyfile=ed.key --http --priority=$P13" \
    "--expect $HTTP200" ok "result=ok"
  scenario "gnutls: client certificate" gnutls \
    "$GS --priority=$P13 --require-client-cert --x509cafile=ca.pem" \
    "--cert cli.pem --key cli.key --expect $HTTP200" ok "client_auth_sent=1"
  scenario "gnutls: untrusted server certificate" gnutls \
    "--x509certfile=bad.pem --x509keyfile=bad.key --http --priority=$P13" \
    "--expect $HTTP200" fail "alert=48"
  scenario "gnutls: client-initiated KeyUpdate" gnutls "$GS --priority=$P13" \
    "--key-update --expect $HTTP200" ok "result=ok"
  scenario "gnutls: session resumption with a stored ticket" gnutls "$GS --priority=$P13" \
    "--twice --expect $HTTP200" ok "resumed=0" "resumed=1"

  P12="NORMAL:-VERS-ALL:+VERS-TLS1.2"
  scenario "tls12/gnutls: default" gnutls "$GS --priority=$P12" \
    "--tls12 --expect $HTTP200" ok "result=ok" "resumed=0"
  scenario "tls12/gnutls: RSA certificate" gnutls \
    "--x509certfile=rsa.pem --x509keyfile=rsa.key --http --priority=$P12" \
    "--tls12 --expect $HTTP200" ok "result=ok"
  scenario "tls12/gnutls: ChaCha20-Poly1305" gnutls \
    "$GS --priority=$P12:-CIPHER-ALL:+CHACHA20-POLY1305" \
    "--tls12 --expect $HTTP200" ok "suite=0xcca9"
  scenario "tls12/gnutls: AES-256-GCM" gnutls \
    "$GS --priority=$P12:-CIPHER-ALL:+AES-256-GCM" \
    "--tls12 --expect $HTTP200" ok "suite=0xc02c"
  scenario "tls12/gnutls: client certificate" gnutls \
    "$GS --priority=$P12 --require-client-cert --x509cafile=ca.pem" \
    "--tls12 --cert cli.pem --key cli.key --expect $HTTP200" ok "client_auth_sent=1"
  scenario "tls12/gnutls: untrusted server certificate" gnutls \
    "--x509certfile=bad.pem --x509keyfile=bad.key --http --priority=$P12" \
    "--tls12 --expect $HTTP200" fail "alert=48"
  scenario "tls12/gnutls: ticket resumption" gnutls "$GS --priority=$P12" \
    "--tls12 --twice --expect $HTTP200" ok "resumed=0" "resumed=1"
fi

# ---------------------------------------------------------------- our server
# server_scenario NAME CLIENTKIND "SERVER ARGS" "CLIENT ARGS" WANT PATTERN...
#   Runs interop-server, connects the named independent client to it and
#   sends "hello\n" (echoed back).  WANT is the server's verdict (ok|fail);
#   PATTERNs must appear in the server's output.
server_scenario ()
{
  name=$1; ckind=$2; sargs=$3; cargs=$4; want=$5; shift 5
  case $name in *"${GQ_INTEROP_FILTER:-}"*) ;; *) return ;; esac
  runs=$((runs + 1))
  attempt=0
  started=0
  while [ $attempt -lt 5 ] && [ $started = 0 ]; do
    port=$(free_port)
    # shellcheck disable=SC2086
    "$SERVER" "$port" --max-bytes 6 --timeout 15 $sargs >srv.out 2>srv.err &
    SERVER_PID=$!
    # The one-shot server accepts a single connection, so do not probe the
    # port: wait for it to announce that it is listening (or to give up).
    n=0
    while ! grep -q listening srv.out 2>/dev/null && kill -0 "$SERVER_PID" 2>/dev/null \
          && [ $n -lt 50 ]; do
      sleep 0.1; n=$((n + 1))
    done
    if grep -q listening srv.out; then
      started=1
    else
      kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null
      SERVER_PID=
      attempt=$((attempt + 1))
    fi
  done
  if [ $started = 0 ]; then
    echo "FAIL $name: server did not start"; cat srv.out srv.err
    fails=$((fails + 1)); return
  fi
  case $ckind in
    openssl)
      # -tls1_3 unless the scenario asks for -tls1_2.
      case " $cargs " in *" -tls1_2 "*|*" -tls1_3 "*) proto= ;; *) proto=-tls1_3 ;; esac
      # shellcheck disable=SC2086
      (printf 'hello\n'; sleep 1) | "$OPENSSL" s_client -connect "127.0.0.1:$port" \
        $proto -CAfile ca.pem -servername example.test \
        -verify_hostname example.test -verify_return_error -quiet $cargs \
        >cli.out 2>cli.err
      ;;
    gnutls)
      # shellcheck disable=SC2086
      (printf 'hello\n'; sleep 1) | "$GNUTLS_CLI" --x509cafile=ca.pem \
        --sni-hostname=example.test --verify-hostname=example.test \
        --port="$port" $cargs 127.0.0.1 \
        >cli.out 2>cli.err
      ;;
  esac
  crc=$?
  # The server exits by itself after the echo or on failure; give it a
  # moment, then reap it.
  n=0
  while kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 30 ]; do
    sleep 0.1; n=$((n + 1))
  done
  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=
  ok=1
  grep -q "result=$want" srv.out || ok=0
  if [ $ok = 1 ]; then
    check_output srv.out "$@" || ok=0
  fi
  if [ $ok = 1 ] && [ "$want" = ok ]; then
    grep -q hello cli.out || { echo "    client did not get the echo"; ok=0; }
  fi
  if [ $ok = 1 ]; then
    echo "PASS $name"
  else
    echo "FAIL $name (client exit $crc)"
    sed 's/^/    server: /' srv.out srv.err
    sed 's/^/    client: /' cli.out | head -10
    sed 's/^/    client: /' cli.err | head -12
    fails=$((fails + 1))
  fi
}

SC="--cert ec.pem --key ec.key"
S12="$SC --tls12"
if "$OPENSSL" s_client -help >/dev/null 2>&1; then
  server_scenario "server/openssl: default (hybrid X25519MLKEM768)" openssl "$SC" "" ok \
    "group=0x11ec" "hrr=0" "sni=example.test" "result=ok"
  server_scenario "server/openssl: X25519" openssl "$SC" "-groups X25519" ok "group=0x001d"
  server_scenario "server/openssl: secp384r1" openssl "$SC" "-groups secp384r1" ok "group=0x0018"
  server_scenario "server/openssl: HelloRetryRequest (server insists on secp384r1)" openssl \
    "$SC --groups p384" "-groups X25519:secp384r1" ok "group=0x0018" "hrr=1"
  server_scenario "server/openssl: HelloRetryRequest with cookie" openssl \
    "$SC --groups p384 --hrr-cookie" "-groups X25519:secp384r1" ok "group=0x0018" "hrr=1"
  server_scenario "server/openssl: HelloRetryRequest to SecP384r1MLKEM1024" openssl \
    "$SC --groups p384mlkem1024" "-groups X25519:SecP384r1MLKEM1024" ok "group=0x11ed" "hrr=1"
  server_scenario "server/openssl: server prefers ChaCha20" openssl "$SC --suites chacha" "" ok "suite=0x1303"
  server_scenario "server/openssl: AES-128-GCM only" openssl "$SC --suites aes128" "" ok "suite=0x1301"
  server_scenario "server/openssl: client restricts to AES-256" openssl "$SC" \
    "-ciphersuites TLS_AES_256_GCM_SHA384" ok "suite=0x1302"
  server_scenario "server/openssl: RSA certificate" openssl "--cert rsa.pem --key rsa.key" "" ok "result=ok"
  server_scenario "server/openssl: Ed25519 certificate" openssl "--cert ed.pem --key ed.key" "" ok "result=ok"
  server_scenario "server/openssl: SNI selects the certificate" openssl \
    "$SC --sni example.test=ec.pem:ec.key --sni other.test=rsa.pem:rsa.key" \
    "-servername other.test -verify_hostname other.test" ok "sni=other.test"
  server_scenario "server/openssl: unknown SNI is refused" openssl \
    "$SC --sni example.test=ec.pem:ec.key" "-servername nowhere.test -verify_hostname nowhere.test" fail "result=fail"
  server_scenario "server/openssl: ALPN by server preference" openssl \
    "$SC --alpn h2 --alpn http/1.1" "-alpn http/1.1,h2" ok "alpn=h2"
  server_scenario "server/openssl: ALPN with no overlap" openssl \
    "$SC --alpn h2" "-alpn foo" fail "alert=120"
  server_scenario "server/openssl: client certificate required" openssl \
    "$SC --client-auth required --ca ca.pem" "-cert cli.pem -key cli.key" ok "client_auth=1"
  server_scenario "server/openssl: client certificate (Ed25519)" openssl \
    "$SC --client-auth required --ca ca.pem" "-cert cliED.pem -key cliED.key" ok "client_auth=1"
  server_scenario "server/openssl: client certificate optional, absent" openssl \
    "$SC --client-auth optional --ca ca.pem" "" ok "client_auth_requested=1" "client_auth=0"
  server_scenario "server/openssl: client certificate required, absent" openssl \
    "$SC --client-auth required --ca ca.pem" "" fail "alert=116"
  server_scenario "server/openssl: client certificate from untrusted CA" openssl \
    "$SC --client-auth required --ca ca.pem" "-cert badcli.pem -key badcli.key" fail "alert=48"
  server_scenario "server/openssl: TLS 1.2 client is refused" openssl \
    "$SC" "-tls1_2" fail "alert=70"
  server_scenario "server/openssl: server-initiated rekey and KeyUpdate" openssl \
    "$SC --rekey 2 --key-update 1" "" ok "result=ok"
  server_scenario "server12/openssl: default" openssl "$S12" "-tls1_2" ok \
    "result=ok" "sni=example.test" "group=0x0017"
  server_scenario "server12/openssl: ECDHE-ECDSA-CHACHA20-POLY1305" openssl "$S12" \
    "-tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305" ok "suite=0xcca9"
  server_scenario "server12/openssl: ECDHE-ECDSA-AES128-GCM-SHA256" openssl "$S12" \
    "-tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256" ok "suite=0xc02b"
  server_scenario "server12/openssl: server preference picks AES-256-GCM" openssl "$S12" \
    "-tls1_2" ok "suite=0xc02c"
  server_scenario "server12/openssl: RSA certificate (ECDHE-RSA-AES128-GCM-SHA256)" openssl \
    "--tls12 --cert rsa.pem --key rsa.key" "-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256" ok "suite=0xc02f"
  server_scenario "server12/openssl: RSA certificate (ChaCha20-Poly1305)" openssl \
    "--tls12 --cert rsa.pem --key rsa.key" "-tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305" ok "suite=0xcca8"
  server_scenario "server12/openssl: SNI selects the certificate" openssl \
    "$S12 --sni example.test=ec.pem:ec.key --sni other.test=rsa.pem:rsa.key" \
    "-tls1_2 -servername other.test -verify_hostname other.test" ok "sni=other.test" "suite=0xc030"
  server_scenario "server12/openssl: ALPN by server preference" openssl \
    "$S12 --alpn h2 --alpn http/1.1" "-tls1_2 -alpn http/1.1,h2" ok "alpn=h2"
  server_scenario "server12/openssl: client certificate required" openssl \
    "$S12 --client-auth required --ca ca.pem" "-tls1_2 -cert cli.pem -key cli.key" ok "client_auth=1"
  server_scenario "server12/openssl: client certificate optional, absent" openssl \
    "$S12 --client-auth optional --ca ca.pem" "-tls1_2" ok "client_auth_requested=1" "client_auth=0"
  server_scenario "server12/openssl: client certificate required, absent" openssl \
    "$S12 --client-auth required --ca ca.pem" "-tls1_2" fail "alert=40"
  server_scenario "server12/openssl: client certificate from untrusted CA" openssl \
    "$S12 --client-auth required --ca ca.pem" "-tls1_2 -cert badcli.pem -key badcli.key" fail "alert=48"
  server_scenario "server12/openssl: TLS 1.3-only client is refused" openssl \
    "$S12" "-tls1_3" fail "alert=70"
  server_scenario "server12/openssl: client without extended master secret is refused" openssl \
    "$S12" "-tls1_2 -no_ems" fail "alert=40"
  server_scenario "server12/openssl: CBC-only client is refused" openssl \
    "$S12" "-tls1_2 -cipher ECDHE-ECDSA-AES128-SHA" fail "alert=40"
fi

if [ -n "$GNUTLS_SERV" ]; then
  GNUTLS_CLI=${GNUTLS_CLI:-$(command -v gnutls-cli)}
fi
if [ -n "${GNUTLS_CLI:-}" ] && "$GNUTLS_CLI" --version >/dev/null 2>&1; then
  P13="NORMAL:-VERS-ALL:+VERS-TLS1.3"
  server_scenario "server/gnutls: default" gnutls "$SC" "--priority=$P13" ok "result=ok" "sni=example.test"
  server_scenario "server/gnutls: secp384r1" gnutls "$SC" \
    "--priority=$P13:-GROUP-ALL:+GROUP-SECP384R1" ok "group=0x0018"
  server_scenario "server/gnutls: HelloRetryRequest" gnutls "$SC --groups p384" \
    "--priority=$P13:-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:+GROUP-SECP384R1" ok "group=0x0018" "hrr=1"
  server_scenario "server/gnutls: ChaCha20-Poly1305" gnutls "$SC" \
    "--priority=$P13:-CIPHER-ALL:+CHACHA20-POLY1305" ok "suite=0x1303"
  server_scenario "server/gnutls: RSA certificate" gnutls "--cert rsa.pem --key rsa.key" \
    "--priority=$P13" ok "result=ok"
  server_scenario "server/gnutls: client certificate" gnutls \
    "$SC --client-auth required --ca ca.pem" \
    "--priority=$P13 --x509certfile=cli.pem --x509keyfile=cli.key" ok "client_auth=1"
  server_scenario "server/gnutls: TLS 1.2 client is refused" gnutls "$SC" \
    "--priority=NORMAL:-VERS-ALL:+VERS-TLS1.2" fail "alert=70"
  P12="NORMAL:-VERS-ALL:+VERS-TLS1.2"
  server_scenario "server12/gnutls: default" gnutls "$S12" "--priority=$P12" ok "result=ok" "sni=example.test"
  server_scenario "server12/gnutls: ChaCha20-Poly1305" gnutls "$S12" \
    "--priority=$P12:-CIPHER-ALL:+CHACHA20-POLY1305" ok "suite=0xcca9"
  server_scenario "server12/gnutls: RSA certificate" gnutls "--tls12 --cert rsa.pem --key rsa.key" \
    "--priority=$P12" ok "result=ok"
  server_scenario "server12/gnutls: client certificate" gnutls \
    "$S12 --client-auth required --ca ca.pem" \
    "--priority=$P12 --x509certfile=cli.pem --x509keyfile=cli.key" ok "client_auth=1"
  server_scenario "server12/gnutls: TLS 1.3-only client is refused" gnutls "$S12" \
    "--priority=NORMAL:-VERS-ALL:+VERS-TLS1.3" fail "alert=70"
fi

# ---------------------------------------------------------------- resumption
# start_ours ARGS...  Start interop-server on a fresh port (retrying if the
# port is taken); sets $port, returns 0 on success.
start_ours ()
{
  attempt=0
  while [ $attempt -lt 5 ]; do
    port=$(free_port)
    "$SERVER" "$port" --timeout 20 "$@" >srv.out 2>srv.err &
    SERVER_PID=$!
    n=0
    while ! grep -q listening srv.out 2>/dev/null && kill -0 "$SERVER_PID" 2>/dev/null \
          && [ $n -lt 50 ]; do
      sleep 0.1; n=$((n + 1))
    done
    grep -q listening srv.out && return 0
    kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=
    attempt=$((attempt + 1))
  done
  return 1
}

# resume_scenario NAME CLIENTKIND "SERVER ARGS" "CLIENT ARGS" PATTERN...
#   Two connections to one server instance: the first stores a session, the
#   second offers it.
resume_scenario ()
{
  name=$1; ckind=$2; sargs=$3; cargs=$4; shift 4
  case $name in *"${GQ_INTEROP_FILTER:-}"*) ;; *) return ;; esac
  runs=$((runs + 1))
  # OpenSSL's client does not close on stdin EOF, so the server closes
  # after echoing the greeting; gnutls-cli ends its connections itself.
  case $ckind in openssl) limit="--max-bytes 6" ;; *) limit= ;; esac
  # shellcheck disable=SC2086
  if ! start_ours --connections 2 $limit $sargs; then
    echo "FAIL $name: server did not start"; cat srv.out srv.err
    fails=$((fails + 1)); return
  fi
  rm -f sess.pem
  case $ckind in
    openssl)
      case " $cargs " in *" -tls1_2 "*|*" -tls1_3 "*) proto= ;; *) proto=-tls1_3 ;; esac
      for pass in 1 2; do
        if [ $pass = 1 ]; then sess="-sess_out sess.pem"; else sess="-sess_in sess.pem"; fi
        # shellcheck disable=SC2086
        (printf 'hello\n'; sleep 1) | "$OPENSSL" s_client -connect "127.0.0.1:$port" \
          $proto -CAfile ca.pem -servername example.test \
          -verify_hostname example.test -verify_return_error -quiet $sess $cargs \
          >cli$pass.out 2>cli$pass.err
      done
      ;;
    gnutls)
      # gnutls-cli --resume reconnects and resumes within one run.
      # shellcheck disable=SC2086
      (printf 'hello\n'; sleep 2) | "$GNUTLS_CLI" --x509cafile=ca.pem \
        --sni-hostname=example.test --verify-hostname=example.test --resume \
        --port="$port" $cargs 127.0.0.1 >cli1.out 2>cli1.err
      ;;
  esac
  n=0
  while kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 40 ]; do
    sleep 0.1; n=$((n + 1))
  done
  kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=
  ok=1
  check_output srv.out "$@" || ok=0
  if [ $ok = 1 ]; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/    server: /' srv.out srv.err
    sed 's/^/    client: /' cli1.err cli2.err 2>/dev/null | head -15
    fails=$((fails + 1))
  fi
}

if "$OPENSSL" s_client -help >/dev/null 2>&1; then
  resume_scenario "server/openssl: resumption (s_client -sess_out / -sess_in)" openssl "$SC" "" \
    "resumed=0" "resumed=1" "result=ok"
  resume_scenario "server/openssl: resumption after HelloRetryRequest" openssl \
    "$SC --groups p384" "-groups X25519:secp384r1" "hrr=1.*resumed=1" "result=ok"
  resume_scenario "server/openssl: resumption with ChaCha20-Poly1305" openssl "$SC --suites chacha" "" \
    "suite=0x1303.*resumed=1"
  resume_scenario "server/openssl: resumption with SNI selection" openssl \
    "$SC --sni example.test=ec.pem:ec.key" "" "sni=example.test.*resumed=1"
  resume_scenario "server/openssl: resumption keeps client authentication" openssl \
    "$SC --client-auth required --ca ca.pem" "-cert cli.pem -key cli.key" \
    "client_auth=1.*resumed=0" "client_auth=1.*resumed=1"
fi
if "$OPENSSL" s_client -help >/dev/null 2>&1; then
  resume_scenario "server12/openssl: ticket resumption" openssl "$SC --tls12" "-tls1_2" \
    "resumed=0" "resumed=1" "result=ok"
  resume_scenario "server12/openssl: ticket resumption, ChaCha20-Poly1305" openssl \
    "$SC --tls12" "-tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305" "suite=0xcca9.*resumed=1"
  resume_scenario "server12/openssl: ticket resumption keeps client authentication" openssl \
    "$SC --tls12 --client-auth required --ca ca.pem" "-tls1_2 -cert cli.pem -key cli.key" \
    "client_auth=1.*resumed=0" "client_auth=1.*resumed=1"
fi
if [ -n "${GNUTLS_CLI:-}" ] && "$GNUTLS_CLI" --version >/dev/null 2>&1; then
  resume_scenario "server12/gnutls: ticket resumption (gnutls-cli --resume)" gnutls "$SC --tls12" \
    "--priority=NORMAL:-VERS-ALL:+VERS-TLS1.2" "resumed=1"
  resume_scenario "server/gnutls: resumption (gnutls-cli --resume)" gnutls "$SC" \
    "--priority=NORMAL:-VERS-ALL:+VERS-TLS1.3" "resumed=1"
fi

# 200 KB echoed through our server by OpenSSL's client, with the server
# rekeying every few records and asking the client to update as well.
if "$OPENSSL" s_client -help >/dev/null 2>&1; then
  runs=$((runs + 1))
  attempt=0
  while [ $attempt -lt 5 ]; do
    port=$(free_port)
    "$SERVER" "$port" --cert ec.pem --key ec.key --max-bytes "$BIGSIZE" \
      --rekey 4 --key-update 3 --timeout 25 >srv.out 2>srv.err &
    SERVER_PID=$!
    n=0
    while ! grep -q listening srv.out 2>/dev/null && kill -0 "$SERVER_PID" 2>/dev/null \
          && [ $n -lt 50 ]; do
      sleep 0.1; n=$((n + 1))
    done
    grep -q listening srv.out && break
    kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=
    attempt=$((attempt + 1))
  done
  (cat big; sleep 3) | "$OPENSSL" s_client -connect "127.0.0.1:$port" -tls1_3 \
    -CAfile ca.pem -servername example.test -verify_hostname example.test \
    -verify_return_error -quiet >cli.out 2>cli.err
  n=0
  while kill -0 "$SERVER_PID" 2>/dev/null && [ $n -lt 50 ]; do
    sleep 0.1; n=$((n + 1))
  done
  kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=
  if grep -q "result=ok" srv.out && cmp -s cli.out big; then
    echo "PASS server/openssl: 200 KB echoed identically with rekeying"
  else
    echo "FAIL server/openssl: 200 KB echo"
    sed 's/^/    server: /' srv.out srv.err | head; ls -l cli.out big | sed 's/^/    /'
    fails=$((fails + 1))
  fi
fi

echo "$runs scenarios, $fails failed"
if [ $runs -eq 0 ]; then exit 77; fi
[ $fails -eq 0 ]
