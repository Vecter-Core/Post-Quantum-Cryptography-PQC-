#!/bin/bash
# Hybrid TLS interop between vpqc-tls-proxy (rustls + aws-lc-rs) and Go crypto/tls, both
# restricted to X25519MLKEM768. Requires: target/release/vpqc-tls-proxy, go >= 1.24, openssl, python3.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROXY="${VPQC_TLS_PROXY:-$ROOT/target/release/vpqc-tls-proxy}"
W="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT

# Test CA and a leaf certificate for "localhost" (webpki rejects a CA certificate as end entity).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -keyout "$W/ca.key" -out "$W/ca.pem" -subj "/CN=vpqc test CA" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$W/key.pem" -out "$W/leaf.csr" -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$W/ext"
openssl x509 -req -in "$W/leaf.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
  -days 2 -extfile "$W/ext" -out "$W/cert.pem" 2>/dev/null
(cd "$ROOT/interop/tls-go" && go build -o "$W/tls-go" .)

port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
wait_port() { for _ in $(seq 100); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 not ready"; return 1; }

# Plain echo backend.
B=$(port)
python3 -c "
import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',$B));s.listen()
def h(c):
    while (d:=c.recv(4096)): c.sendall(d)
while True: threading.Thread(target=h,args=(s.accept()[0],),daemon=True).start()
" & PIDS+=($!)
wait_port "$B"

echo "1) Go client (hybrid only) -> vpqc-tls-proxy server (require hybrid) -> backend"
S=$(port)
"$PROXY" server --listen 127.0.0.1:$S --backend 127.0.0.1:$B --cert "$W/cert.pem" --key "$W/key.pem" 2>"$W/server.log" & PIDS+=($!)
wait_port "$S"
"$W/tls-go" client 127.0.0.1:$S "$W/ca.pem" localhost | tee "$W/out1"
grep -q "echo: hello from go" "$W/out1"
sleep 0.2; grep -q "X25519MLKEM768 \[post-quantum\]" "$W/server.log" && echo "   proxy log: $(grep -m1 X25519MLKEM768 "$W/server.log")"

echo "2) vpqc-tls-proxy probe --require-pq -> Go server (hybrid only)"
G=$(port)
"$W/tls-go" server 127.0.0.1:$G "$W/cert.pem" "$W/key.pem" > "$W/go.log" & PIDS+=($!)
wait_port "$G"
"$PROXY" probe 127.0.0.1:$G --server-name localhost --ca "$W/ca.pem" --require-pq

echo "3) plaintext client -> vpqc-tls-proxy client (require hybrid) -> Go server"
C=$(port)
"$PROXY" client --listen 127.0.0.1:$C --connect 127.0.0.1:$G --server-name localhost --ca "$W/ca.pem" 2>"$W/client.log" & PIDS+=($!)
wait_port "$C"
reply=$(python3 -c "
import socket;s=socket.create_connection(('127.0.0.1',$C));s.sendall(b'legacy\n');print(s.recv(100).decode().strip())")
[ "$reply" = legacy ] && echo "   echo: $reply"
sleep 0.2; grep -q "X25519MLKEM768 \[post-quantum\]" "$W/client.log"

echo "4) negative: probe of a classical-only server fails --require-pq"
P=$(port)
python3 - "$P" "$W" <<'PY' & PIDS+=($!)
import socket, ssl, sys
port, w = int(sys.argv[1]), sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(f"{w}/cert.pem", f"{w}/key.pem")
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen()
while True:
    c, _ = s.accept()
    try: ctx.wrap_socket(c, server_side=True).close()
    except Exception: pass
PY
wait_port "$P"
set +e; "$PROXY" probe 127.0.0.1:$P --server-name localhost --ca "$W/ca.pem" --require-pq > "$W/probe.out"; rc=$?; set -e
cat "$W/probe.out"
[ "$rc" = 2 ] || { echo "expected exit code 2, got $rc"; exit 1; }

echo "hybrid TLS interop: all checks passed"
