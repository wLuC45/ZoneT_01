#!/bin/sh
# verificar_pilha.sh — teste de fumaça da pilha de anonimização.
# Executar DENTRO do contêiner:  podman exec zonet01 sh /opt/zonet/scripts/verificar_pilha.sh
set -u

FALHAS=0
ok()    { echo "  [OK]   $*"; }
falha() { echo "  [FALHA] $*"; FALHAS=$((FALHAS + 1)); }

echo "=== ZoneT_01 — verificação da pilha ==="

echo "[1] Porta SOCKS do Tor (9050)"
nc -z 127.0.0.1 9050 2>/dev/null && ok "Tor SOCKS ativo" || falha "Tor SOCKS inativo"

echo "[2] Porta de controle do Tor (9051)"
nc -z 127.0.0.1 9051 2>/dev/null && ok "ControlPort ativa" || falha "ControlPort inativa"

echo "[3] Resolução via dnscrypt-proxy (127.0.0.1:53)"
RES=$(dig +short +time=8 +tries=2 @127.0.0.1 example.com A 2>/dev/null)
[ -n "$RES" ] && ok "dnscrypt-proxy resolve ($RES)" || falha "sem resolução DNS"

echo "[4] Saída pela rede Tor"
TOR=$(curl -s --max-time 30 --socks5-hostname 127.0.0.1:9050 \
      https://check.torproject.org/api/ip 2>/dev/null)
echo "$TOR" | grep -q '"IsTor":true' \
  && ok "tráfego saindo pelo Tor" \
  || falha "Tor não confirmado ($TOR)"

echo "[5] resolv.conf aponta só para 127.0.0.1"
if [ "$(grep -c '^nameserver' /etc/resolv.conf)" = "1" ] && \
   grep -q '^nameserver 127.0.0.1' /etc/resolv.conf; then
  ok "resolv.conf sem vazamento"
else
  falha "resolv.conf contém resolvedores externos"
fi

echo "[6] Camada web (/healthz)"
curl -fsS --max-time 5 http://127.0.0.1:5000/healthz >/dev/null 2>&1 \
  && ok "Gunicorn respondendo" || falha "web não responde"

echo "[7] AXFR fim a fim contra alvo público vulnerável (zonetransfer.me)"
AXFR=$(torsocks dig axfr zonetransfer.me @nsztm1.digi.ninja \
       +tcp +time=40 +tries=1 +nocomments +nostats 2>&1)
echo "$AXFR" | grep -qE '[[:space:]]IN[[:space:]]' \
  && ok "caminho AXFR via Tor funcional" \
  || falha "AXFR não retornou registros"

echo "=== Concluído: $FALHAS falha(s) ==="
[ "$FALHAS" -eq 0 ]
