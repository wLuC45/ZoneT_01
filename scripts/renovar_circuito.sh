#!/bin/sh
# renovar_circuito.sh — solicita um circuito Tor novo a cada 10 minutos.
#
# Além do MaxCircuitDirtiness do torrc, envia SIGNAL NEWNYM pela porta de
# controle para forçar um circuito limpo periodicamente, dificultando
# ataques de correlação de tráfego.
set -u

COOKIE_FILE="/var/lib/tor/control_auth_cookie"
INTERVALO=600

while true; do
  sleep "$INTERVALO"
  if [ ! -r "$COOKIE_FILE" ]; then
    continue
  fi
  COOKIE=$(od -An -tx1 "$COOKIE_FILE" 2>/dev/null | tr -d ' \n')
  [ -z "$COOKIE" ] && continue
  printf 'AUTHENTICATE %s\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$COOKIE" \
    | nc 127.0.0.1 9051 >/dev/null 2>&1 || true
  echo "[renovar_circuito] novo circuito Tor solicitado."
done
