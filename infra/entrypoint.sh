#!/bin/sh
# entrypoint.sh — supervisor de inicialização do contêiner ZoneT_01.
#
# Ordem obrigatória: Tor precisa estar 100% bootstrapped ANTES do
# dnscrypt-proxy (que sonda a porta SOCKS e busca listas pela rede Tor); o
# DNS precisa estar resolvendo ANTES do Gunicorn aceitar scans.
#
# Os daemons rodam como root DENTRO do contêiner — aceitável porque o contêiner
# já roda com --cap-drop ALL, --read-only e --security-opt no-new-privileges,
# que removem qualquer privilégio efetivo. Sem essas capabilities não é possível
# usar chown nem su-exec; por isso não há troca de usuário aqui.
set -eu

log() { echo "[entrypoint] $*"; }

# --- 0. preparar diretórios graváveis (montados como tmpfs) ----------------
mkdir -p /var/lib/tor /var/cache/dnscrypt-proxy /var/log/zonet /run
chmod 700 /var/lib/tor

# Semeia o cache do dnscrypt-proxy com as listas de resolvers/relays embutidas
# na imagem. Assim o dnscrypt-proxy não depende de baixar essas listas no
# arranque — evita o fetch a raw.githubusercontent.com e acelera o startup.
if [ -d /opt/zonet/infra/dnscrypt/cache ]; then
  cp -f /opt/zonet/infra/dnscrypt/cache/* /var/cache/dnscrypt-proxy/ 2>/dev/null || true
  log "Cache do dnscrypt-proxy semeado a partir da imagem."
fi

TOR_PID=""
DC_PID=""
REN_PID=""
GUNICORN_PID=""

encerrar() {
  log "Encerrando daemons..."
  for pid in "$GUNICORN_PID" "$REN_PID" "$DC_PID" "$TOR_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  exit 0
}
trap encerrar TERM INT

# --- helper: ler o cookie de controle do Tor em hexadecimal ----------------
cookie_hex() {
  od -An -tx1 /var/lib/tor/control_auth_cookie 2>/dev/null | tr -d ' \n'
}

# --- funções de (re)início dos daemons -------------------------------------
iniciar_tor() {
  tor -f "$TORRC" &
  TOR_PID=$!
}

iniciar_dnscrypt() {
  dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml &
  DC_PID=$!
}

# --- montar o torrc efetivo (base + bridges opcionais) ---------------------
# O operador pode esconder o uso do Tor da própria rede montando um arquivo de
# bridges em /etc/tor/bridges.conf. Bridges vanilla funcionam de imediato;
# bridges obfs4 exigem um binário obfs4proxy/lyrebird presente no contêiner.
# Sem esse arquivo, o Tor usa guardas normais.
TORRC=/run/torrc
cp /etc/tor/torrc "$TORRC"

if [ -s /etc/tor/bridges.conf ]; then
  log "Bridges fornecidas: ativando UseBridges."
  {
    echo ""
    echo "UseBridges 1"
    OBFS4=$(command -v lyrebird || command -v obfs4proxy || true)
    if [ -n "$OBFS4" ]; then
      log "Transporte obfs4 disponível ($OBFS4)."
      echo "ClientTransportPlugin obfs4 exec $OBFS4"
    fi
    # Cada linha não vazia e não comentada vira uma diretiva Bridge.
    while IFS= read -r linha; do
      case "$linha" in
        ""|\#*) ;;
        Bridge\ *) echo "$linha" ;;
        *) echo "Bridge $linha" ;;
      esac
    done < /etc/tor/bridges.conf
  } >> "$TORRC"
  if ! command -v lyrebird >/dev/null 2>&1 \
     && ! command -v obfs4proxy >/dev/null 2>&1; then
    log "AVISO: sem obfs4proxy; apenas bridges vanilla funcionarão."
  fi
fi

# --- 1. iniciar o Tor ------------------------------------------------------
log "Iniciando Tor..."
iniciar_tor

# --- 2. gate: aguardar a porta SOCKS e o bootstrap 100% --------------------
log "Aguardando a porta SOCKS do Tor (9050)..."
i=0
while [ "$i" -lt 60 ]; do
  if nc -z 127.0.0.1 9050 2>/dev/null; then break; fi
  i=$((i + 1)); sleep 2
done

log "Aguardando bootstrap completo do Tor..."
i=0
while [ "$i" -lt 90 ]; do
  COOKIE=$(cookie_hex)
  if [ -n "$COOKIE" ]; then
    FASE=$(printf 'AUTHENTICATE %s\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' \
           "$COOKIE" | nc 127.0.0.1 9051 2>/dev/null || true)
    echo "$FASE" | grep -q 'PROGRESS=100' && break
  fi
  i=$((i + 1)); sleep 3
done
log "Tor pronto."

# --- 3. iniciar o dnscrypt-proxy ------------------------------------------
log "Iniciando dnscrypt-proxy..."
iniciar_dnscrypt

# --- 4. gate: aguardar a resolução DNS funcionar via 127.0.0.1 -------------
log "Aguardando o dnscrypt-proxy resolver..."
i=0
while [ "$i" -lt 60 ]; do
  if [ -n "$(dig +short +time=5 +tries=1 "@127.0.0.1" example.com A 2>/dev/null)" ]; then
    break
  fi
  i=$((i + 1)); sleep 2
done
log "Resolução DNS pronta."

# --- 5. loop de renovação de circuito Tor ----------------------------------
/opt/zonet/scripts/renovar_circuito.sh &
REN_PID=$!

# --- 6. iniciar o Gunicorn -------------------------------------------------
log "Iniciando Gunicorn na porta 5000..."
cd /opt/zonet
# O log de acesso é descartado (/dev/null): registrar cada requisição deixaria
# rastros dos scans. Apenas erros vão para o stderr.
gunicorn \
  --chdir /opt/zonet \
  --bind 0.0.0.0:5000 \
  --workers 1 --threads 8 \
  --timeout 150 \
  --access-logfile /dev/null --error-logfile - \
  app.wsgi:application &
GUNICORN_PID=$!

# --- 7. supervisão contínua dos daemons ------------------------------------
# Fecha o gap de não haver supervisão pós-arranque: se o Tor ou o
# dnscrypt-proxy encerrar, são reiniciados; se o Gunicorn cair, o contêiner é
# finalizado para que o orquestrador o trate.
log "Supervisionando daemons..."
while true; do
  sleep 20
  if ! kill -0 "$GUNICORN_PID" 2>/dev/null; then
    log "Gunicorn encerrou; finalizando contêiner."
    break
  fi
  if ! kill -0 "$TOR_PID" 2>/dev/null; then
    log "Tor caiu; reiniciando."
    iniciar_tor
  fi
  if ! kill -0 "$DC_PID" 2>/dev/null; then
    log "dnscrypt-proxy caiu; reiniciando."
    iniciar_dnscrypt
  fi
  if ! kill -0 "$REN_PID" 2>/dev/null; then
    log "Loop de renovação de circuito caiu; reiniciando."
    /opt/zonet/scripts/renovar_circuito.sh &
    REN_PID=$!
  fi
done

encerrar
