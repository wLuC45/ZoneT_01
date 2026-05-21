#!/bin/sh
# run.sh — constrói e executa o contêiner ZoneT_01.
#
# Usa podman por padrão; passe `docker` como 1o argumento para usar Docker.
# A interface ficará em http://localhost:5000
#
# Para esconder o uso do Tor da rede do operador, coloque bridges obfs4 num
# arquivo e exporte ZONET_BRIDGES com o caminho dele antes de rodar este script
# (ver infra/tor/bridges.exemplo.conf).
set -eu

MOTOR="${1:-podman}"
IMAGEM="zonet01:latest"
NOME="zonet01"

echo "[run] Construindo a imagem com ${MOTOR}..."
"${MOTOR}" build -t "${IMAGEM}" -f Containerfile .

echo "[run] Removendo contêiner anterior, se existir..."
"${MOTOR}" rm -f "${NOME}" >/dev/null 2>&1 || true

# Monta o arquivo de bridges, se o operador tiver indicado um.
MONTA_BRIDGES=""
if [ -n "${ZONET_BRIDGES:-}" ] && [ -f "${ZONET_BRIDGES}" ]; then
  echo "[run] Usando bridges de ${ZONET_BRIDGES}"
  MONTA_BRIDGES="--volume ${ZONET_BRIDGES}:/etc/tor/bridges.conf:ro"
fi

# Geolocalização externa fica desativada salvo opt-in explícito do operador.
ENV_GEO=""
if [ -n "${ZONET_GEOIP_API:-}" ]; then
  echo "[run] Geolocalização externa ATIVADA (ZONET_GEOIP_API=${ZONET_GEOIP_API})"
  ENV_GEO="--env ZONET_GEOIP_API=${ZONET_GEOIP_API}"
fi

echo "[run] Iniciando o contêiner..."
# Notas de rede e OPSEC:
#   * rede 'bridge' (nao 'none'): --publish exige rede e o Tor precisa de
#     saida. O anti-vazamento vem da configuracao -- todo processo resolve via
#     127.0.0.1 (dnscrypt-proxy), que so sai pela rede Tor.
#   * --read-only + tmpfs em todo caminho gravavel => nada persiste em disco.
#   * --log-driver none: a saida dos daemons nao e gravada no disco do host,
#     evitando rastro forense dos scans.
#   * --rm: ao parar, o conteiner e removido por completo.
# shellcheck disable=SC2086
"${MOTOR}" run -d --rm \
  --name "${NOME}" \
  --publish 127.0.0.1:5000:5000 \
  --network bridge \
  --dns 127.0.0.1 \
  --read-only \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --log-driver none \
  --memory 512m \
  ${MONTA_BRIDGES} \
  ${ENV_GEO} \
  --tmpfs /var/lib/tor:rw,mode=0700,size=32m \
  --tmpfs /var/cache/dnscrypt-proxy:rw,mode=0755,size=16m \
  --tmpfs /var/log/zonet:rw,mode=0755,size=32m \
  --tmpfs /run:rw,mode=0755,size=16m \
  --tmpfs /tmp:rw,mode=1777,size=32m \
  "${IMAGEM}"

echo "[run] Conteiner iniciado. O bootstrap do Tor leva ~30-60s."
echo "[run] Verifique a prontidao:  curl -s http://localhost:5000/readyz"
echo "[run] Teste de fumaca:        ${MOTOR} exec ${NOME} sh /opt/zonet/scripts/verificar_pilha.sh"
echo "[run] Interface web:          http://localhost:5000"
