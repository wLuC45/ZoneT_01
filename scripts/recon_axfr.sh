#!/bin/sh
# recon_axfr.sh — teste de transferência de zona em Bash puro.
#
# Equivalente de linha de comando ao recon/transferencia_zona.py: descobre os
# nameservers de um domínio e tenta AXFR em cada um, com a conexão roteada
# pelo Tor via torsocks. Útil para diagnóstico sem a camada web.
#
# Uso: ./recon_axfr.sh <dominio>
set -u

RESOLVEDOR="127.0.0.1"
TIMEOUTS="10 20 40"

if [ "$#" -ne 1 ]; then
  echo "Uso: $0 <dominio>" >&2
  exit 1
fi
DOMINIO="$1"

# O AXFR sempre sai pela rede Tor via torsocks. Sem torsocks, o script aborta:
# uma conexão direta exporia o IP do operador (falha fechada).
if ! command -v torsocks >/dev/null 2>&1; then
  echo "[erro] torsocks ausente: conexao direta bloqueada pela politica de" \
       "anonimato. Abortando." >&2
  exit 3
fi
TORWRAP="torsocks"

echo "=== ZoneT_01 — recon AXFR de ${DOMINIO} ==="

NAMESERVERS=$(dig +short NS "${DOMINIO}" "@${RESOLVEDOR}" | sed 's/\.$//')
if [ -z "${NAMESERVERS}" ]; then
  echo "[erro] Nenhum nameserver encontrado para ${DOMINIO}." >&2
  exit 2
fi

for NS in ${NAMESERVERS}; do
  IP=$(dig +short A "${NS}" "@${RESOLVEDOR}" | head -n1)
  if [ -z "${IP}" ]; then
    echo "[${NS}] inacessível — sem IP."
    continue
  fi
  echo "--- ${NS} (${IP}) ---"

  TRANSFERIDO=0
  for T in ${TIMEOUTS}; do
    SAIDA=$(${TORWRAP} dig axfr "${DOMINIO}" "@${IP}" \
            +tcp "+time=${T}" +tries=1 +nocomments +nostats 2>&1)
    if echo "${SAIDA}" | grep -qiE '[[:space:]]IN[[:space:]]'; then
      echo "${SAIDA}" | grep -E '[[:space:]]IN[[:space:]]'
      echo "[${NS}] VULNERÁVEL — transferência de zona permitida."
      TRANSFERIDO=1
      break
    fi
    if echo "${SAIDA}" | grep -qiE 'transfer failed|refused|communications error'; then
      echo "[${NS}] transferência negada (configuração correta)."
      TRANSFERIDO=2
      break
    fi
  done
  [ "${TRANSFERIDO}" -eq 0 ] && echo "[${NS}] inacessível após todas as tentativas."
done
