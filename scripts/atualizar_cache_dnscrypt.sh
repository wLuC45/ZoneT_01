#!/bin/sh
# atualizar_cache_dnscrypt.sh — atualiza as listas de resolvers e relays do
# DNSCrypt embutidas na imagem (infra/dnscrypt/cache/).
#
# Essas listas sao commitadas de proposito: o entrypoint as semeia no cache do
# dnscrypt-proxy para que NAO haja nenhum fetch HTTP no arranque do conteiner
# (ver infra/entrypoint.sh e a secao "DNS sem fetch em tempo de execucao" do
# README). Como consequencia, elas envelhecem. Rode este script
# periodicamente (por exemplo, mensalmente), revise o diff e recommite.
#
# A integridade e garantida pela assinatura minisign: o dnscrypt-proxy valida
# cada lista contra a chave publica fixada em dnscrypt-proxy.toml. Por isso o
# arquivo .minisig e baixado junto.
set -eu

BASE="https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3"
DESTINO="$(CDPATH= cd -- "$(dirname -- "$0")/../infra/dnscrypt/cache" && pwd)"

for nome in public-resolvers.md relays.md; do
  for arquivo in "$nome" "$nome.minisig"; do
    echo "[cache] baixando ${arquivo}..."
    curl -fsS "${BASE}/${arquivo}" -o "${DESTINO}/${arquivo}"
  done
done

echo "[cache] listas atualizadas em ${DESTINO}"
echo "[cache] revise o 'git diff' e recommite; reconstrua a imagem em seguida."
