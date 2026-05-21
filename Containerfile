# Containerfile — ZoneT_01: scanner AXFR anônimo numa imagem Alpine mínima.
# Compatível com `podman build` e `docker build -f Containerfile`.
FROM alpine:3.21

# --- pacotes de runtime ----------------------------------------------------
#   tor             : daemon de roteamento cebola (anonimização)
#   dnscrypt-proxy  : resolvedor DNSCrypt com DNS anonimizado (repo community)
#   bind-tools      : fornece dig e nslookup
#   whois           : cliente whois
#   torsocks        : embrulha dig AXFR e whois para saírem pela rede Tor
# Bridges vanilla funcionam sem dependência extra. Para bridges obfs4, monte um
# binário obfs4proxy/lyrebird no contêiner (ver infra/tor/bridges.exemplo.conf).
RUN apk add --no-cache \
      tor \
      dnscrypt-proxy \
      bind-tools \
      whois \
      torsocks \
      python3 py3-pip \
      ca-certificates tzdata \
      curl jq \
 && update-ca-certificates

# --- dependências Python (sem dnspython) -----------------------------------
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

# --- código da aplicação ---------------------------------------------------
WORKDIR /opt/zonet
COPY app/     /opt/zonet/app/
COPY recon/   /opt/zonet/recon/
COPY scripts/ /opt/zonet/scripts/
COPY infra/   /opt/zonet/infra/

# --- configuração de runtime nos caminhos esperados ------------------------
COPY infra/tor/torrc                    /etc/tor/torrc
COPY infra/dnscrypt/dnscrypt-proxy.toml /etc/dnscrypt-proxy/dnscrypt-proxy.toml
COPY infra/resolv.conf                  /etc/resolv.conf
RUN chmod +x /opt/zonet/scripts/*.sh /opt/zonet/infra/entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/opt/zonet/infra/entrypoint.sh"]
