"""Enumeração de subdomínios por força bruta de DNS.

Cada candidato de uma lista embutida é resolvido (A/AAAA) através da cadeia
DNSCrypt mais Tor. As consultas rodam em paralelo num pool limitado. Antes da
enumeração, detecta-se DNS curinga (wildcard): se um rótulo aleatório resolve,
a força bruta de registros A não é confiável e é abortada, evitando uma lista
inteira de falsos positivos.
"""

import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import ferramentas_dns as fdns

# Paralelismo da enumeração.
_MAX_PARALELO = 10

# Candidatos relevantes para reconhecimento de hosts.
_CANDIDATOS = (
    "www", "mail", "smtp", "imap", "pop", "webmail", "mx", "ns1", "ns2",
    "ftp", "sftp", "ssh", "vpn", "remote", "gateway", "proxy", "fw", "router",
    "dev", "staging", "test", "qa", "uat", "demo", "sandbox", "lab",
    "api", "app", "web", "portal", "dashboard", "painel", "panel", "cpanel",
    "admin", "secure", "login", "auth", "sso", "ldap", "adfs",
    "git", "gitlab", "jenkins", "ci", "registry", "docker", "k8s",
    "db", "sql", "mysql", "postgres", "mongo", "redis", "elastic",
    "backup", "old", "legacy", "cdn", "static", "assets", "media", "files",
    "download", "intranet", "internal", "interno", "corp", "mobile", "m",
    "blog", "shop", "loja", "status", "monitor", "grafana", "kibana",
    "jira", "wiki", "support", "suporte", "help",
)


def detectar_wildcard(dominio):
    """Retorna True se o domínio responde a um subdomínio aleatório (curinga)."""
    aleatorio = secrets.token_hex(10)
    return bool(fdns.resolver_ips(f"{aleatorio}.{dominio}"))


def _sondar(dominio, candidato):
    """Resolve um candidato; retorna (candidato, lista_de_ips)."""
    try:
        ips = fdns.resolver_ips(f"{candidato}.{dominio}")
    except fdns.ErroFerramentaDNS:
        ips = []
    return candidato, ips


def enumerar(dominio):
    """Enumera subdomínios de ``dominio``.

    Retorna ``{"wildcard": bool, "encontrados": [{"sub", "fqdn", "ips"}]}``.
    Com DNS curinga, a enumeração é abortada e ``encontrados`` fica vazio.
    """
    if detectar_wildcard(dominio):
        return {"wildcard": True, "encontrados": []}

    encontrados = []
    with ThreadPoolExecutor(max_workers=_MAX_PARALELO) as executor:
        futuros = [
            executor.submit(_sondar, dominio, c) for c in _CANDIDATOS
        ]
        for futuro in as_completed(futuros):
            candidato, ips = futuro.result()
            if ips:
                encontrados.append({
                    "sub": candidato,
                    "fqdn": f"{candidato}.{dominio}",
                    "ips": ips,
                })
    encontrados.sort(key=lambda e: e["sub"])
    return {"wildcard": False, "encontrados": encontrados}
