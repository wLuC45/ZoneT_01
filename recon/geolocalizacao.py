"""Enriquecimento de IPs com geolocalização e ASN.

Por padrão a geolocalização fica DESATIVADA. Consultar uma API externa, ainda
que pela rede Tor, revela ao serviço e ao nó de saída do Tor quais endereços
estão sendo investigados. Quem aceita esse compromisso ativa a consulta com a
variável de ambiente ``ZONET_GEOIP_API=1``.

Quando ativada, a API gratuita ip-api.com é consultada através do proxy SOCKS5
do Tor (``socks5h://`` — o ``h`` garante que a resolução DNS do hostname da API
também ocorra dentro do Tor). Usa-se o endpoint em lote: uma única requisição
resolve até 100 endereços, em vez de uma requisição por IP. Isso troca um custo
de rede O(n), com O(n) esperas de rate limit, por O(ceil(n/100)) requisições.
A requisição é endurecida contra fingerprinting: sem variáveis de ambiente de
proxy, sem .netrc, sem redirecionamentos e com User-Agent neutro. Falhas são
não fatais: a recon continua sem geolocalização.
"""

import os
import time

from .utilitarios import eh_ip_interno, eh_ip_valido

try:
    import requests
except ImportError:  # pragma: no cover - requests é dependência declarada
    requests = None

_PROXY_TOR = "socks5h://127.0.0.1:9050"
_ENDPOINT = "http://ip-api.com/json/{ip}"
_ENDPOINT_LOTE = "http://ip-api.com/batch"
_CAMPOS = "status,message,country,city,regionName,isp,org,as,lat,lon,query"

# ip-api.com aceita até 100 IPs por requisição em lote.
_TAM_LOTE = 100
# Espera entre lotes consecutivos (só relevante para mais de 100 IPs).
_INTERVALO_LOTE = 1.4  # segundos

# User-Agent neutro: evita anunciar "python-requests/x.y" ao destino.
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
)

_MSG_DESATIVADA = (
    "geolocalização desativada (defina ZONET_GEOIP_API=1 para ativar)"
)


def _api_habilitada():
    """A consulta à API externa só ocorre se explicitamente ativada."""
    return os.environ.get("ZONET_GEOIP_API", "").strip().lower() in (
        "1", "true", "sim", "on", "yes",
    )


def _sessao():
    """Cria uma sessão requests isolada do ambiente, roteada pelo Tor."""
    sess = requests.Session()
    sess.trust_env = False  # ignora HTTP(S)_PROXY, NO_PROXY e .netrc do ambiente
    sess.proxies = {"http": _PROXY_TOR, "https": _PROXY_TOR}
    sess.headers.update({"User-Agent": _USER_AGENT, "Accept": "application/json"})
    return sess


def _mapear(ip, dados):
    """Converte um item de resposta da API no dicionário de resultado."""
    if not isinstance(dados, dict) or dados.get("status") != "success":
        msg = "consulta sem sucesso"
        if isinstance(dados, dict):
            msg = dados.get("message", msg)
        return {"ip": ip, "erro": msg}
    return {
        "ip": ip,
        "pais": dados.get("country"),
        "regiao": dados.get("regionName"),
        "cidade": dados.get("city"),
        "isp": dados.get("isp"),
        "organizacao": dados.get("org"),
        "asn": dados.get("as"),
        "latitude": dados.get("lat"),
        "longitude": dados.get("lon"),
    }


def localizar_ip(ip, sessao=None):
    """Consulta geolocalização/ASN de um único IP. Retorna dict (nunca levanta)."""
    if not eh_ip_valido(ip):
        return {"ip": ip, "erro": "endereço IP inválido"}
    if eh_ip_interno(ip):
        # IPs privados/reservados não são geolocalizáveis; evita uma chamada
        # de API inútil.
        return {"ip": ip, "erro": "IP privado ou reservado, sem geolocalização"}
    if not _api_habilitada():
        return {"ip": ip, "erro": _MSG_DESATIVADA}
    if requests is None:
        return {"ip": ip, "erro": "biblioteca requests indisponível"}

    fechar = sessao is None
    sessao = sessao or _sessao()
    try:
        resp = sessao.get(
            _ENDPOINT.format(ip=ip),
            params={"fields": _CAMPOS},
            timeout=20,
            allow_redirects=False,
        )
        if resp.status_code >= 400:
            return {"ip": ip, "erro": f"resposta HTTP {resp.status_code}"}
        return _mapear(ip, resp.json())
    except Exception as exc:  # rede/Tor/JSON — degradação graciosa
        return {"ip": ip, "erro": f"falha na consulta: {exc}"}
    finally:
        if fechar:
            sessao.close()


def _consultar_lote(sessao, ips):
    """Consulta um lote de IPs públicos no endpoint batch. Uma só requisição.

    Retorna ``dict[ip -> resultado]``. A resposta da API preserva a ordem dos
    IPs enviados; itens faltantes (caso a API responda menos do que pediu)
    são preenchidos com um erro genérico para manter o tamanho consistente.
    """
    try:
        resp = sessao.post(
            _ENDPOINT_LOTE,
            params={"fields": _CAMPOS},
            json=ips,
            timeout=30,
            allow_redirects=False,
        )
    except Exception as exc:
        return {ip: {"ip": ip, "erro": f"falha na consulta: {exc}"} for ip in ips}

    if resp.status_code >= 400:
        msg = f"resposta HTTP {resp.status_code}"
        return {ip: {"ip": ip, "erro": msg} for ip in ips}

    try:
        dados = resp.json()
    except ValueError:
        return {ip: {"ip": ip, "erro": "JSON inválido"} for ip in ips}

    if not isinstance(dados, list):
        return {ip: {"ip": ip, "erro": "resposta inesperada da API"} for ip in ips}

    resultados = {}
    for ip, item in zip(ips, dados):
        resultados[ip] = _mapear(ip, item)
    # Garante uma entrada para cada IP, mesmo que a API devolva menos itens.
    for ip in ips:
        resultados.setdefault(ip, {"ip": ip, "erro": "sem resposta da API"})
    return resultados


def localizar_varios(ips):
    """Geolocaliza uma lista de IPs (deduplicada).

    IPs privados, reservados ou inválidos são resolvidos localmente. Os IPs
    públicos vão para o endpoint em lote, em grupos de até 100.

    Retorna ``dict[ip -> resultado]``.
    """
    resultados = {}
    vistos = set()
    unicos = []
    for ip in ips:
        if ip and ip not in vistos:
            vistos.add(ip)
            unicos.append(ip)

    publicos = [
        ip for ip in unicos if eh_ip_valido(ip) and not eh_ip_interno(ip)
    ]
    publicos_set = set(publicos)

    # Resolve localmente o que não é IP público (privados, reservados, inválidos).
    for ip in unicos:
        if ip not in publicos_set:
            resultados[ip] = localizar_ip(ip)

    if not publicos:
        return resultados

    if not _api_habilitada() or requests is None:
        nota = _MSG_DESATIVADA if not _api_habilitada() else (
            "biblioteca requests indisponível"
        )
        for ip in publicos:
            resultados[ip] = {"ip": ip, "erro": nota}
        return resultados

    sessao = _sessao()
    try:
        for i in range(0, len(publicos), _TAM_LOTE):
            if i > 0:
                time.sleep(_INTERVALO_LOTE)  # espaça lotes consecutivos
            resultados.update(
                _consultar_lote(sessao, publicos[i:i + _TAM_LOTE])
            )
    finally:
        sessao.close()
    return resultados
