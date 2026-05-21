"""Funções utilitárias de parsing e validação compartilhadas pelo recon."""

import ipaddress
import re
from collections import defaultdict

# Domínio: rótulos alfanuméricos separados por ponto, hífens internos permitidos.
_REGEX_DOMINIO = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$"
)

# Faixas privadas/internas (RFC 1918, loopback, link-local) para heurística de risco.
_FAIXAS_INTERNAS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validar_alvo(alvo):
    """Valida e normaliza um alvo (domínio ou IP).

    Retorna ``(tipo, valor_normalizado)`` onde tipo é ``"dominio"`` ou ``"ip"``.
    Levanta ``ValueError`` para qualquer entrada inválida — essencial porque o
    valor será passado a subprocessos (defesa contra injeção).
    """
    if not alvo or not isinstance(alvo, str):
        raise ValueError("Alvo vazio.")
    alvo = alvo.strip().lower()
    if len(alvo) > 253:
        raise ValueError("Alvo longo demais.")

    # Tenta interpretar como IP literal primeiro.
    try:
        ip = ipaddress.ip_address(alvo)
        return "ip", str(ip)
    except ValueError:
        pass

    alvo_sem_ponto = alvo.rstrip(".")
    if _REGEX_DOMINIO.match(alvo):
        return "dominio", alvo_sem_ponto

    raise ValueError(f"Alvo inválido: {alvo!r}")


def eh_ip_valido(valor):
    """Retorna True se ``valor`` for um endereço IPv4/IPv6 válido."""
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def eh_ip_interno(valor):
    """Retorna True se ``valor`` for um IP de faixa privada/interna."""
    try:
        ip = ipaddress.ip_address(valor)
    except ValueError:
        return False
    return any(ip in faixa for faixa in _FAIXAS_INTERNAS)


def organizar_registros(linhas, formatar_nome):
    """Agrupa linhas de registro DNS por tipo.

    Cada linha segue o formato ``nome<TAB>ttl<TAB>IN<TAB>tipo<TAB>valor``
    (saída de ``dig axfr``). ``formatar_nome`` normaliza o nome do registro.
    Retorna ``dict[tipo -> list[(nome, valor)]]``.
    """
    organizados = defaultdict(list)
    for linha in linhas:
        partes = linha.split("\t", 4)
        if len(partes) >= 5:
            nome, _ttl, _classe, tipo, valor = partes
            organizados[tipo].append((formatar_nome(nome), valor))
    return dict(organizados)
