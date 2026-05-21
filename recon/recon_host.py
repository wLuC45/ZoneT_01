"""Fluxos de reconhecimento que não envolvem zona DNS.

Cobre dois casos em que o caminho AXFR não se aplica:

* um nome que não é ápice de zona (por exemplo ``www.exemplo.com``): coleta-se
  apenas o que o nome oferece (registros, portas, whois, geolocalização);
* um alvo informado como endereço IP literal: aplica-se a varredura de portas
  e a geolocalização, sem AXFR.

Separar esses fluxos do orquestrador principal reduz a quantidade de
condicionais em ``executar_recon`` e facilita o teste em isolamento.
"""

from . import ferramentas_dns as fdns
from . import geolocalizacao as geo
from . import varredura_portas as portas
from .classificacao_risco import classificar
from .coleta_ips import ColetorIPs

# Tipos de registro relevantes para um host que não é ápice de zona.
_TIPOS_HOST = ("A", "AAAA", "MX", "TXT")


def _consultar_seguro(nome, tipo):
    """Consulta um registro DNS retornando lista vazia em caso de falha."""
    try:
        return fdns.consultar(nome, tipo)
    except fdns.ErroFerramentaDNS:
        return []


def recon_host_sem_zona(
    nome, ip_alvo, varrer_portas, relatar, resultado, limite_geo,
):
    """Reconhecimento de um nome cujo ápice de zona não foi identificado.

    Resolve registros A/AAAA/MX/TXT, geolocaliza os endereços encontrados e,
    se solicitado, executa a varredura de portas. Preenche e devolve o dict
    ``resultado`` já inicializado pelo chamador.
    """
    relatar(30, "Sem NS no nome; reconhecimento do host...")

    registros = {}
    coletor = ColetorIPs()
    for tipo_registro in _TIPOS_HOST:
        valores = _consultar_seguro(nome, tipo_registro)
        if valores:
            registros[tipo_registro] = valores
    resultado["registros_dominio"] = registros

    for tipo_registro in ("A", "AAAA"):
        for valor in registros.get(tipo_registro, []):
            coletor.adicionar_prioritario(valor)

    if ip_alvo is None and coletor.prioritarios:
        ip_alvo = coletor.prioritarios[0]

    if varrer_portas:
        if ip_alvo:
            relatar(45, f"Varrendo portas de {ip_alvo} via Tor...")
            resultado["portas"] = portas.varrer(ip_alvo)
        else:
            resultado["portas"] = {
                "executada": False,
                "motivo": "nenhum IP do alvo foi resolvido",
            }

    relatar(82, "Consultando whois...")
    resultado["whois"] = fdns.whois_dominio(nome)

    relatar(90, f"Geolocalizando {len(coletor.prioritarios)} IPs...")
    resultado["geo"] = geo.localizar_varios(coletor.combinados(limite_geo))
    resultado["risco"] = classificar([])

    relatar(100, "Reconhecimento do host concluído.")
    return resultado


def recon_ip_sem_zona(ip, erro, varrer_portas=False):
    """Resultado uniforme para um alvo IP que não conduziu a um domínio.

    Usado quando o reverso (PTR) é ausente ou derivou um domínio inválido.
    """
    if varrer_portas:
        resultado_portas = portas.varrer(ip)
    else:
        resultado_portas = {"executada": False, "motivo": "não solicitada"}
    return {
        "alvo": ip,
        "tipo": "ip",
        "nameservers": [],
        "registros_dominio": {},
        "whois": "",
        "axfr": [],
        "subdominios": {"wildcard": False, "encontrados": []},
        "postura": {},
        "portas": resultado_portas,
        "geo": geo.localizar_varios([ip]),
        "risco": classificar([]),
        "erro": erro,
    }
