"""Processamento independente de cada nameserver: resolução de IPs e AXFR.

Isolado do orquestrador para permitir teste unitário. Cada chamada é uma
tarefa autônoma, sem estado compartilhado, podendo executar em paralelo com
outras dentro de um pool de threads.
"""

from . import ferramentas_dns as fdns
from .transferencia_zona import tentar_axfr

# Ordem de prioridade dos desfechos quando um NS possui vários IPs: o pior
# cenário (zona transferida) suplanta os demais; uma recusa explícita é
# preferida sobre um nameserver inacessível.
PRIORIDADE_DESFECHO = {"transferido": 3, "negado": 2, "inacessivel": 1}


def _resultado_inacessivel(nameserver):
    """Resultado uniforme para um nameserver que não pôde ser resolvido."""
    return {
        "servidor": nameserver,
        "ip": None,
        "desfecho": "inacessivel",
        "mensagem": "Não foi possível resolver o IP do nameserver.",
        "registros": {},
        "linhas": [],
        "ips_ns": [],
    }


def processar_nameserver(dominio, nameserver):
    """Resolve o IP de ``nameserver`` e tenta o AXFR contra cada endereço.

    Retorna um dicionário descrevendo o melhor desfecho observado entre os
    IPs daquele NS: o pior caso (uma zona transferida) prevalece sobre uma
    recusa explícita, que por sua vez prevalece sobre inacessibilidade.

    Mantida como função pura em relação a estado externo: pode rodar em
    paralelo com chamadas para outros nameservers sem coordenação.
    """
    ips_ns = fdns.resolver_ips(nameserver)
    if not ips_ns:
        return _resultado_inacessivel(nameserver)

    melhor = None
    melhor_ip = None
    for ip in ips_ns:
        tentativa = tentar_axfr(dominio, ip)
        if (melhor is None
                or PRIORIDADE_DESFECHO[tentativa["desfecho"]]
                > PRIORIDADE_DESFECHO[melhor["desfecho"]]):
            melhor, melhor_ip = tentativa, ip
        # Não há ganho em testar outros IPs após confirmar a vulnerabilidade.
        if tentativa["desfecho"] == "transferido":
            break

    return {
        "servidor": nameserver,
        "ip": melhor_ip,
        "desfecho": melhor["desfecho"],
        "mensagem": melhor["mensagem"],
        "registros": melhor["registros"],
        "linhas": melhor["linhas"],
        "ips_ns": ips_ns,
    }
