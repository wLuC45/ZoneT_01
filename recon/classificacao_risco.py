"""Classificação de risco a partir dos desfechos de AXFR por nameserver.

A pontuação não usa degraus fixos: para o nível CRITICO ela é uma função
contínua da exposição, modelada por uma curva de saturação exponencial
``1 - e^(-x)``. Assim, quanto mais registros expostos (e quanto mais deles
parecerem internos), maior a pontuação, com retornos decrescentes que se
aproximam assintoticamente do teto de 100.
"""

import math

from .utilitarios import eh_ip_interno

# Constante de escala da curva de exposição. Registros internos pesam 4x.
_ESCALA_EXPOSICAO = 60.0
_PESO_INTERNO = 4

# Indícios de nomes "internos" expostos numa zona transferida.
_PALAVRAS_INTERNAS = (
    "internal", "interno", "intranet", "vpn", "dev", "test", "teste",
    "staging", "homolog", "corp", "lan", "local", "private", "privado",
    "admin", "backup", "db", "sql",
)


def _contar_nomes_internos(linhas):
    """Conta registros cujo nome ou valor sugere infraestrutura interna."""
    total = 0
    for linha in linhas:
        partes = linha.split("\t", 4)
        if len(partes) < 5:
            continue
        nome, _ttl, _classe, tipo, valor = partes
        nome_baixo = nome.lower()
        if any(p in nome_baixo for p in _PALAVRAS_INTERNAS):
            total += 1
        elif tipo in ("A", "AAAA") and eh_ip_interno(valor.strip()):
            total += 1
    return total


def _fator_exposicao(registros, internos):
    """Curva de saturação ``1 - e^(-x)`` em [0, 1).

    ``x`` combina o total de registros expostos e os registros internos, estes
    com peso maior. A saturação dá retornos decrescentes: as primeiras dezenas
    de registros elevam muito a pontuação; centenas adicionais quase não mudam.
    """
    x = (registros + _PESO_INTERNO * internos) / _ESCALA_EXPOSICAO
    return 1.0 - math.exp(-x)


def classificar(resultados_ns):
    """Classifica o risco geral do domínio.

    ``resultados_ns`` é uma lista de dicts, cada um com ao menos as chaves
    ``servidor``, ``desfecho`` e ``linhas`` (registros transferidos, se houver).

    Retorna dict: ``nivel``, ``pontuacao`` (0-100), ``motivos`` e
    ``recomendacoes``.
    """
    motivos = []
    recomendacoes = []

    transferidos = [r for r in resultados_ns if r["desfecho"] == "transferido"]
    negados = [r for r in resultados_ns if r["desfecho"] == "negado"]
    total = len(resultados_ns)

    if transferidos:
        nivel = "CRITICO"
        servidores = ", ".join(sorted({r["servidor"] for r in transferidos}))
        motivos.append(
            f"Transferência de zona não autenticada permitida em: {servidores}."
        )

        linhas_unicas = set()
        for r in transferidos:
            linhas_unicas.update(r.get("linhas", []))
        total_registros = len(linhas_unicas)
        motivos.append(
            f"{total_registros} registros DNS expostos ao público."
        )

        internos = _contar_nomes_internos(linhas_unicas)
        # Base 90 (piso do nível CRITICO) mais até 10 conforme a exposição.
        pontuacao = min(
            100,
            90 + round(10 * _fator_exposicao(total_registros, internos)),
        )
        if internos:
            motivos.append(
                f"{internos} registros sugerem infraestrutura interna "
                "(subdomínios sensíveis ou IPs privados)."
            )
        recomendacoes.append(
            "Restrinja AXFR aos IPs dos servidores secundários autorizados "
            "(allow-transfer / TSIG)."
        )
        recomendacoes.append(
            "Audite os registros expostos e remova entradas internas do DNS "
            "público."
        )
    elif total == 0:
        nivel = "INDETERMINADO"
        pontuacao = 50
        motivos.append("Nenhum nameserver autoritativo foi identificado.")
        recomendacoes.append("Verifique se o domínio está corretamente delegado.")
    elif len(negados) == total:
        nivel = "BAIXO"
        # Quanto mais nameservers confirmam a recusa, maior a confiança e
        # menor a pontuação residual de risco (piso de 5).
        pontuacao = max(5, 12 - total)
        motivos.append(
            f"Todos os {total} nameservers recusaram a transferência de zona."
        )
        recomendacoes.append(
            "Configuração adequada — mantenha as restrições de AXFR."
        )
    else:
        nivel = "INDETERMINADO"
        inacessiveis = total - len(negados)
        # Pondera a incerteza: 40 mais um acréscimo proporcional à fração de
        # nameservers que não puderam ser avaliados.
        pontuacao = 40 + round(10 * inacessiveis / total)
        motivos.append(
            f"{inacessiveis} de {total} nameservers ficaram inacessíveis; "
            "não foi possível confirmar a postura de AXFR."
        )
        if negados:
            motivos.append(
                f"{len(negados)} nameservers recusaram a transferência."
            )
        recomendacoes.append(
            "Reexecute o teste — latência do Tor ou filtragem podem ter "
            "impedido a conclusão."
        )

    return {
        "nivel": nivel,
        "pontuacao": pontuacao,
        "motivos": motivos,
        "recomendacoes": recomendacoes,
    }
