"""Avaliação da postura de DNS e e-mail de um domínio.

Verifica, com consultas dig, sinais de boa configuração que também interessam
ao reconhecimento: SPF e DMARC (antifraude de e-mail), DNSSEC (integridade das
respostas DNS) e CAA (controle de emissão de certificados). As funções de
parsing são puras, para permitir teste unitário.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from . import ferramentas_dns as fdns


def _limpar_txt(valor):
    """Remove aspas que o dig coloca em volta de registros TXT."""
    return valor.strip().strip('"').strip()


def politica_dmarc(registro):
    """Extrai o valor da tag ``p`` (política) de um registro DMARC."""
    for parte in registro.split(";"):
        parte = parte.strip()
        if parte.lower().startswith("p="):
            return parte.split("=", 1)[1].strip().lower() or "none"
    return "none"


def resumo_spf(registro):
    """Resume a diretiva final de um registro SPF (all qualifier)."""
    reg = registro.lower()
    if "-all" in reg:
        return "rígido (-all)"
    if "~all" in reg:
        return "suave (~all)"
    if "?all" in reg:
        return "neutro (?all)"
    if "+all" in reg:
        return "permissivo (+all)"
    return "sem diretiva all"


def _avaliar_spf(dominio):
    for txt in fdns.consultar(dominio, "TXT"):
        limpo = _limpar_txt(txt)
        if limpo.lower().startswith("v=spf1"):
            return {"presente": True, "registro": limpo,
                    "resumo": resumo_spf(limpo)}
    return {"presente": False, "registro": None, "resumo": "ausente"}


def _avaliar_dmarc(dominio):
    for txt in fdns.consultar(f"_dmarc.{dominio}", "TXT"):
        limpo = _limpar_txt(txt)
        if limpo.lower().startswith("v=dmarc1"):
            return {"presente": True, "registro": limpo,
                    "politica": politica_dmarc(limpo)}
    return {"presente": False, "registro": None, "politica": "ausente"}


def _avaliar_dnssec(dominio):
    ds = fdns.consultar(dominio, "DS")
    dnskey = fdns.consultar(dominio, "DNSKEY")
    return {"presente": bool(ds or dnskey),
            "ds": len(ds), "dnskey": len(dnskey)}


def _avaliar_caa(dominio):
    caa = fdns.consultar(dominio, "CAA")
    return {"presente": bool(caa), "registros": caa}


def avaliar(dominio):
    """Avalia SPF, DMARC, DNSSEC e CAA do domínio (consultas em paralelo)."""
    tarefas = {
        "spf": _avaliar_spf,
        "dmarc": _avaliar_dmarc,
        "dnssec": _avaliar_dnssec,
        "caa": _avaliar_caa,
    }
    resultado = {}
    with ThreadPoolExecutor(max_workers=len(tarefas)) as executor:
        futuros = {
            executor.submit(funcao, dominio): chave
            for chave, funcao in tarefas.items()
        }
        # ``as_completed`` permite que o dict seja preenchido na ordem real
        # de chegada das respostas, sem bloquear no item mais lento.
        for futuro in as_completed(futuros):
            chave = futuros[futuro]
            try:
                resultado[chave] = futuro.result()
            except fdns.ErroFerramentaDNS:
                resultado[chave] = {"presente": False, "erro": "consulta falhou"}
    return resultado
