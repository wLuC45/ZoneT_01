"""Orquestrador do reconhecimento DNS — encadeia os estágios do scan.

A função pública é ``executar_recon``. Cada estágio é uma operação isolada
delegada a um módulo dedicado; aqui se cuida apenas da ordem, do paralelismo
controlado e do relatório de progresso.

Os estágios custosos são paralelizados: as consultas de registros do domínio
e o processamento de cada nameserver rodam num pool limitado. Como cada
tarefa é uma função sem estado compartilhado, a thread principal apenas
funde os resultados à medida que ficam prontos.

Cada estágio reporta progresso por um callback ``relatar(progresso, etapa)``.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from . import ferramentas_dns as fdns
from . import geolocalizacao as geo
from . import postura_dns
from . import subdominios as subs
from . import varredura_portas as portas
from .classificacao_risco import classificar
from .coleta_ips import ColetorIPs
from .processador_ns import processar_nameserver
from .recon_host import recon_host_sem_zona, recon_ip_sem_zona
from .utilitarios import validar_alvo

# Limite de IPs enviados à geolocalização. Uma zona transferida pode conter
# centenas de registros A; o ``ColetorIPs`` garante que IPs do domínio e dos
# nameservers ocupem as primeiras posições.
_LIMITE_GEO = 40

# Paralelismo máximo dentro de um único scan. Combinado com o limite global
# de scans simultâneos do ``GerenciadorJobs``, mantém o número total de
# subprocessos sob controle.
_MAX_PARALELO = 5

# Tipos de registro do domínio resolvidos no estágio de coleta.
_TIPOS_DOMINIO = ("A", "AAAA", "MX", "TXT", "SOA")


def _sem_relato(_progresso, _etapa):
    """Callback nulo padrão (consumido quando o chamador não informa um)."""


def _consultar_seguro(nome, tipo):
    """Wrapper de ``consultar`` que retorna lista vazia em vez de levantar."""
    try:
        return fdns.consultar(nome, tipo)
    except fdns.ErroFerramentaDNS:
        return []


def _esqueleto_resultado(dominio, tipo):
    """Resultado vazio com todas as chaves esperadas pelo front-end."""
    return {
        "alvo": dominio,
        "tipo": tipo,
        "nameservers": [],
        "registros_dominio": {},
        "whois": "",
        "axfr": [],
        "subdominios": {"wildcard": False, "encontrados": []},
        "postura": {},
        "portas": {"executada": False, "motivo": "não solicitada"},
        "geo": {},
        "risco": {},
        "erro": None,
    }


def _resolver_alvo_ip(valor, varrer_portas, relatar):
    """Para um alvo IP, deriva um domínio via PTR ou recai em recon de IP.

    Retorna ``(dominio, resultado_pronto)``. Se o segundo elemento não for
    ``None``, ele é o resultado final do scan e o orquestrador deve devolvê-lo
    imediatamente (sem prosseguir com o caminho de zona).
    """
    relatar(10, f"Resolvendo PTR de {valor}...")
    ptrs = _consultar_seguro(valor, "PTR")
    if not ptrs:
        return None, recon_ip_sem_zona(
            valor, "Sem registro PTR: não há domínio associado para AXFR.",
            varrer_portas,
        )

    # Reduz o PTR a um domínio de até dois rótulos como melhor esforço.
    dominio = ptrs[0].rstrip(".")
    partes = dominio.split(".")
    if len(partes) > 2:
        dominio = ".".join(partes[-2:])

    # O PTR é controlado por quem opera o DNS reverso; o domínio derivado
    # precisa ser revalidado antes de chegar a um subprocesso.
    try:
        _tipo, dominio = validar_alvo(dominio)
    except ValueError:
        return None, recon_ip_sem_zona(
            valor, f"PTR derivou um domínio inválido: {dominio!r}",
            varrer_portas,
        )

    relatar(15, f"Domínio derivado do PTR: {dominio}")
    return dominio, None


def _resolver_registros_dominio(dominio):
    """Consulta em paralelo os tipos de registro do domínio raiz."""
    registros = {}
    with ThreadPoolExecutor(max_workers=len(_TIPOS_DOMINIO)) as executor:
        futuros = {
            executor.submit(_consultar_seguro, dominio, tipo): tipo
            for tipo in _TIPOS_DOMINIO
        }
        for futuro in as_completed(futuros):
            valores = futuro.result()
            if valores:
                registros[futuros[futuro]] = valores
    return registros


def _processar_todos_ns(dominio, nameservers, relatar, coletor):
    """Dispara o processamento paralelo dos nameservers e agrega resultados.

    Para cada NS, registra os IPs próprios como prioritários e os IPs vistos
    em registros A/AAAA da zona transferida como secundários. A ordenação
    final por nome de servidor garante saída determinística para o front-end.
    """
    total = len(nameservers)
    base, faixa = 30, 32  # faixa de progresso atribuída a esta etapa
    paralelismo = min(total, _MAX_PARALELO)
    resultados = []

    with ThreadPoolExecutor(max_workers=paralelismo) as executor:
        futuros = {
            executor.submit(processar_nameserver, dominio, ns): ns
            for ns in nameservers
        }
        concluidos = 0
        for futuro in as_completed(futuros):
            resultado_ns = futuro.result()
            resultados.append(resultado_ns)
            concluidos += 1
            relatar(
                base + int(faixa * concluidos / total),
                f"AXFR testado: {concluidos}/{total} nameservers",
            )
            for ip in resultado_ns.get("ips_ns", []):
                coletor.adicionar_prioritario(ip)
            for linha in resultado_ns["linhas"]:
                partes = linha.split("\t", 4)
                if len(partes) >= 5 and partes[3] in ("A", "AAAA"):
                    coletor.adicionar_secundario(partes[4].strip())

    resultados.sort(key=lambda r: r["servidor"])
    for r in resultados:
        r.pop("ips_ns", None)  # campo interno, oculto na resposta final
    return resultados


def executar_recon(alvo, relatar=None, varrer_portas=False):
    """Executa o reconhecimento completo de ``alvo`` (domínio ou IP).

    ``relatar`` é um callable ``(progresso:int, etapa:str)``. ``varrer_portas``
    ativa a varredura de portas via Tor (opcional, mais lenta). Retorna um
    dict com o resultado completo do scan.
    """
    relatar = relatar or _sem_relato

    # --- Estágio 1: validar alvo -------------------------------------------
    relatar(0, "Validando alvo...")
    tipo, valor = validar_alvo(alvo)

    ip_alvo = valor if tipo == "ip" else None

    if tipo == "ip":
        dominio, resultado_pronto = _resolver_alvo_ip(
            valor, varrer_portas, relatar,
        )
        if resultado_pronto is not None:
            return resultado_pronto
    else:
        dominio = valor

    resultado = _esqueleto_resultado(dominio, tipo)

    # --- Estágio 2: coletar nameservers ------------------------------------
    relatar(15, "Coletando servidores autoritativos (NS)...")
    nameservers = fdns.obter_ns(dominio)
    resultado["nameservers"] = nameservers
    if not nameservers:
        # Não é ápice de zona — segue o fluxo de host.
        return recon_host_sem_zona(
            dominio, ip_alvo, varrer_portas, relatar, resultado, _LIMITE_GEO,
        )

    # --- Estágio 3: registros do domínio (em paralelo) ---------------------
    relatar(25, "Resolvendo registros A/AAAA/MX/TXT...")
    registros_dominio = _resolver_registros_dominio(dominio)
    resultado["registros_dominio"] = registros_dominio

    coletor = ColetorIPs()
    for tipo_registro in ("A", "AAAA"):
        for valor in registros_dominio.get(tipo_registro, []):
            coletor.adicionar_prioritario(valor)

    if ip_alvo is None and coletor.prioritarios:
        ip_alvo = coletor.prioritarios[0]

    # --- Estágio 4: nameservers e AXFR (em paralelo) -----------------------
    resultados_axfr = _processar_todos_ns(
        dominio, nameservers, relatar, coletor,
    )
    resultado["axfr"] = resultados_axfr

    # --- Estágio 5: enumeração de subdomínios ------------------------------
    relatar(64, "Enumerando subdomínios...")
    sub = subs.enumerar(dominio)
    resultado["subdominios"] = sub
    for item in sub.get("encontrados", []):
        for ip in item.get("ips", []):
            coletor.adicionar_secundario(ip)

    # --- Estágio 6: postura de DNS e e-mail --------------------------------
    relatar(72, "Avaliando postura de DNS e e-mail...")
    resultado["postura"] = postura_dns.avaliar(dominio)

    # --- Estágio 7: varredura de portas via Tor (opcional) -----------------
    if varrer_portas:
        if ip_alvo:
            relatar(76, f"Varrendo portas de {ip_alvo} via Tor...")
            resultado["portas"] = portas.varrer(ip_alvo)
        else:
            resultado["portas"] = {
                "executada": False,
                "motivo": "nenhum IP do alvo foi resolvido",
            }

    # --- Estágio 8: whois --------------------------------------------------
    relatar(84, "Consultando whois do domínio...")
    resultado["whois"] = fdns.whois_dominio(dominio)

    # --- Estágio 9: geolocalização via Tor ---------------------------------
    alvos_geo = coletor.combinados(_LIMITE_GEO)
    relatar(89, f"Geolocalizando {len(alvos_geo)} IPs...")
    resultado["geo"] = geo.localizar_varios(alvos_geo)

    # --- Estágio 10: classificação de risco --------------------------------
    relatar(95, "Classificando risco...")
    resultado["risco"] = classificar(resultados_axfr)

    relatar(100, "Reconhecimento concluído.")
    return resultado
