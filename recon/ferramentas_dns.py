"""Wrappers de subprocesso para as ferramentas clássicas dig / nslookup / whois.

Regras de segurança aplicadas em todo o módulo:
  * Todos os comandos são listas de argumentos (argv) — NUNCA ``shell=True``.
  * Consultas recursivas vão sempre a ``@127.0.0.1`` (dnscrypt-proxy local), de
    modo que mesmo um resolv.conf incorreto não causaria vazamento.
  * Estas consultas recursivas NÃO são embrulhadas com torsocks: elas falam com
    o resolvedor local, que por sua vez sai pelo Tor. (torsocks não roteia UDP.)
"""

import shutil
import subprocess

from .utilitarios import eh_ip_valido

RESOLVEDOR_LOCAL = "127.0.0.1"
_TIMEOUT_PADRAO = 35  # segundos para o subprocesso dig (margem para latência do Tor)


class ErroFerramentaDNS(Exception):
    """Falha ao executar uma ferramenta DNS externa."""


def _executar(argv, timeout=_TIMEOUT_PADRAO):
    """Executa ``argv`` e retorna stdout (str). Levanta ErroFerramentaDNS.

    ``errors="replace"`` é essencial: respostas de whois de alguns registros e
    valores de registros DNS podem conter bytes que não são UTF-8 válido. Sem
    isso, ``subprocess.run`` levantaria ``UnicodeDecodeError`` e abortaria o
    scan inteiro.
    """
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ErroFerramentaDNS(f"Ferramenta não encontrada: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ErroFerramentaDNS(f"Timeout ao executar {argv[0]}") from exc
    return proc.stdout, proc.stderr, proc.returncode


def consultar(nome, tipo):
    """Consulta recursiva via ``dig +short`` no resolvedor local.

    Retorna a lista de valores (uma string por registro). ``tipo`` deve ser um
    tipo DNS conhecido (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR).
    """
    tipo = tipo.upper()
    # +time/+tries generosos: cada consulta sai pela cadeia DNSCrypt -> Tor,
    # cuja latência (RTT) varia bastante a cada circuito.
    argv = [
        "dig", "+short", "+time=9", "+tries=3",
        "-t", tipo, nome, f"@{RESOLVEDOR_LOCAL}",
    ]
    stdout, _stderr, _rc = _executar(argv)
    valores = []
    for linha in stdout.splitlines():
        linha = linha.strip()
        if linha and not linha.startswith(";"):
            valores.append(linha)
    return valores


def obter_ns(dominio):
    """Retorna a lista de hostnames de nameservers autoritativos do domínio."""
    servidores = []
    for valor in consultar(dominio, "NS"):
        servidores.append(valor.rstrip("."))
    # Remove duplicatas preservando ordem.
    vistos = set()
    unicos = []
    for s in servidores:
        if s not in vistos:
            vistos.add(s)
            unicos.append(s)
    return unicos


def resolver_ips(nome):
    """Resolve registros A e AAAA de ``nome``; retorna apenas IPs.

    ``dig +short A`` numa cadeia CNAME devolve também os nomes-alvo do CNAME;
    a filtragem por ``eh_ip_valido`` garante que só endereços IP sejam
    retornados.
    """
    ips = []
    for tipo in ("A", "AAAA"):
        try:
            valores = consultar(nome, tipo)
        except ErroFerramentaDNS:
            continue
        for valor in valores:
            if eh_ip_valido(valor) and valor not in ips:
                ips.append(valor)
    return ips


def resolvedor_pronto():
    """Verifica rapidamente se o dnscrypt-proxy local resolve nomes.

    Consulta curta (sem retries longos), adequada para um healthcheck. Retorna
    True se uma resposta com pelo menos um registro foi obtida.
    """
    argv = [
        "dig", "+short", "+time=4", "+tries=1",
        "-t", "A", "example.com", f"@{RESOLVEDOR_LOCAL}",
    ]
    try:
        stdout, _stderr, _rc = _executar(argv, timeout=8)
    except ErroFerramentaDNS:
        return False
    return any(
        linha.strip() and not linha.startswith(";")
        for linha in stdout.splitlines()
    )


def whois_dominio(dominio):
    """Executa ``whois`` no domínio e devolve a saída crua (texto).

    O comando é embrulhado com ``torsocks`` para que tanto a conexão TCP (porta
    43) quanto a resolução do hostname do servidor whois saiam pela rede Tor.

    Falha fechada: sem o torsocks, o whois NÃO é executado, pois uma consulta
    direta exporia o IP de egresso do contêiner ao servidor whois.
    """
    if not shutil.which("torsocks"):
        return (
            "[whois desativado: torsocks ausente, consulta direta bloqueada "
            "pela política de anonimato]"
        )
    argv = ["torsocks", "whois", dominio]
    try:
        # Cadeia de referência whois sobre Tor pode encadear conexões: 60 s.
        stdout, stderr, _rc = _executar(argv, timeout=60)
    except ErroFerramentaDNS as exc:
        return f"[whois indisponível: {exc}]"
    saida = stdout.strip()
    if not saida:
        return stderr.strip() or "[whois sem resposta]"
    return saida
