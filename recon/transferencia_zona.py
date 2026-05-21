"""Tentativa de transferência de zona (AXFR) — o teste de vulnerabilidade central.

O comando ``dig axfr`` é embrulhado com ``torsocks`` para que a conexão TCP ao
nameserver alvo saia pela rede Tor (o IP do contêiner nunca é exposto). AXFR é
inerentemente TCP, então o SOCKS5 do Tor (que só roteia TCP) é compatível;
``+tcp`` é passado explicitamente por garantia.

Estratégia de timeout adaptativo com retry exponencial: cada tentativa usa um
timeout maior. Distinguem-se três desfechos:
  * ``transferido``  — o servidor devolveu a zona completa (VULNERÁVEL).
  * ``negado``       — o servidor respondeu recusando (configuração correta).
  * ``inacessivel``  — sem resposta após todas as tentativas.
"""

import shutil
import subprocess

from .utilitarios import organizar_registros

# Timeouts (segundos) por tentativa — crescimento exponencial.
_TIMEOUTS_AXFR = [10, 20, 40]

# Teto de registros lidos de uma zona transferida. Limita o uso de memória
# diante de um nameserver hostil que devolva uma zona enorme.
_LIMITE_REGISTROS = 5000

# Sinais de falha de REDE: a conexão não chegou a um servidor DNS funcional.
# Devem ser distinguidos de uma recusa explícita, senão um problema de rede
# seria classificado como "negado" (risco BAIXO) por engano.
_SINAIS_FALHA_REDE = (
    "communications error",
    "connection refused",
    "connection timed out",
    "timed out",
    "network is unreachable",
    "network unreachable",
    "no route to host",
    "host unreachable",
    "no servers could be reached",
)

# Sinais de RECUSA pelo servidor: ele respondeu, mas negou a transferência.
_SINAIS_RECUSA = (
    "transfer failed",
    "notauth",
    "not authoritative",
    "rcode refused",
)


def _comando_disponivel(nome):
    return shutil.which(nome) is not None


def _montar_argv(dominio, ip_ns, timeout):
    """Monta o argv do dig AXFR sempre embrulhado em torsocks.

    A conexão de transferência de zona JAMAIS é feita diretamente: ou sai pela
    rede Tor via torsocks, ou não é feita. Ver ``tentar_axfr``, que recusa a
    execução quando o torsocks não está presente (falha fechada).
    """
    dig = [
        "dig", "axfr", dominio, f"@{ip_ns}",
        "+tcp", f"+time={timeout}", "+tries=1", "+nocomments", "+nostats",
    ]
    return ["torsocks"] + dig


def _parsear_zona(stdout, dominio):
    """Converte a saída do dig AXFR em linhas normalizadas e registros agrupados.

    Retorna ``(linhas, registros_agrupados)``. Cada linha segue o formato
    ``nome<TAB>ttl<TAB>IN<TAB>tipo<TAB>valor``.
    """
    linhas = []
    for bruta in stdout.splitlines():
        bruta = bruta.strip()
        if not bruta or bruta.startswith(";"):
            continue
        # dig AXFR usa espaços/tab variáveis: nome ttl classe tipo valor...
        campos = bruta.split(None, 4)
        if len(campos) < 5:
            continue
        nome, ttl, classe, tipo, valor = campos
        if classe.upper() != "IN":
            continue
        linhas.append(f"{nome.rstrip('.')}\t{ttl}\tIN\t{tipo}\t{valor}")
        if len(linhas) >= _LIMITE_REGISTROS:
            break  # bound de memória contra zonas exageradamente grandes

    def _formatar(nome):
        return nome or dominio

    return linhas, organizar_registros(linhas, _formatar)


def avaliar_saida(stdout, stderr, dominio):
    """Classifica a saída de uma única tentativa de ``dig axfr``.

    Retorna ``(parcial, linhas, registros)`` onde ``parcial`` é um de:
      * ``transferido`` — há registros além do SOA (zona real obtida).
      * ``negado``      — o servidor respondeu recusando a transferência.
      * ``falha_rede``  — a conexão não alcançou um servidor funcional.
      * ``indefinido``  — sem sinal conclusivo (deve-se tentar de novo).

    Função pura, sem efeitos colaterais, para permitir teste unitário.
    """
    saida = (stdout or "") + "\n" + (stderr or "")
    baixa = saida.lower()
    falha_rede = any(sinal in baixa for sinal in _SINAIS_FALHA_REDE)

    linhas, registros = _parsear_zona(stdout or "", dominio)
    # Um AXFR recusado costuma devolver apenas o SOA seguido de
    # "; Transfer failed."; registros além do SOA indicam uma zona real.
    # Divide cada linha uma única vez (evita split redundante).
    nao_soa = []
    for ln in linhas:
        campos = ln.split("\t")
        if len(campos) >= 4 and campos[3].upper() != "SOA":
            nao_soa.append(ln)
    if nao_soa:
        return "transferido", linhas, registros

    # "transfer failed" aparece tanto numa recusa quanto numa falha de rede;
    # só é recusa do servidor quando NÃO há sinal de falha de rede.
    recusa = any(sinal in baixa for sinal in _SINAIS_RECUSA) and not falha_rede
    if recusa:
        return "negado", [], {}
    if falha_rede:
        return "falha_rede", [], {}
    return "indefinido", [], {}


def tentar_axfr(dominio, ip_ns):
    """Tenta uma transferência de zona de ``dominio`` contra o IP ``ip_ns``.

    Retorna um dicionário com: ``desfecho`` (transferido|negado|inacessivel),
    ``mensagem``, ``linhas`` (registros crus) e ``registros`` (agrupados).
    Falhas de rede e respostas inconclusivas levam a nova tentativa com
    timeout maior; uma recusa explícita é definitiva.

    Falha fechada: sem o torsocks instalado, a transferência não é tentada,
    pois isso significaria conectar diretamente ao nameserver e expor o IP.
    """
    if not _comando_disponivel("torsocks"):
        return {
            "desfecho": "inacessivel",
            "mensagem": (
                "torsocks ausente: conexão direta bloqueada pela política "
                "de anonimato."
            ),
            "linhas": [],
            "registros": {},
        }

    ultimo_erro = ""
    for tentativa, timeout in enumerate(_TIMEOUTS_AXFR, start=1):
        argv = _montar_argv(dominio, ip_ns, timeout)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout + 15,  # margem sobre o timeout interno do dig
                check=False,
            )
        except subprocess.TimeoutExpired:
            ultimo_erro = f"timeout do processo (tentativa {tentativa})"
            continue
        except FileNotFoundError:
            return {
                "desfecho": "inacessivel",
                "mensagem": "dig não encontrado no sistema",
                "linhas": [],
                "registros": {},
            }

        parcial, linhas, registros = avaliar_saida(
            proc.stdout, proc.stderr, dominio
        )
        if parcial == "transferido":
            return {
                "desfecho": "transferido",
                "mensagem": f"Zona transferida ({len(linhas)} registros).",
                "linhas": linhas,
                "registros": registros,
            }
        if parcial == "negado":
            return {
                "desfecho": "negado",
                "mensagem": "Servidor recusou a transferência de zona.",
                "linhas": [],
                "registros": {},
            }
        ultimo_erro = (
            f"falha de rede (tentativa {tentativa})"
            if parcial == "falha_rede"
            else f"sem resposta útil (tentativa {tentativa})"
        )

    return {
        "desfecho": "inacessivel",
        "mensagem": f"Nameserver inacessível: {ultimo_erro}",
        "linhas": [],
        "registros": {},
    }
