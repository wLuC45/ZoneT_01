"""Varredura de portas TCP roteada pela rede Tor.

Faz um connect scan: cada porta é sondada abrindo uma conexão TCP através do
proxy SOCKS5 do Tor. O SOCKS5 só transporta TCP, então não há SYN scan nem
UDP; em compensação, o alvo nunca vê o IP do operador, apenas o nó de saída
do Tor.

Garantias de OPSEC:
  * O PySocks sempre conecta primeiro ao proxy; nunca há conexão direta. Se o
    Tor estiver fora do ar, a varredura falha fechada, sem vazar.
  * ``rdns=True`` faz a resolução de nome ocorrer no Tor (aqui o alvo já é um
    IP, então nem isso é necessário).
  * Com ``IsolateDestAddr``/``IsolateDestPort`` no Tor, cada porta sondada usa
    um circuito próprio: nenhum nó de saída observa a varredura inteira.
  * Lista de portas curada e enxuta, mantendo a varredura discreta e de baixo
    volume.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import socks  # PySocks
except ImportError:  # pragma: no cover - PySocks é dependência declarada
    socks = None

_PROXY_HOST = "127.0.0.1"
_PROXY_PORTA = 9050
_TIMEOUT = 12          # segundos por porta (a latência do Tor exige folga)
_MAX_PARALELO = 10

# Portas de serviços comuns, com rótulo, relevantes para recon de host.
_PORTAS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3000: "http-dev", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5601: "kibana", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9000: "http-app",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}


def disponivel():
    """True se a biblioteca de proxy SOCKS estiver presente."""
    return socks is not None


def _tor_acessivel():
    """Verificação rápida: a porta SOCKS do Tor está aberta?"""
    try:
        with socket.create_connection((_PROXY_HOST, _PROXY_PORTA), timeout=4):
            return True
    except OSError:
        return False


def _sondar(host, porta):
    """Sonda uma porta via SOCKS5 do Tor. Retorna (porta, estado).

    Estados: ``aberta``, ``fechada`` (recusada pelo destino) ou ``filtrada``
    (sem resposta, descartada ou bloqueada por política de saída do Tor).
    """
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, _PROXY_HOST, _PROXY_PORTA, rdns=True)
    s.settimeout(_TIMEOUT)
    try:
        s.connect((host, porta))
        return porta, "aberta"
    except socks.SOCKS5Error as exc:
        return porta, "fechada" if "refused" in str(exc).lower() else "filtrada"
    except (socket.timeout, OSError):
        return porta, "filtrada"
    finally:
        try:
            s.close()
        except OSError:
            pass


def varrer(host):
    """Varre as portas comuns de ``host`` (um IP) através do Tor.

    Retorna um dict; ``executada`` indica se a varredura ocorreu.
    """
    if not disponivel():
        return {"executada": False, "motivo": "biblioteca SOCKS indisponível"}
    if not _tor_acessivel():
        return {"executada": False, "motivo": "Tor indisponível na porta 9050"}

    abertas = []
    contagem = {"aberta": 0, "fechada": 0, "filtrada": 0}
    with ThreadPoolExecutor(max_workers=_MAX_PARALELO) as executor:
        futuros = {
            executor.submit(_sondar, host, porta): porta for porta in _PORTAS
        }
        for futuro in as_completed(futuros):
            porta, estado = futuro.result()
            contagem[estado] += 1
            if estado == "aberta":
                abertas.append({"porta": porta, "servico": _PORTAS[porta]})

    abertas.sort(key=lambda x: x["porta"])
    return {
        "executada": True,
        "host": host,
        "total": len(_PORTAS),
        "abertas": abertas,
        "fechadas": contagem["fechada"],
        "filtradas": contagem["filtrada"],
    }
