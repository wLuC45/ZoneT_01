import sys
import dns.resolver
import dns.query
import dns.zone
from dns.exception import DNSException, Timeout
from collections import defaultdict

RESET = "\033[0m"
BOLD = "\033[1m"
VERDE = "\033[92m"
VERMELHO = "\033[91m"
AMARELO = "\033[93m"
AZUL = "\033[94m"
CINZA = "\033[90m"

def obter_servidores_nome_eficiente(dominio_alvo):
    lista_ns = []
    try:
        respostas = dns.resolver.resolve(dominio_alvo, 'NS')
        for rdata in respostas:
            servidor = rdata.target.to_text().rstrip('.')
            lista_ns.append(servidor)
        print(f"{VERDE}[OK]{RESET} {len(lista_ns)} nameservers encontrados para {dominio_alvo}")
        return lista_ns
    except DNSException as e:
        print(f"{VERMELHO}[ERRO]{RESET} Falha ao consultar {dominio_alvo}: {e}")
        return []

def tentar_transferencia_zona_eficiente(dominio, lista_ns):
    resultados_axfr = []
    for nameserver in lista_ns:
        print(f"{AZUL}[INFO]{RESET} Testando {nameserver}...")
        try:
            respostas_a = dns.resolver.resolve(nameserver, 'A')
            ip_nameserver = [rdata.to_text() for rdata in respostas_a][0]
            print(f"   IP: {ip_nameserver}")
        except DNSException:
            print(f"{AMARELO}[AVISO]{RESET} Falha ao resolver IP de {nameserver}")
            continue
        try:
            zona = dns.zone.from_xfr(dns.query.xfr(ip_nameserver, dominio, timeout=15))
            print(f"{VERDE}[OK]{RESET} Transferência bem-sucedida em {nameserver}")
            for (nome, rdataset) in zona.iterate_rdatasets():
                nome_completo = nome.to_text(omit_final_dot=True)
                for rdata in rdataset:
                    registro = f"{nome_completo}\t{rdataset.ttl}\tIN\t{rdata.rdtype.name}\t{rdata.to_text()}"
                    resultados_axfr.append(registro)
        except Timeout:
            print(f"{AMARELO}[TIMEOUT]{RESET} {nameserver}")
        except DNSException:
            print(f"{VERMELHO}[FALHA]{RESET} Transferência negada em {nameserver}")
    return resultados_axfr

def formatar_fqdn(nome_registro, dominio_alvo):
    return dominio_alvo if nome_registro == '@' else f"{nome_registro.rstrip('.')}.{dominio_alvo}"

def imprimir_tabela_organizada(resultado, alvo):
    if not resultado:
        print(f"{CINZA}[INFO]{RESET} Nenhum registro obtido.")
        return

    registros_organizados = defaultdict(list)
    for linha in resultado:
        partes = linha.split('\t', 4)
        if len(partes) >= 5:
            nome, _, _, tipo, valor = partes
            registros_organizados[tipo].append((formatar_fqdn(nome, alvo), valor))

    print(f"\n{BOLD}===> Registros DNS coletados ({alvo}) <==={RESET}")
    for tipo in sorted(registros_organizados):
        print(f"{AZUL}{tipo}:{RESET}")
        for nome, valor in registros_organizados[tipo]:
            print(f"  {VERDE}{nome}{RESET} → {valor}")
    print(f"{CINZA}Total: {sum(len(v) for v in registros_organizados.values())} registros.{RESET}")

def main():
    if len(sys.argv) < 2:
        print(f"{AMARELO}Uso:{RESET} python script.py <domínio>")
        sys.exit(1)

    alvo = sys.argv[1]
    print(f"{BOLD}{AZUL}===> DNS Zone Transfer Tester <==={RESET}")
    lista_ns = obter_servidores_nome_eficiente(alvo)
    if not lista_ns:
        print(f"{CINZA}Nenhum nameserver encontrado.{RESET}")
        return

    print(f"{AZUL}[INFO]{RESET} Tentando transferência de zona (AXFR)...")
    resultado = tentar_transferencia_zona_eficiente(alvo, lista_ns)
    imprimir_tabela_organizada(resultado, alvo)

if __name__ == "__main__":
    main()
