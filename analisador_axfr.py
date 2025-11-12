import dns.resolver
import dns.query
import dns.zone
from dns.exception import DNSException, Timeout
from terminal_colorido import *
from utilitarios import organizar_registros


class AnaliseTransferenciaZona:
    def __init__(self, DominioAlvo):
        self.DominioAlvo = DominioAlvo
        self.ListaServidores = []
        self.RegistrosObtidos = []

    def ColetarServidoresNome(self):
        try:
            respostas = dns.resolver.resolve(self.DominioAlvo, 'NS')
            self.ListaServidores = [rdata.target.to_text().rstrip('.') for rdata in respostas]
            print(f"{Verde}[OK]{ResetCor} {len(self.ListaServidores)} servidores NS encontrados.")
            return True
        except DNSException as e:
            print(f"{Vermelho}[ERRO]{ResetCor} Falha ao consultar {self.DominioAlvo}: {e}")
            return False

    def ExecutarTentativasAXFR(self):
        for Servidor in self.ListaServidores:
            print(f"{Azul}[INFO]{ResetCor} Testando {Servidor}...")

            try:
                resposta_a = dns.resolver.resolve(Servidor, 'A')
                EnderecoIP = [rdata.to_text() for rdata in resposta_a][0]
                print(f"  IP: {EnderecoIP}")
            except DNSException:
                print(f"{Amarelo}[AVISO]{ResetCor} Não foi possível resolver IP de {Servidor}")
                continue

            try:
                zona = dns.zone.from_xfr(dns.query.xfr(EnderecoIP, self.DominioAlvo, timeout=15))
                print(f"{Verde}[SUCESSO]{ResetCor} Transferência completa em {Servidor}")

                for (Nome, Conjunto) in zona.iterate_rdatasets():
                    NomeFinal = Nome.to_text(omit_final_dot=True)
                    for Registro in Conjunto:
                        linha = f"{NomeFinal}\t{Conjunto.ttl}\tIN\t{Registro.rdtype.name}\t{Registro.to_text()}"
                        self.RegistrosObtidos.append(linha)

            except Timeout:
                print(f"{Amarelo}[TIMEOUT]{ResetCor} {Servidor}")
            except DNSException:
                print(f"{Vermelho}[FALHA]{ResetCor} Transferência negada em {Servidor}")

    def _FormatarNomeFQDN(self, NomeRegistro):
        return self.DominioAlvo if NomeRegistro == '@' else f"{NomeRegistro.rstrip('.')}.{self.DominioAlvo}"

    def ExibirResultado(self):
        if not self.RegistrosObtidos:
            print(f"{Cinza}[INFO]{ResetCor} Nenhum dado obtido")
            return

        agrupados = organizar_registros(self.RegistrosObtidos, self._FormatarNomeFQDN)
        print(f"\n{Negrito}===> Registros DNS coletados ({self.DominioAlvo}) <==={ResetCor}")
        
        for tipo in sorted(agrupados):
            print(f"{Azul}{tipo}:{ResetCor}")
            for nome, valor in agrupados[tipo]:
                print(f"  {Verde}{nome}{ResetCor} → {valor}")
        
        total = sum(len(v) for v in agrupados.values())
        print(f"{Cinza}Total: {total} registros{ResetCor}")
