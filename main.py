import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from analisador_axfr import AnaliseTransferenciaZona
from terminal_colorido import *

def executar():
    if len(sys.argv) < 2:
        print(f"{Amarelo}Uso:{ResetCor} python main.py <domínio>")
        print(f"{Cinza}Exemplo:{ResetCor} python main.py exemplo.com")
        sys.exit(1)

    alvo = sys.argv[1]
    print(f"{Negrito}{Azul}===> ZoneT_01 - Diagnóstico de Transferência de Zona DNS <==={ResetCor}")
    
    analise = AnaliseTransferenciaZona(alvo)
    if analise.ColetarServidoresNome():
        print(f"{Azul}[INFO]{ResetCor} Iniciando tentativa de AXFR...")
        analise.ExecutarTentativasAXFR()
        analise.ExibirResultado()


if __name__ == "__main__":
    executar()
