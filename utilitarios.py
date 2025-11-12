from collections import defaultdict

def organizar_registros(lista_registros, formatar_nome):
    registros_organizados = defaultdict(list)
    for linha in lista_registros:
        partes = linha.split('\t', 4)
        if len(partes) >= 5:
            nome, _, _, tipo, valor = partes
            registros_organizados[tipo].append((formatar_nome(nome), valor))
    return registros_organizados