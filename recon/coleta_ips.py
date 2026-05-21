"""Coletor de IPs com prioridade e deduplicação.

Durante uma recon, IPs aparecem em momentos diferentes (registros do domínio,
nameservers, zona transferida, subdomínios) e em quantidades distintas. Este
módulo concentra a lógica de:

* deduplicar IPs entre todas as fontes;
* preservar uma ordem de prioridade entre eles (IPs do domínio e dos NS antes
  dos IPs derivados da zona);
* filtrar valores que não sejam IPs válidos.

Manter essa responsabilidade num único objeto evita que a ordem e a
deduplicação se espalhem pelo orquestrador e simplifica o teste unitário.
"""

from .utilitarios import eh_ip_valido


class ColetorIPs:
    """Acumula IPs em dois grupos: prioritários e secundários.

    Os IPs do domínio raiz e dos nameservers entram como ``prioritarios``; os
    IPs vindos da zona transferida ou da enumeração de subdomínios entram como
    ``secundarios``. A geolocalização consome a lista combinada respeitando
    essa ordem, de modo que, mesmo com limite, os endereços relevantes são
    cobertos primeiro.
    """

    def __init__(self):
        self._prioritarios = []
        self._secundarios = []
        self._vistos = set()

    def adicionar_prioritario(self, ip):
        """Registra um IP como prioritário, se válido e ainda não conhecido."""
        self._inserir(self._prioritarios, ip)

    def adicionar_secundario(self, ip):
        """Registra um IP como secundário, se válido e ainda não conhecido."""
        self._inserir(self._secundarios, ip)

    def _inserir(self, alvo, ip):
        if not ip or not eh_ip_valido(ip):
            return
        if ip in self._vistos:
            return
        self._vistos.add(ip)
        alvo.append(ip)

    @property
    def prioritarios(self):
        """Lista (na ordem de inserção) dos IPs marcados como prioritários."""
        return list(self._prioritarios)

    def combinados(self, limite=None):
        """Devolve a lista completa, prioritários antes dos secundários.

        ``limite`` corta no comprimento informado, mantendo a prioridade.
        """
        combinado = self._prioritarios + self._secundarios
        if limite is None:
            return combinado
        return combinado[:limite]
