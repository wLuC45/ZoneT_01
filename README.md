# ZoneT_01

ZoneT_01 é uma ferramenta educacional e defensiva para testar se servidores DNS permitem transferências de zona (AXFR) sem autorização. Ela foi criada para ajudar administradores e estudantes a identificar configurações vulneráveis que podem expor a estrutura de um domínio.

## O que é a falha de transferência de zona - AXFR

A transferência de zona (AXFR) é um mecanismo legítimo do protocolo DNS usado para replicar completamente os dados de uma zona entre servidores autoritativos (por exemplo, de um master para um slave). Quando configurada corretamente, o servidor só aceita solicitações de transferência vindas de servidores autorizados. A falha ocorre quando um servidor responde a solicitações AXFR de qualquer origem, permitindo que um atacante obtenha todo o conteúdo da zona: registros, subdomínios, apontamentos internos, TTLs e outros detalhes que deveriam ficar restritos.

Essa exposição facilita o mapeamento da rede e pode revelar endereços internos, nomes de máquinas e serviços, tornando outras fases de um ataque (reconhecimento, phishing, movimentação lateral) muito mais simples.

## Como a ferramenta verifica e explora a falha

A proposta do ZoneT_01 é demonstrar de forma controlada e educativa como uma transferência de zona indevida se manifesta. O processo resumido que a ferramenta segue é:

1. **Consulta de NS**
   O ZoneT_01 pergunta ao DNS público do domínio quais são os servidores autoritativos (registros NS).

2. **Resolução dos nameservers**
   Para cada nameserver listado, resolve-se o registro A para obter o endereço IP do servidor que será testado.

3. **Tentativa de AXFR**
   A ferramenta envia uma solicitação de transferência de zona (AXFR) para o IP do nameserver, pedindo a zona completa do domínio alvo.

4. **Coleta e formatação**
   Se o servidor responde com sucesso, a ferramenta reúne os registros retornados (A, MX, TXT, CNAME, etc.) e os organiza para apresentação. Se a transferência for negada ou ocorrer timeout, a ferramenta informa isso na saída.

O objetivo não é explorar para dano, mas mostrar de forma prática que um servidor está indevidamente configurado. Quando a transferência é permitida, isso indica uma falha de configuração que requer correção do administrador do DNS.

## Uso básico

Instale a dependência principal:

```bash
pip install dnspython
```

Execute a ferramenta (exemplo):

```bash
python main.py exemplo.com
```

A saída informa os servidores NS encontrados, cada tentativa de AXFR e, se obtida, a listagem dos registros coletados.

