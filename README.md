<p align="center">
  <img src="app/static/logo.svg" alt="ZoneT_01" width="440">
</p>

<h1 align="center">ZoneT_01</h1>

<p align="center">
  Ferramenta de reconhecimento DNS com foco na deteção de transferências de
  zona (AXFR) não autorizadas, encapsulada num contêiner Alpine que força
  toda a saída de rede pela cadeia DNSCrypt mais Tor.
</p>

<p align="center">
  <em>Uso educacional, defensivo e em testes de segurança autorizados.</em>
</p>

---

## Sumário

1. [Visão geral](#visão-geral)
2. [A falha de transferência de zona](#a-falha-de-transferência-de-zona)
3. [Como o ZoneT_01 funciona](#como-o-zonet_01-funciona)
4. [Arquitetura da pilha](#arquitetura-da-pilha)
5. [Estrutura do repositório](#estrutura-do-repositório)
6. [Requisitos](#requisitos)
7. [Execução](#execução)
8. [Interface web](#interface-web)
9. [Modo de linha de comando](#modo-de-linha-de-comando)
10. [Endpoints HTTP](#endpoints-http)
11. [Configuração e variáveis de ambiente](#configuração-e-variáveis-de-ambiente)
12. [Verificação da pilha](#verificação-da-pilha)
13. [Postura de OPSEC](#postura-de-opsec)
14. [Modelagem de risco](#modelagem-de-risco)
15. [Segurança e isolamento do contêiner](#segurança-e-isolamento-do-contêiner)
16. [Notas técnicas](#notas-técnicas)
17. [Limitações conhecidas](#limitações-conhecidas)
18. [Aviso legal](#aviso-legal)
19. [Licença](#licença)

---

## Visão geral

ZoneT_01 é uma ferramenta de diagnóstico que verifica se servidores DNS aceitam
transferências de zona (AXFR) a partir de origens não autorizadas. A ferramenta
roda inteiramente dentro de um contêiner Alpine Linux e direciona todo o
tráfego de saída por uma cadeia de anonimização composta por DNSCrypt e Tor,
de modo que o endereço do operador não seja exposto ao resolvedor recursivo
nem ao servidor alvo.

A intenção é apoiar inspeções defensivas e exercícios de segurança autorizados.
Execute o ZoneT_01 apenas contra domínios para os quais você possua autorização
explícita.

## A falha de transferência de zona

A transferência de zona é um mecanismo legítimo do protocolo DNS, usado para
replicar uma zona completa entre servidores autoritativos (do servidor primário
para os secundários). Quando configurada de forma adequada, a transferência só
ocorre a partir de endereços previamente autorizados, frequentemente reforçada
por chaves TSIG.

A falha aparece quando um servidor autoritativo responde a uma solicitação
AXFR vinda de qualquer origem. Em tal cenário, qualquer interessado obtém o
conteúdo completo da zona: subdomínios, registros internos, TTLs e
apontamentos que deveriam permanecer restritos. Esse vazamento facilita o
mapeamento da infraestrutura por um atacante e tipicamente indica um erro de
configuração que o administrador do DNS precisa corrigir.

## Como o ZoneT_01 funciona

Para um alvo informado, a ferramenta percorre as etapas a seguir:

1. **Validação do alvo.** A entrada do usuário passa por uma validação estrita
   antes de qualquer chamada externa, defendendo a borda contra injeção em
   comandos auxiliares.
2. **Coleta de nameservers.** Resolve os registros NS do domínio, identificando
   os servidores autoritativos.
3. **Registros públicos.** Resolve em paralelo os registros do ápice da zona
   (A, AAAA, MX, TXT, SOA).
4. **Tentativa de AXFR.** Cada nameserver é processado em paralelo: o IP é
   resolvido e a tentativa de transferência é executada com timeout adaptativo
   e novas tentativas em intervalos crescentes. As conexões são embrulhadas
   com torsocks para que saiam pela rede Tor.
5. **Enumeração de subdomínios.** Aplica força bruta com uma lista curada,
   precedida de deteção de DNS curinga para evitar uma cascata de falsos
   positivos.
6. **Postura DNS e e-mail.** Avalia SPF, DMARC, DNSSEC e CAA com consultas
   paralelas.
7. **Whois.** Faz uma consulta WHOIS encapsulada por torsocks.
8. **Geolocalização opcional.** Quando explicitamente ativada, enriquece os
   endereços IP com país, cidade, ISP e ASN (ver [Postura de OPSEC](#postura-de-opsec)).
9. **Varredura de portas opcional.** Quando solicitada, executa um connect
   scan TCP do host alvo por SOCKS5 do Tor, com isolamento de circuito por
   destino e lista de portas curada.
10. **Classificação de risco.** Calcula um nível geral (CRITICO, BAIXO ou
    INDETERMINADO) acompanhado de uma pontuação contínua entre 0 e 100.

Quando o alvo é um host que não está no ápice de uma zona (por exemplo
`www.exemplo.com`), o caminho de AXFR não se aplica e a ferramenta executa o
reconhecimento de host apenas: registros, varredura de portas, geolocalização
e whois.

## Arquitetura da pilha

```
navegador
   |
   v  HTTP 5000 (somente 127.0.0.1)
Gunicorn (1 worker, 8 threads)
   |
   v  motor de recon (dig, whois, varredura de portas)
   +----------------+---------------------+
   |                |                     |
   v UDP/53         v TCP via torsocks    v SOCKS5 TCP
127.0.0.1:53     dig axfr + whois       portas
dnscrypt-proxy        |                     |
   |                  v                     v
   |          127.0.0.1:9050 (Tor SOCKS) <--+
   v
DNS anonimizado --> Tor --> internet
```

Todas as resoluções recursivas saem por DNSCrypt encaminhado pelo SOCKS do Tor.
Conexões TCP de AXFR e whois passam por torsocks. A varredura de portas usa
PySocks contra o mesmo SOCKS local. Não há nenhum caminho de código que se
conecte fora do Tor.

## Estrutura do repositório

| Caminho                              | Conteúdo                                                                 |
|--------------------------------------|--------------------------------------------------------------------------|
| `app/`                               | Camada web Flask e Gunicorn, fila de jobs em memória, rotas e estáticos. |
| `app/static/logo.svg`                | Logo do projeto.                                                         |
| `recon/`                             | Motor de reconhecimento, em módulos independentes (ver tabela abaixo).   |
| `infra/`                             | `torrc`, `dnscrypt-proxy.toml`, `entrypoint.sh`, cache do DNSCrypt.      |
| `scripts/`                           | CLI de AXFR, renovação de circuito, verificação da pilha e cache.        |
| `Containerfile` / `docker-compose.yml` | Empacotamento do contêiner.                                              |
| `run.sh`                             | Script utilitário para build e execução com podman ou docker.            |

Os módulos do motor de recon são:

| Módulo                          | Responsabilidade                                              |
|---------------------------------|---------------------------------------------------------------|
| `recon/motor_recon.py`          | Orquestrador: encadeia os estágios e relata progresso.        |
| `recon/transferencia_zona.py`   | Executa e classifica a tentativa de AXFR.                     |
| `recon/processador_ns.py`       | Processa um nameserver (resolução de IP mais AXFR).           |
| `recon/recon_host.py`           | Fluxos para host sem zona e para alvo IP sem PTR.             |
| `recon/coleta_ips.py`           | Acumula IPs com prioridade e deduplicação.                    |
| `recon/subdominios.py`          | Força bruta de subdomínios com deteção de curinga.            |
| `recon/postura_dns.py`          | Avalia SPF, DMARC, DNSSEC e CAA.                              |
| `recon/varredura_portas.py`     | Connect scan TCP por SOCKS5 do Tor.                           |
| `recon/geolocalizacao.py`       | Enriquecimento opt-in com geolocalização e ASN.               |
| `recon/classificacao_risco.py`  | Computa nível e pontuação de risco.                           |
| `recon/ferramentas_dns.py`      | Wrappers de subprocesso para `dig`, `whois` e o resolvedor.   |
| `recon/utilitarios.py`          | Validação de alvo, classificação de IPs e parsing comum.      |

## Requisitos

* Podman ou Docker no host.
* O restante (Tor, dnscrypt-proxy, bind-tools, whois, torsocks, Python e
  bibliotecas) é instalado dentro da imagem durante o build.

## Execução

Construir e iniciar o contêiner:

```
./run.sh            # usa podman (padrão)
./run.sh docker     # usa docker
```

O bootstrap do Tor leva de trinta a sessenta segundos. Acompanhe a prontidão
pelo endpoint `/readyz`:

```
curl -s http://localhost:5000/readyz
```

Quando `/readyz` retornar `status: ok`, abra `http://localhost:5000` no
navegador, informe um domínio e acompanhe o progresso. Uma varredura completa
costuma levar de trinta a noventa segundos por causa da latência do Tor.

Alternativa via docker-compose:

```
docker compose up -d --build
```

## Interface web

A interface é um painel em tema escuro, sem nenhuma dependência externa
(fontes locais, sem CDN, sem analytics, sem Content Delivery alheio). A página
exibe, do topo para a base:

* a logo do projeto e a marca textual;
* tiles de status para Tor, DNSCrypt, total de scans e críticos da sessão;
* um carrossel de cartões com a pilha de anonimização, estatísticas da
  sessão, lembretes de OPSEC e uma nota explicativa sobre AXFR;
* o formulário de scan, com a opção de varredura de portas via Tor;
* a área de resultados, com diagnóstico, AXFR por nameserver, registros
  obtidos numa transferência bem-sucedida, subdomínios, postura DNS e
  e-mail, portas, registros públicos, geolocalização e whois;
* o histórico de scans da sessão, com retomada por clique e exportação JSON
  no botão correspondente.

A página vem com Content-Security-Policy restritiva, X-Frame-Options DENY,
Referrer-Policy `no-referrer`, X-Content-Type-Options `nosniff` e
Cache-Control `no-store`. O front-end nunca solicita recursos fora da própria
origem, evitando qualquer requisição que escapasse do Tor.

## Modo de linha de comando

Para usar a versão CLI, sem a interface web:

```
podman exec zonet01 sh /opt/zonet/scripts/recon_axfr.sh exemplo.com
```

O script faz a coleta de nameservers, tenta o AXFR contra cada um deles via
torsocks e imprime o resultado em texto plano. Útil para diagnóstico rápido
ou pipelines.

## Endpoints HTTP

| Método | Caminho                | Função                                                                      |
|--------|------------------------|-----------------------------------------------------------------------------|
| GET    | `/`                    | Página única da interface.                                                  |
| GET    | `/healthz`             | Liveness probe (apenas confirma que o processo web responde).               |
| GET    | `/readyz`              | Readiness probe (confirma que o resolvedor local responde).                 |
| POST   | `/scan`                | Cria um job de scan. Corpo: `{"alvo": "...", "portas": false}`.             |
| GET    | `/status/<job_id>`     | Estado atual de um job; aceita polling por AJAX.                            |
| GET    | `/pilha`               | Estado da pilha (Tor, DNSCrypt) e estatísticas da sessão.                   |
| GET    | `/historico`           | Lista resumida dos scans recentes da sessão.                                |

Todas as respostas trazem os cabeçalhos de segurança descritos acima.

## Configuração e variáveis de ambiente

| Variável              | Padrão  | Efeito                                                                 |
|-----------------------|---------|------------------------------------------------------------------------|
| `ZONET_GEOIP_API`     | (vazio) | Quando definido como `1`, `true`, `sim`, `on` ou `yes`, ativa a consulta de geolocalização externa via Tor. |
| `ZONET_BRIDGES`       | (vazio) | Caminho de um arquivo de bridges. Quando definido, o `run.sh` monta o arquivo em `/etc/tor/bridges.conf` e o Tor passa a usar bridges. |

Exemplos:

```
ZONET_GEOIP_API=1 ./run.sh
ZONET_BRIDGES=./bridges.conf ./run.sh
```

## Verificação da pilha

Teste de fumaça da pilha de anonimização, executado dentro do contêiner:

```
podman exec zonet01 sh /opt/zonet/scripts/verificar_pilha.sh
```

O teste de fumaça confirma que o Tor está ativo, que o dnscrypt-proxy resolve
nomes, que o tráfego sai pela rede Tor, que o `resolv.conf` não vaza, que a
camada web responde e que o caminho de AXFR funciona de ponta a ponta.

Para validar a deteção, o domínio público `zonetransfer.me` é mantido
propositalmente vulnerável e deve resultar em **CRITICO**. Um domínio com
configuração correta, como `google.com`, deve resultar em **BAIXO**.

## Postura de OPSEC

O objetivo é que o operador não seja identificável. As medidas a seguir
tratam disso de forma direta.

**Falha fechada.** As ferramentas que se conectam à rede (transferência de
zona e whois) só são executadas através do torsocks. Se o torsocks estiver
ausente, a operação é recusada em vez de cair para uma conexão direta. A
varredura de portas usa um socket SOCKS5 que conecta sempre primeiro ao proxy
do Tor; se o Tor estiver fora do ar, a varredura nem começa. Não existe
caminho de código que conecte fora do Tor.

**Varredura de portas anônima.** O connect scan opcional sai pela rede Tor:
o alvo enxerga apenas nós de saída do Tor, jamais o IP do operador. Com o
isolamento de circuitos por destino, cada porta sondada usa um circuito
próprio, de modo que nenhum nó de saída observa a varredura inteira. A lista
de portas é curada e enxuta, mantendo a varredura discreta.

**Sem rastro em disco.** O contêiner roda com `--log-driver none`, então a
saída dos daemons não é gravada no armazenamento de logs do host. O log de
acesso do Gunicorn é descartado, o registro de consultas do dnscrypt-proxy é
mantido desligado e o Tor registra apenas avisos. Com `--rm`, o contêiner é
removido por completo ao parar. Todo o estado de execução vive em tmpfs
volátil.

**Esconder o uso do Tor.** Por padrão o Tor usa guardas públicos, o que
revela a um observador da rede do operador a existência de tráfego Tor. Para
ocultar esse fato, forneça um arquivo de bridges (ver
`infra/tor/bridges.exemplo.conf`): bridges vanilla evitam os guardas
conhecidos e bridges obfs4 disfarçam o tráfego como dados genéricos.

**Isolamento de circuitos.** A porta SOCKS do Tor usa `IsolateDestAddr` e
`IsolateDestPort`. Destinos diferentes recebem circuitos diferentes,
dificultando a correlação entre alvos distintos.

**DNS sem fetch em tempo de execução.** As listas de resolvers e relays ficam
embutidas na imagem; o `refresh_delay` é de um ano, eliminando qualquer busca
HTTP no arranque que pudesse escapar do Tor. A atualização dessas listas é
feita fora do tempo de execução, com `scripts/atualizar_cache_dnscrypt.sh`,
seguida de um rebuild da imagem.

**Geolocalização opcional.** A consulta de geolocalização a um serviço
externo fica desativada por padrão. Mesmo saindo pela rede Tor, ela revelaria
ao serviço e ao nó de saída quais endereços estão sendo investigados. O
operador ativa essa consulta de forma consciente com `ZONET_GEOIP_API=1`.
Quando ativa, a requisição ignora variáveis de proxy do ambiente, ignora o
`.netrc`, usa User-Agent neutro e não segue redirecionamentos.

**Interface contida.** A página web não carrega nenhum recurso externo e
responde com Content-Security-Policy restritiva, que impede o navegador do
operador de contatar qualquer host fora da origem local.

## Modelagem de risco

A classificação devolve quatro campos: `nivel`, `pontuacao`, `motivos` e
`recomendacoes`.

**Níveis.**

* `CRITICO`: ao menos um nameserver entregou a zona.
* `BAIXO`: todos os nameservers responderam recusando a transferência.
* `INDETERMINADO`: nenhum nameserver foi identificado, ou parte deles ficou
  inacessível, impedindo conclusão segura.

**Pontuação.** A pontuação é uma função contínua entre 0 e 100, definida em
faixas por nível. Para o nível CRITICO, parte de 90 e acrescenta até 10
unidades segundo uma curva de saturação `1 - exp(-x)` aplicada à exposição:

* registros expostos contam linearmente;
* registros que sugerem infraestrutura interna (nomes como `vpn`, `admin`,
  `backup`, ou IPs em faixas privadas) pesam quatro vezes mais;
* a curva traz retornos decrescentes; as primeiras dezenas de registros
  elevam muito a pontuação e centenas adicionais quase não mudam o teto.

Para o nível BAIXO, mais nameservers confirmando a recusa reduzem a
pontuação residual, com piso de 5. Para o INDETERMINADO, a pontuação parte
de 40 e cresce com a fração de nameservers inacessíveis.

## Segurança e isolamento do contêiner

O contêiner roda com o sistema de arquivos raiz em modo somente leitura.
Todos os caminhos graváveis (dados do Tor, cache do dnscrypt-proxy, logs e
`/tmp`) são montados como tmpfs; nada persiste em disco e todo o estado é
volátil.

As capabilities do Linux são removidas com `--cap-drop ALL`. Apenas
`NET_BIND_SERVICE` é adicionada de volta, pois o dnscrypt-proxy precisa
escutar na porta 53. A flag `--security-opt no-new-privileges` impede
escalonamento por binários setuid. Os daemons rodam como root dentro do
contêiner, o que não tem efeito prático já que não há capabilities e o
sistema de arquivos é somente leitura.

A porta 5000 é publicada apenas em `127.0.0.1` no host. A rede usada é a
bridge padrão (a rede `none` é incompatível com a publicação de portas e
impediria o Tor de alcançar a internet). A proteção contra vazamento de DNS
vem da configuração: `--dns=127.0.0.1` faz o contêiner usar exclusivamente o
dnscrypt-proxy interno, que só envia tráfego para fora através do Tor.

## Notas técnicas

* O dnscrypt-proxy usa `force_tcp = true` porque um proxy SOCKS transporta
  apenas TCP; sem essa opção, as consultas seriam tentadas em UDP e o caminho
  pelo proxy falharia em silêncio.
* O torsocks não roteia UDP. Por isso somente as conexões TCP (AXFR e whois)
  são embrulhadas com ele. As consultas recursivas são enviadas ao
  dnscrypt-proxy local, que cuida da saída pela rede Tor.
* As listas de resolvers e relays do dnscrypt-proxy ficam embutidas na
  imagem, em `infra/dnscrypt/cache`. Rode `scripts/atualizar_cache_dnscrypt.sh`
  periodicamente para baixar versões novas, revise o diff, recommite e
  reconstrua a imagem. A integridade das listas é assegurada pela assinatura
  minisign, validada pelo dnscrypt-proxy.
* O Gunicorn roda com um único worker e oito threads, premissa que a fila de
  jobs em memória depende; mais de um worker quebraria o compartilhamento de
  estado entre `/scan` e `/status`.
* O gerenciador de jobs tem um reaper periódico em thread daemon que descarta
  jobs antigos a cada cinco minutos, complementando a expiração disparada na
  criação de novos jobs.
* Se o pacote dnscrypt-proxy não existir na versão do Alpine utilizada, é
  possível substituí-lo pelo binário estático oficial publicado em
  `https://github.com/DNSCrypt/dnscrypt-proxy/releases`, compatível com musl.

## Limitações conhecidas

* A correlação de tráfego ponta a ponta é um limite inerente ao Tor. Um
  adversário que observe ao mesmo tempo a rede do operador e a rede do alvo
  pode, em tese, correlacionar os tempos. As bridges reduzem a exposição do
  lado do operador, mas não eliminam esse modelo de ameaça.
* Quando a geolocalização externa é ativada, a consulta usa a API ip-api.com,
  que só responde em HTTP no plano gratuito. A identidade do operador
  permanece protegida pelo Tor, mas o nó de saída e o serviço enxergam quais
  IPs estão sendo consultados. Para também ocultar isso, use um serviço com
  HTTPS ou bancos GeoIP2 locais em formato mmdb. Por essa razão a
  geolocalização é opt-in.
* Os daemons internos são iniciados em ordem pelo entrypoint, que depois
  entra num laço de supervisão: se o Tor ou o dnscrypt-proxy encerrar, são
  reiniciados; se o Gunicorn cair, o contêiner é finalizado para o
  orquestrador tratar. Durante o reinício do Tor há uma janela curta em que
  os scans falham; o endpoint `/readyz` permite detetar esse estado e o
  healthcheck do `docker-compose` o utiliza.
* A imagem parte de `alpine:3.21`, uma tag que recebe atualizações. Para
  builds totalmente reproduzíveis, fixe a imagem base por digest no
  `Containerfile`.
* A aplicação não impõe limite de requisições. Como a porta 5000 é publicada
  apenas em `127.0.0.1`, a superfície fica restrita ao host local.

## Aviso legal

Utilize o ZoneT_01 somente contra ativos para os quais você possui autorização
explícita e por escrito. Reconhecimento contra terceiros sem permissão pode
violar leis locais, contratos de serviço e políticas de uso aceitável dos
provedores envolvidos. A responsabilidade pelo uso é integralmente do
operador.

## Licença

Distribuído sob a licença incluída em `LICENSE`.
