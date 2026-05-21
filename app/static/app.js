"use strict";

// ZoneT_01 — dashboard: tiles de status, carrossel hero (fade), scan via
// polling AJAX, histórico e exportação local.

const INTERVALO_POLL = 1500;    // ms entre consultas de status de um scan
const INTERVALO_PILHA = 20000;  // ms entre atualizações de pilha/sessão
const INTERVALO_CARROSSEL = 8000;

let ultimoResultado = null;

function $(id) { return document.getElementById(id); }

function escapar(t) {
  const d = document.createElement("div");
  d.textContent = t == null ? "" : String(t);
  return d.innerHTML;
}

/* ------------------------------------------------------------------ */
/* Carrossel hero (transição por fade)                                */
/* ------------------------------------------------------------------ */
const slides = Array.from(document.querySelectorAll(".slide"));
let slideAtual = 0;
let timerCarrossel = null;

function mostrarSlide(indice) {
  slideAtual = (indice + slides.length) % slides.length;
  slides.forEach((s, i) => s.classList.toggle("ativo", i === slideAtual));
  document.querySelectorAll(".ponto").forEach((p, i) => {
    p.classList.toggle("ativo", i === slideAtual);
  });
}

function reiniciarTimerCarrossel() {
  clearInterval(timerCarrossel);
  timerCarrossel = setInterval(
    () => mostrarSlide(slideAtual + 1), INTERVALO_CARROSSEL
  );
}

function montarCarrossel() {
  const pontos = $("car-pontos");
  slides.forEach((_, i) => {
    const b = document.createElement("button");
    b.className = "ponto";
    b.setAttribute("aria-label", "cartão " + (i + 1));
    b.addEventListener("click", () => {
      mostrarSlide(i);
      reiniciarTimerCarrossel();
    });
    pontos.appendChild(b);
  });
  const car = $("carrossel");
  car.addEventListener("mouseenter", () => clearInterval(timerCarrossel));
  car.addEventListener("mouseleave", reiniciarTimerCarrossel);
  mostrarSlide(0);
  reiniciarTimerCarrossel();
}

/* ------------------------------------------------------------------ */
/* Tiles de status, pilha e sessão                                    */
/* ------------------------------------------------------------------ */
function aplicarEstado(elemento, ativo, rotuloAtivo, rotuloInativo) {
  elemento.textContent = ativo ? rotuloAtivo : rotuloInativo;
  elemento.className = "tile-valor " + (ativo ? "sim" : "nao");
}

async function atualizarPilha() {
  let d;
  try {
    d = await (await fetch("/pilha")).json();
  } catch (e) {
    return;
  }
  const tor = !!d.tor, dns = !!d.dnscrypt;

  // Tiles de status
  aplicarEstado($("t-tor"), tor, "ativo", "inativo");
  aplicarEstado($("t-dns"), dns, "ativo", "inativo");
  $("tile-tor").className = "tile " + (tor ? "ok" : "falha");
  $("tile-dns").className = "tile " + (dns ? "ok" : "falha");

  const s = d.sessao || {};
  const niv = s.por_nivel || {};
  $("t-scans").textContent = s.total || 0;
  const criticos = niv.CRITICO || 0;
  const tc = $("t-criticos");
  tc.textContent = criticos;
  tc.className = "tile-valor " + (criticos > 0 ? "alerta" : "neutro");

  // Cartões do carrossel
  const plTor = $("pl-tor"), plDns = $("pl-dns");
  plTor.textContent = tor ? "ativo" : "inativo";
  plTor.className = tor ? "sim" : "nao";
  plDns.textContent = dns ? "ativo" : "inativo";
  plDns.className = dns ? "sim" : "nao";
  $("ss-total").textContent = s.total || 0;
  $("ss-ativos").textContent = s.ativos || 0;
  $("ss-niveis").textContent = criticos + " / " + (niv.BAIXO || 0);
}

/* ------------------------------------------------------------------ */
/* Histórico                                                          */
/* ------------------------------------------------------------------ */
async function atualizarHistorico() {
  let d;
  try {
    d = await (await fetch("/historico")).json();
  } catch (e) {
    return;
  }
  const ul = $("historico");
  ul.innerHTML = "";
  const jobs = d.jobs || [];
  if (!jobs.length) {
    const li = document.createElement("li");
    li.className = "vazio-hist";
    li.textContent = "sem scans nesta sessão";
    ul.appendChild(li);
    return;
  }
  for (const j of jobs) {
    const li = document.createElement("li");
    li.innerHTML =
      '<span class="h-alvo">' + escapar(j.alvo) + "</span>" +
      '<span class="h-meta">' + escapar(j.nivel || j.estado) + "</span>";
    li.addEventListener("click", () => carregarJob(j.id));
    ul.appendChild(li);
  }
}

async function carregarJob(jobId) {
  try {
    const s = await (await fetch("/status/" + jobId)).json();
    if (s.estado === "concluido" && s.resultado) {
      renderizarResultado(s.resultado);
    } else if (s.estado === "erro") {
      mostrarErro(s.erro || "scan terminou com erro");
    }
  } catch (e) {
    mostrarErro("falha ao carregar o scan");
  }
}

/* ------------------------------------------------------------------ */
/* Scan                                                               */
/* ------------------------------------------------------------------ */
function mostrarErro(t) {
  const m = $("mensagem-erro");
  m.textContent = t;
  m.classList.remove("oculto");
}
function limparErro() {
  $("mensagem-erro").classList.add("oculto");
}

$("formulario").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  limparErro();
  const alvo = $("alvo").value.trim();
  if (!alvo) return;
  $("botao").disabled = true;
  $("painel-resultado").classList.add("oculto");
  $("resultado-vazio").classList.add("oculto");
  $("painel-progresso").classList.remove("oculto");
  $("barra").style.width = "0%";
  $("etapa-atual").textContent = "enviando...";

  try {
    const r = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alvo, portas: $("opt-portas").checked }),
    });
    const d = await r.json();
    if (!r.ok) {
      mostrarErro(d.erro || "falha ao iniciar o scan");
      $("painel-progresso").classList.add("oculto");
      $("resultado-vazio").classList.remove("oculto");
      $("botao").disabled = false;
      return;
    }
    acompanhar(d.job_id);
  } catch (e) {
    mostrarErro("erro de rede ao contatar o servidor");
    $("painel-progresso").classList.add("oculto");
    $("resultado-vazio").classList.remove("oculto");
    $("botao").disabled = false;
  }
});

function acompanhar(jobId) {
  const iv = setInterval(async () => {
    let s;
    try {
      const r = await fetch("/status/" + jobId);
      s = await r.json();
      if (!r.ok) {
        clearInterval(iv);
        mostrarErro(s.erro || "job não encontrado");
        $("botao").disabled = false;
        return;
      }
    } catch (e) {
      return;
    }
    $("barra").style.width = s.progresso + "%";
    $("etapa-atual").textContent = s.etapa_atual || "";
    if (s.estado === "concluido" || s.estado === "erro") {
      clearInterval(iv);
      $("botao").disabled = false;
      $("painel-progresso").classList.add("oculto");
      if (s.estado === "erro") {
        mostrarErro(s.erro || "o scan terminou com erro");
        $("resultado-vazio").classList.remove("oculto");
      } else {
        renderizarResultado(s.resultado);
      }
      atualizarHistorico();
      atualizarPilha();
    }
  }, INTERVALO_POLL);
}

/* ------------------------------------------------------------------ */
/* Renderização do resultado                                          */
/* ------------------------------------------------------------------ */
function renderizarResultado(r) {
  if (!r) return;
  ultimoResultado = r;
  $("resultado-vazio").classList.add("oculto");
  $("painel-resultado").classList.remove("oculto");

  const risco = r.risco || {};
  const nivel = risco.nivel || "INDETERMINADO";
  const badge = $("badge-risco");
  badge.className = "badge " + nivel;
  badge.textContent = nivel + (risco.pontuacao != null ? " " + risco.pontuacao : "");
  $("resultado-alvo").textContent = r.alvo || "";

  let h = "";
  if (r.erro) h += '<p class="erro">' + escapar(r.erro) + "</p>";

  if (risco.motivos && risco.motivos.length) {
    h += '<div class="bloco"><h3>diagnóstico</h3><ul class="lista">';
    for (const m of risco.motivos) h += "<li>" + escapar(m) + "</li>";
    h += "</ul>";
    if (risco.recomendacoes && risco.recomendacoes.length) {
      h += '<ul class="lista">';
      for (const rec of risco.recomendacoes) {
        h += "<li>&rarr; " + escapar(rec) + "</li>";
      }
      h += "</ul>";
    }
    h += "</div>";
  }

  if (r.axfr && r.axfr.length) {
    h += '<div class="bloco"><h3>nameservers e AXFR</h3><table>' +
         "<tr><th>nameserver</th><th>IP</th><th>AXFR</th><th>detalhe</th></tr>";
    for (const a of r.axfr) {
      h += "<tr><td>" + escapar(a.servidor) + "</td><td>" +
           escapar(a.ip || "-") + '</td><td class="tag tag-' +
           escapar(a.desfecho) + '">' + escapar(a.desfecho) + "</td><td>" +
           escapar(a.mensagem) + "</td></tr>";
    }
    h += "</table></div>";
  }

  const reg = fundirRegistros(r.axfr);
  const tipos = Object.keys(reg).sort();
  if (tipos.length) {
    h += '<div class="bloco"><h3>registros obtidos na transferência</h3>';
    for (const t of tipos) {
      h += "<details><summary>" + escapar(t) + " (" + reg[t].length +
           ")</summary><table>";
      for (const [nome, valor] of reg[t]) {
        h += "<tr><td><code>" + escapar(nome) + "</code></td><td>" +
             escapar(valor) + "</td></tr>";
      }
      h += "</table></details>";
    }
    h += "</div>";
  }

  if (r.subdominios) {
    h += '<div class="bloco"><h3>subdomínios</h3>';
    if (r.subdominios.wildcard) {
      h += '<p class="texto">DNS curinga detectado; a enumeração por força ' +
           "bruta não é confiável neste domínio.</p>";
    } else {
      const enc = r.subdominios.encontrados || [];
      if (!enc.length) {
        h += '<p class="texto">nenhum subdomínio da lista respondeu.</p>';
      } else {
        h += "<table><tr><th>subdomínio</th><th>IPs</th></tr>";
        for (const e of enc) {
          h += "<tr><td><code>" + escapar(e.fqdn) + "</code></td><td>" +
               escapar((e.ips || []).join(", ")) + "</td></tr>";
        }
        h += "</table>";
      }
    }
    h += "</div>";
  }

  if (r.postura && Object.keys(r.postura).length) {
    const p = r.postura;
    const simNao = (v) => v
      ? '<span class="sim">sim</span>' : '<span class="nao">não</span>';
    h += '<div class="bloco"><h3>postura de DNS e e-mail</h3><table>';
    if (p.spf) {
      h += "<tr><td>SPF</td><td>" + simNao(p.spf.presente) + "</td><td>" +
           escapar(p.spf.resumo || "") + "</td></tr>";
    }
    if (p.dmarc) {
      h += "<tr><td>DMARC</td><td>" + simNao(p.dmarc.presente) +
           "</td><td>política: " + escapar(p.dmarc.politica || "-") +
           "</td></tr>";
    }
    if (p.dnssec) {
      h += "<tr><td>DNSSEC</td><td>" + simNao(p.dnssec.presente) +
           "</td><td>DS: " + escapar(p.dnssec.ds || 0) + " / DNSKEY: " +
           escapar(p.dnssec.dnskey || 0) + "</td></tr>";
    }
    if (p.caa) {
      h += "<tr><td>CAA</td><td>" + simNao(p.caa.presente) + "</td><td>" +
           escapar((p.caa.registros || []).join("; ")) + "</td></tr>";
    }
    h += "</table></div>";
  }

  // Varredura de portas via Tor
  if (r.portas && r.portas.executada) {
    const p = r.portas;
    const nAbertas = (p.abertas || []).length;
    h += '<div class="bloco"><h3>portas abertas (varredura via Tor)</h3>';
    if (!nAbertas) {
      h += '<p class="texto">nenhuma porta aberta entre as ' +
           escapar(p.total) + " testadas.</p>";
    } else {
      h += "<table><tr><th>porta</th><th>serviço</th></tr>";
      for (const o of p.abertas) {
        h += '<tr><td class="tag tag-transferido">' + escapar(o.porta) +
             "</td><td>" + escapar(o.servico) + "</td></tr>";
      }
      h += "</table>";
    }
    h += '<p class="texto">host ' + escapar(p.host) + " &middot; " +
         nAbertas + " abertas / " + escapar(p.fechadas) + " fechadas / " +
         escapar(p.filtradas) + " filtradas</p></div>";
  } else if (r.portas && r.portas.motivo &&
             r.portas.motivo !== "não solicitada") {
    h += '<div class="bloco"><h3>portas</h3><p class="texto">varredura não ' +
         "realizada: " + escapar(r.portas.motivo) + "</p></div>";
  }

  if (r.registros_dominio && Object.keys(r.registros_dominio).length) {
    h += '<div class="bloco"><h3>registros DNS públicos</h3><table>';
    for (const t of Object.keys(r.registros_dominio)) {
      for (const v of r.registros_dominio[t]) {
        h += '<tr><td class="tag">' + escapar(t) + "</td><td>" +
             escapar(v) + "</td></tr>";
      }
    }
    h += "</table></div>";
  }

  if (r.geo && Object.keys(r.geo).length) {
    h += '<div class="bloco"><h3>geolocalização dos IPs</h3><table>' +
         "<tr><th>IP</th><th>país / cidade</th><th>ASN</th></tr>";
    for (const ip of Object.keys(r.geo)) {
      const g = r.geo[ip];
      if (g.erro) {
        h += "<tr><td>" + escapar(ip) + '</td><td colspan="2">' +
             escapar(g.erro) + "</td></tr>";
      } else {
        h += "<tr><td>" + escapar(ip) + "</td><td>" +
             escapar((g.pais || "?") + " / " + (g.cidade || "?")) +
             "</td><td>" + escapar(g.asn || "-") + "</td></tr>";
      }
    }
    h += "</table></div>";
  }

  if (r.whois) {
    h += '<div class="bloco"><h3>whois</h3><details><summary>exibir saída' +
         "</summary><pre>" + escapar(r.whois) + "</pre></details></div>";
  }

  $("conteudo-resultado").innerHTML = h;
}

function fundirRegistros(axfr) {
  const f = {};
  if (!axfr) return f;
  for (const a of axfr) {
    if (a.desfecho !== "transferido" || !a.registros) continue;
    for (const t of Object.keys(a.registros)) {
      if (!f[t]) f[t] = [];
      for (const par of a.registros[t]) f[t].push(par);
    }
  }
  return f;
}

/* ------------------------------------------------------------------ */
/* Exportação JSON (download local, sem rede)                         */
/* ------------------------------------------------------------------ */
$("btn-exportar").addEventListener("click", () => {
  if (!ultimoResultado) return;
  const texto = JSON.stringify(ultimoResultado, null, 2);
  const blob = new Blob([texto], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "zonet01_" + (ultimoResultado.alvo || "scan") + ".json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
});

/* ------------------------------------------------------------------ */
/* Inicialização                                                      */
/* ------------------------------------------------------------------ */
montarCarrossel();
atualizarPilha();
atualizarHistorico();
setInterval(atualizarPilha, INTERVALO_PILHA);
