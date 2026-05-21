"""Rotas HTTP do ZoneT_01."""

import socket

from flask import Blueprint, current_app, jsonify, render_template, request

from recon.ferramentas_dns import resolvedor_pronto
from recon.utilitarios import validar_alvo

bp = Blueprint("rotas", __name__)


def _porta_aberta(host, porta, timeout=1.5):
    """Verificação rápida de socket TCP, sem bloquear a interface."""
    try:
        with socket.create_connection((host, porta), timeout=timeout):
            return True
    except OSError:
        return False


@bp.get("/")
def indice():
    """Página única da interface web."""
    return render_template("index.html")


@bp.get("/healthz")
def healthz():
    """Liveness probe: indica apenas que o processo web está de pé."""
    return jsonify({"status": "ok"})


@bp.get("/readyz")
def readyz():
    """Readiness probe: confirma que a cadeia de resolução DNS funciona.

    Responde 200 quando o dnscrypt-proxy local resolve nomes e 503 caso
    contrário. Usado pelo healthcheck do contêiner para não reportar como
    saudável um estado em que os scans falhariam.
    """
    if resolvedor_pronto():
        return jsonify({"status": "ok", "dns": "operacional"})
    return jsonify({"status": "indisponivel", "dns": "sem resolução"}), 503


@bp.post("/scan")
def iniciar_scan():
    """Cria um job de scan. Corpo JSON: ``{"alvo": "..."}``.

    Retorna ``{"job_id": "..."}`` com HTTP 202, ou 400 para alvo inválido.
    """
    dados = request.get_json(silent=True) or {}
    alvo = dados.get("alvo", "")
    varrer_portas = bool(dados.get("portas", False))

    try:
        # Valida ANTES de criar o job — o valor chegará a subprocessos.
        validar_alvo(alvo)
    except ValueError as exc:
        return jsonify({"erro": str(exc)}), 400

    job_id = current_app.gerenciador.criar_job(
        alvo.strip().lower(), varrer_portas
    )
    return jsonify({"job_id": job_id}), 202


@bp.get("/status/<job_id>")
def status_scan(job_id):
    """Retorna o estado atual de um job para polling AJAX."""
    if not job_id.isalnum() or len(job_id) != 32:
        return jsonify({"erro": "job_id inválido"}), 400
    job = current_app.gerenciador.obter_job(job_id)
    if job is None:
        return jsonify({"erro": "job não encontrado ou expirado"}), 404
    return jsonify(job)


@bp.get("/pilha")
def pilha():
    """Estado da pilha de anonimização e estatísticas da sessão.

    Usa verificações de socket rápidas (sem consultas DNS lentas) para que o
    carrossel da interface possa consultar este endpoint com frequência.
    """
    return jsonify({
        "tor": _porta_aberta("127.0.0.1", 9050),
        "dnscrypt": _porta_aberta("127.0.0.1", 53),
        "sessao": current_app.gerenciador.estatisticas(),
    })


@bp.get("/historico")
def historico():
    """Lista resumida dos scans mais recentes da sessão."""
    return jsonify({"jobs": current_app.gerenciador.historico()})
