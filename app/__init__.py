"""Camada web Flask do ZoneT_01.

``create_app()`` constrói a aplicação, registra as rotas e anexa um único
``GerenciadorJobs`` compartilhado. Importante: o Gunicorn deve rodar com um
único worker (``--workers 1 --threads 8``), pois o store de jobs vive na
memória do processo.
"""

from flask import Flask

from .gerenciador_jobs import GerenciadorJobs
from .rotas import bp


# Política restritiva: a interface só pode carregar recursos locais e só pode
# abrir conexões para a própria origem. Mesmo que a página fosse adulterada, o
# navegador do operador é impedido de contatar qualquer host externo, evitando
# requisições fora do Tor que revelariam o IP real.
_CSP = (
    "default-src 'self'; connect-src 'self'; img-src 'self'; "
    "style-src 'self'; script-src 'self'; font-src 'self'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def create_app():
    app = Flask(__name__)
    app.config["JSON_AS_ASCII"] = False
    app.gerenciador = GerenciadorJobs()
    app.register_blueprint(bp)

    @app.after_request
    def _cabecalhos_seguranca(resposta):
        resposta.headers["Content-Security-Policy"] = _CSP
        resposta.headers["Referrer-Policy"] = "no-referrer"
        resposta.headers["X-Content-Type-Options"] = "nosniff"
        resposta.headers["X-Frame-Options"] = "DENY"
        resposta.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resposta.headers["Cache-Control"] = "no-store"
        # Não revela versão de servidor.
        resposta.headers["Server"] = "ZoneT_01"
        return resposta

    return app
