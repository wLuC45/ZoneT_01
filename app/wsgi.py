"""Ponto de entrada WSGI para o Gunicorn: ``app.wsgi:application``."""

from app import create_app

application = create_app()

if __name__ == "__main__":
    # Execução direta apenas para desenvolvimento local.
    application.run(host="0.0.0.0", port=5000, debug=False)
