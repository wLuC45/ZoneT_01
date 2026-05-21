"""Gerenciador de jobs de scan em memória volátil (sem persistência em disco).

Os jobs são executados num ThreadPoolExecutor limitado e armazenados num dict
protegido por lock. Um reaper descarta jobs antigos para manter a memória
limitada — todo o estado é volátil, conforme o requisito de não persistência.
"""

import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor

from recon.motor_recon import executar_recon

# Limita scans simultâneos para não esgotar circuitos Tor.
_MAX_WORKERS = 4
# Jobs já finalizados são removidos após este tempo (segundos).
_TTL_JOB = 1800  # 30 min
# Limite absoluto: mesmo um job preso é removido após este tempo, evitando
# vazamento de memória caso uma thread trabalhadora nunca conclua.
_TTL_ABSOLUTO = 10800  # 3 h
# Teto de jobs guardados; acima dele, os terminais mais antigos são removidos.
_LIMITE_JOBS = 200
# Estados terminais de um job.
_ESTADOS_TERMINAIS = ("concluido", "erro")
# Intervalo entre passadas do reaper periódico (segundos).
_INTERVALO_REAPER = 300


class Job:
    """Estado de um único scan, atualizado pela thread trabalhadora."""

    def __init__(self, job_id, alvo, varrer_portas=False):
        self.id = job_id
        self.alvo = alvo
        self.varrer_portas = varrer_portas
        self.estado = "pendente"          # pendente|executando|concluido|erro
        self.progresso = 0                # 0-100
        self.etapa_atual = "Na fila..."
        self.etapas = []                  # log append-only de (progresso, texto)
        self.resultado = None             # dict final de executar_recon
        self.erro = None
        self.criado_em = time.time()
        self.concluido_em = None

    def para_dict(self):
        return {
            "id": self.id,
            "alvo": self.alvo,
            "estado": self.estado,
            "progresso": self.progresso,
            "etapa_atual": self.etapa_atual,
            "etapas": list(self.etapas),
            "resultado": self.resultado,
            "erro": self.erro,
        }


class GerenciadorJobs:
    """Cria, executa e consulta jobs de scan."""

    def __init__(self):
        self._jobs = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS)
        # Reaper periódico: garante que jobs antigos sejam removidos mesmo
        # quando o operador deixar a interface inativa por longos períodos
        # (cenário em que ``criar_job`` não é chamado para disparar a limpeza).
        # ``daemon=True`` faz a thread morrer junto com o processo.
        self._parar_reaper = threading.Event()
        self._thread_reaper = threading.Thread(
            target=self._loop_reaper, name="zonet-reaper", daemon=True,
        )
        self._thread_reaper.start()

    def criar_job(self, alvo, varrer_portas=False):
        """Cria um job para ``alvo`` e o agenda. Retorna o job_id."""
        job_id = uuid.uuid4().hex
        job = Job(job_id, alvo, varrer_portas)
        with self._lock:
            self._expirar_antigos_locked()
            self._jobs[job_id] = job
        self._executor.submit(self._executar, job)
        return job_id

    def obter_job(self, job_id):
        """Retorna o dict de estado do job, ou None se inexistente."""
        with self._lock:
            job = self._jobs.get(job_id)
            return job.para_dict() if job else None

    def estatisticas(self):
        """Resumo da sessão: total, jobs ativos e distribuição por nível."""
        with self._lock:
            total = len(self._jobs)
            ativos = 0
            por_nivel = {}
            for job in self._jobs.values():
                if job.estado in ("pendente", "executando"):
                    ativos += 1
                elif job.estado == "concluido" and job.resultado:
                    nivel = (job.resultado.get("risco") or {}).get("nivel")
                    if nivel:
                        por_nivel[nivel] = por_nivel.get(nivel, 0) + 1
            return {"total": total, "ativos": ativos, "por_nivel": por_nivel}

    def historico(self, limite=15):
        """Lista resumida dos jobs mais recentes, do mais novo ao mais antigo."""
        with self._lock:
            recentes = sorted(
                self._jobs.values(), key=lambda j: j.criado_em, reverse=True
            )[:limite]
            return [
                {
                    "id": j.id,
                    "alvo": j.alvo,
                    "estado": j.estado,
                    "nivel": ((j.resultado or {}).get("risco") or {}).get("nivel"),
                    "criado_em": j.criado_em,
                }
                for j in recentes
            ]

    def _executar(self, job):
        """Corpo da thread trabalhadora — executa a recon do job."""
        def relatar(progresso, etapa):
            with self._lock:
                job.progresso = progresso
                job.etapa_atual = etapa
                job.etapas.append({"progresso": progresso, "texto": etapa})

        with self._lock:
            job.estado = "executando"
        try:
            resultado = executar_recon(job.alvo, relatar, job.varrer_portas)
            with self._lock:
                job.resultado = resultado
                job.estado = "concluido"
                job.progresso = 100
                job.concluido_em = time.time()
        except ValueError as exc:
            # Alvo inválido — erro previsível.
            with self._lock:
                job.estado = "erro"
                job.erro = str(exc)
                job.etapa_atual = f"Erro: {exc}"
                job.concluido_em = time.time()
        except Exception as exc:  # falha inesperada
            with self._lock:
                job.estado = "erro"
                job.erro = f"Falha interna: {exc}"
                job.etapa_atual = "Erro interno durante o scan."
                job.concluido_em = time.time()
            traceback.print_exc()

    def _expirar_antigos_locked(self):
        """Remove jobs antigos. Deve ser chamado com o lock adquirido.

        Um job só é removido pelo TTL normal se já estiver finalizado; assim um
        scan longo ainda em execução não desaparece do store enquanto a thread
        trabalhadora o atualiza. O TTL absoluto cobre jobs presos.
        """
        agora = time.time()
        expirados = []
        for jid, j in self._jobs.items():
            idade = agora - j.criado_em
            terminou = j.estado in _ESTADOS_TERMINAIS
            if (terminou and idade > _TTL_JOB) or idade > _TTL_ABSOLUTO:
                expirados.append(jid)
        for jid in expirados:
            del self._jobs[jid]

        # Teto rígido: se ainda houver jobs demais, remove os terminais mais
        # antigos para limitar o uso de memória.
        if len(self._jobs) > _LIMITE_JOBS:
            terminais = sorted(
                (j for j in self._jobs.values()
                 if j.estado in _ESTADOS_TERMINAIS),
                key=lambda j: j.criado_em,
            )
            excedente = len(self._jobs) - _LIMITE_JOBS
            for job in terminais[:excedente]:
                del self._jobs[job.id]

    def _loop_reaper(self):
        """Executa a expiração periodicamente em background."""
        while not self._parar_reaper.wait(_INTERVALO_REAPER):
            with self._lock:
                self._expirar_antigos_locked()

    def parar(self):
        """Encerra a thread de reaper e o executor (uso em testes)."""
        self._parar_reaper.set()
        self._executor.shutdown(wait=False)
