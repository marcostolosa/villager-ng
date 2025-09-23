# -*- coding: utf-8 -*-
import uuid
import json
import asyncio
import threading
from pathlib import Path
from typing import Union, Dict, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import queue
import atexit


@dataclass
class ShareGPTLoggerConfig:
    """Configuração do ShareGPT Logger"""
    output_dir: str = "dataset_output"
    max_queue_size: int = 10000
    flush_interval: float = 1.0  # segundos
    max_batch_size: int = 100
    enable_async: bool = True
    backup_on_error: bool = True


class ShareGPTLogger:
    """Logger de alto desempenho em formato ShareGPT"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, config: Optional[ShareGPTLoggerConfig] = None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, config: Optional[ShareGPTLoggerConfig] = None):
        if self._initialized:
            return

        self.config = config or ShareGPTLoggerConfig()
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Inicializar fila e pool de threads
        self.queue = queue.Queue(maxsize=self.config.max_queue_size)
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.running = True

        # Iniciar thread de processamento em background
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()

        # Registrar manipulador de saída
        atexit.register(self._cleanup)

        self._initialized = True

    def _worker(self):
        """Thread de trabalho em background"""
        batch = []
        last_flush = datetime.now()

        while self.running:
            try:
                # Coletar dados em lote
                while len(batch) < self.config.max_batch_size:
                    try:
                        item = self.queue.get_nowait()
                        if item is None:  # sinal de parada
                            self.running = False
                            break
                        batch.append(item)
                    except queue.Empty:
                        break

                # Verificar se precisa fazer flush
                now = datetime.now()
                should_flush = (
                        len(batch) >= self.config.max_batch_size or
                        (now - last_flush).total_seconds() >= self.config.flush_interval or
                        not self.running
                )

                if batch and should_flush:
                    self._flush_batch(batch)
                    batch.clear()
                    last_flush = now

                # Se a fila estiver vazia e não precisar de flush forçado, dormir brevemente
                if not batch and self.running:
                    threading.Event().wait(0.01)

            except Exception as e:
                print(f"[ShareGPTLogger] Worker error: {e}")
                if self.config.backup_on_error:
                    self._backup_failed_items(batch)
                batch.clear()

    def _flush_batch(self, batch: list):
        """Escrita em lote para arquivo"""
        try:
            for item in batch:
                self._write_single_item(item)
        except Exception as e:
            print(f"[ShareGPTLogger] Batch flush error: {e}")
            if self.config.backup_on_error:
                self._backup_failed_items(batch)

    def _write_single_item(self, item: Dict[str, Any]):
        """Escrever item individual"""
        try:
            # Construir formato ShareGPT
            sharegpt_data = {
                "id": str(uuid.uuid4()),
                "conversations": [
                    {"from": "human", "value": str(item.get("input", ""))},
                    {"from": "gpt", "value": str(item.get("output", ""))}
                ],
                "timestamp": datetime.now().isoformat(),
                "metadata": item.get("metadata", {})
            }

            # Gerar caminho do arquivo
            filename = f"{sharegpt_data['id']}.sharegpt.json"
            file_path = self.output_dir / filename

            # Escrever arquivo
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(sharegpt_data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            print(f"[ShareGPTLogger] Write error for item: {e}")
            if self.config.backup_on_error:
                self._backup_single_item(item)

    def _backup_single_item(self, item: Dict[str, Any]):
        """Backup de itens com falha"""
        try:
            backup_dir = self.output_dir / "backup"
            backup_dir.mkdir(exist_ok=True)
            filename = f"failed_{uuid.uuid4()}.json"
            file_path = backup_dir / filename

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(item, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[ShareGPTLogger] Backup error: {e}")

    def _backup_failed_items(self, items: list):
        """Backup em lote de itens com falha"""
        for item in items:
            self._backup_single_item(item)

    def log(
            self,
            input_content: Union[str, dict],
            output_content: Union[str, dict],
            metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Registrar dados de uma conversa

        Args:
            input_content: Conteúdo de entrada (prompt)
            output_content: Conteúdo de saída (resposta do modelo)
            metadata: Metadados
        """
        try:
            item = {
                "input": input_content,
                "output": output_content,
                "metadata": metadata or {}
            }

            if self.config.enable_async:
                # Modo assíncrono: colocar na fila
                try:
                    self.queue.put_nowait(item)
                except queue.Full:
                    print("[ShareGPTLogger] Queue full, dropping item")
            else:
                # Modo síncrono: escrever diretamente
                self._write_single_item(item)

        except Exception as e:
            print(f"[ShareGPTLogger] Log error: {e}")
            if self.config.backup_on_error:
                self._backup_single_item({
                    "input": str(input_content),
                    "output": str(output_content),
                    "metadata": metadata or {},
                    "error": str(e)
                })

    async def alog(
            self,
            input_content: Union[str, dict],
            output_content: Union[str, dict],
            metadata: Optional[Dict[str, Any]] = None
    ):
        """Interface de registro assíncrono"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self.executor,
            self.log,
            input_content,
            output_content,
            metadata
        )

    def _cleanup(self):
        """Limpeza de recursos"""
        self.running = False
        if hasattr(self, 'queue'):
            self.queue.put_nowait(None)  # enviar sinal de parada
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)

    def flush(self):
        """Forçar flush de todos os dados pendentes"""
        # Aguardar esvaziamento da fila
        while not self.queue.empty():
            threading.Event().wait(0.1)


# Instância global
def get_sharegpt_logger(config: Optional[ShareGPTLoggerConfig] = None) -> ShareGPTLogger:
    """Obter instância global do ShareGPT Logger"""
    return ShareGPTLogger(config)


# Funções de conveniência
def log_sharegpt_conversation(
        input_content: Union[str, dict],
        output_content: Union[str, dict],
        metadata: Optional[Dict[str, Any]] = None,
        config: Optional[ShareGPTLoggerConfig] = None
):
    """Função conveniente de registro de log"""
    logger = get_sharegpt_logger(config)
    logger.log(input_content, output_content, metadata)


async def alog_sharegpt_conversation(
        input_content: Union[str, dict],
        output_content: Union[str, dict],
        metadata: Optional[Dict[str, Any]] = None,
        config: Optional[ShareGPTLoggerConfig] = None
):
    """Função conveniente de registro de log assíncrono"""
    logger = get_sharegpt_logger(config)
    await logger.alog(input_content, output_content, metadata)
