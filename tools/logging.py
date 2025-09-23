import datetime
import functools
import json
import os
from typing import List
import orjson


# Objeto de log, usado para transmitir informações de log entre middlewares
class Logging(object):
	def __init__(self, level, data):
		self.level = level
		self.data = data
		self.logging_time = datetime.datetime.now().isoformat()

	def __dict__(self):
		return {
			"level": self.level,
			"data": self.data,
			"logging_time": self.logging_time,
		}


# Objeto de log antes de ser enviado para o fluxo de saída, usado para processar logs na perspectiva de string em middlewares
class Preflush:
	def __init__(self, data_object: Logging, data_str: str):
		self.data_object: Logging = data_object
		self.data_str: str = data_str


# Classe abstrata de middleware de log
class LoggingMiddlewareAbstract(object):
	# Função para processar logs na forma de Object
	def write(self, data: Logging) -> Logging:
		raise NotImplementedError()

	# Função para processar logs na forma de string
	def flush(self, data: Preflush) -> Preflush:
		raise NotImplementedError()




# Middleware que processa logs em strings serializadas JSON
class JsonLoggingMiddleware(LoggingMiddlewareAbstract):
	def write(self, data: Logging) -> Logging:
		return data

	def flush(self, data: Preflush) -> Preflush:
		print(data)
		def default(obj):
			return "<class '{}'>".format(type(obj))
		#data.data_str = orjson.dumps(data.data_object.__dict__(), default=default, option=orjson.OPT_SERIALIZE_NUMPY).decode()
		data.data_str = json.dumps(data.data_object.__dict__(), ensure_ascii=False, default=str) + "\n"

		return data


# Fluxo de saída de log abstrato
class AbstractLoggingStream:
	def write(self, data: str) -> Logging:
		raise NotImplementedError()


# Fluxo de saída de log para terminal
class LoggingToConsole(AbstractLoggingStream):
	def write(self, data: str):
		logging_time = datetime.datetime.now().isoformat()
		print(f"[DEBUG] time:{logging_time} data:{data}")


# Fluxo de saída de log para arquivo
class LoggingToFile(AbstractLoggingStream):
	def __init__(self, filename="function_log.json"):
		self.filename = filename
		self.fs = open(self.filename, "a")

	def write(self, data: str):
		self.fs.write(f"{data}\n")
		self.fs.flush()


# Fluxo de saída de log para socket
class LoggingToSocket(AbstractLoggingStream):
	def __init__(self,server_uuid, host: str, port: int):

		import threading
		import queue
		self.server_uuid = server_uuid
		self.host = host
		self.port = port
		self.socket = None
		self.log_queue = queue.Queue()
		self.running = False
		self.worker_thread = threading.Thread(target=self._send_logs, daemon=True)
		self._connect_socket()
		self._start_worker()
		pass

	def _connect_socket(self):
		import socket
		import sys
		"""Criar e conectar ao Socket"""
		try:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.socket.connect((self.host, self.port))
		except socket.error as e:
			sys.stderr.write(f"Socket connection failed: {str(e)}\n")
			self.socket = None

	def _start_worker(self):
		"""Iniciar thread de trabalho"""
		if self.socket:
			self.running = True
			self.worker_thread.start()

	def write(self, data: str):
		import sys
		import queue
		"""
		Colocar dados de log na fila
		:param data: Dados de log a serem transmitidos
		"""
		if not self.running or not self.socket:
			return
		try:
			log_data_packed={
				'server_uuid': self.server_uuid,
				'data': data,
			}
			# Colocar dados na fila (não bloqueante, definir timeout para evitar deadlock)
			self.log_queue.put(json.dumps(log_data_packed,default=str), block=True, timeout=0.1)
		except queue.Full:
			sys.stderr.write("Log queue full. Dropping log message.\n")

	def _send_logs(self):
		import threading
		import queue
		import socket
		import sys
		"""Função da thread de trabalho: retirar logs da fila e enviar para Socket"""
		while self.running:
			try:
				# Obter dados da fila (com timeout)
				data = self.log_queue.get(block=True, timeout=1)
				if not self.socket:
					continue
				try:
					# Enviar dados e adicionar quebra de linha
					self.socket.sendall((data + '\n').encode('utf-8'))
				except socket.error as e:
					sys.stderr.write(f"Socket send error: {str(e)}\n")
					self._reconnect_socket()
			except queue.Empty:
				# Timeout, continuar verificando status de execução
				continue

	def _reconnect_socket(self):
		import socket
		import sys
		"""Tentar reconectar Socket"""
		try:
			if self.socket:
				self.socket.close()
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.socket.settimeout(2)
			self.socket.connect((self.host, self.port))
			sys.stderr.write("Socket reconnected successfully.\n")
		except socket.error as e:
			sys.stderr.write(f"Socket reconnect failed: {str(e)}\n")
			self.socket = None

	def close(self):
		"""Fechar conexão e parar thread de trabalho"""
		self.running = False
		if self.worker_thread.is_alive():
			self.worker_thread.join(timeout=1)
		if self.socket:
			self.socket.close()

"""
/**
	Perguntar IA
*/
"""


# Implementação concreta do log, este log é singleton em todo o processo
class __logging:
	def __init__(self):
		self._logging_stream: AbstractLoggingStream = LoggingToConsole()
		self._check_logging_level()
		self._loging_level: int = 0
		self._logging_middleware: List[LoggingMiddlewareAbstract] = list()
		self._logging_middleware.append(JsonLoggingMiddleware())

	def _check_logging_level(self):
		self._loging_level = int(os.environ.get("LOGGING_LEVEL", 0))

	def set_logging_level(self, level: int):
		self._loging_level = level

	def set_logging_middleware(self, middleware: List[LoggingMiddlewareAbstract]):
		self._logging_middleware = middleware

	def set_logging_stream(self, logging_stream: AbstractLoggingStream):
		self._logging_stream = logging_stream

	def _log(self, data: Logging):
		if data.level < self._loging_level < 0:
			del data
			return
		for middleware in self._logging_middleware:
			data = middleware.write(data)

		pre_flush = Preflush(data_object=data, data_str="")

		for middleware in self._logging_middleware:
			pre_flush = middleware.flush(pre_flush)

		self._logging_stream.write(pre_flush.data_str)

	# Log comum
	def log(self, data, logging_level: int = 0):
		self._log(Logging(level=logging_level, data=data))

	# Decorador para monitorar entrada e saída de funções
	def function_logging(self, logging_level: int = 0):
		def decorator(func):
			@functools.wraps(func)
			def wrapper(*args, **kwargs):
				try:
					result = func(*args, **kwargs)
					status = "Success"
					error = None
				except Exception as e:
					result = None
					status = "Error"
					error = e
				log_data = {
					"function_name": func.__name__,
					"arguments": {
						"args": args,
						"kwargs": kwargs
					},
					"status": status,
					"return_value": result,
					"error": str(error)
				}
				self._log(Logging(level=logging_level, data=log_data))
				if error is not None:
					raise error
				return result

			return wrapper

		return decorator


logging = __logging()
