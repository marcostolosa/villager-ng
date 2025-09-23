# EXERCÍCIOS PRÁTICOS EDUCACIONAIS - VILLAGER-NG
## Laboratório de Segurança Cibernética para Ensino

### IMPORTANTE: AMBIENTE EDUCACIONAL CONTROLADO
Todos os exercícios devem ser executados EXCLUSIVAMENTE em ambiente isolado, com supervisão acadêmica e para fins educacionais de segurança defensiva.

---

## MÓDULO 1: ANÁLISE DE CÓDIGO PERIGOSO

### Exercício 1.1: Detecção de Code Injection
**Objetivo**: Identificar e corrigir vulnerabilidades de injeção de código

#### Código para Análise:
```python
# ARQUIVO: scheduler/core/Thought.py
def pyeval(python_codeblock: str):
    """CÓDIGO PERIGOSO - Para análise educacional"""
    return eval(python_codeblock)

def os_execute_cmd(cmd: str):
    """CÓDIGO PERIGOSO - Para análise educacional"""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)
```

#### Questões para Estudantes:
1. **Identifique os problemas**: Que vulnerabilidades existem neste código?
2. **Classifique os riscos**: Qual é o nível de severidade de cada problema?
3. **Proponha correções**: Como tornar este código seguro?

#### Solução Educacional:
```python
import subprocess
import shlex
import re
from typing import List, Optional

class SecureExecutor:
    """Implementação segura para fins educacionais"""

    def __init__(self):
        # Lista branca de comandos permitidos
        self.allowed_commands = {
            'ls', 'pwd', 'whoami', 'date', 'echo', 'cat'
        }

        # Lista branca de operadores matemáticos
        self.math_operators = {'+', '-', '*', '/', '(', ')', ' ', '.'}

    def safe_eval(self, expression: str, allowed_names: Optional[dict] = None) -> float:
        """Avaliação segura de expressões matemáticas"""
        if allowed_names is None:
            allowed_names = {"__builtins__": {}}

        # Validação de entrada
        if not isinstance(expression, str):
            raise ValueError("Expression must be a string")

        if len(expression) > 100:
            raise ValueError("Expression too long")

        # Verificar apenas caracteres matemáticos
        allowed_chars = set("0123456789+-*/() .")
        if not set(expression).issubset(allowed_chars):
            raise ValueError("Invalid characters in expression")

        # Prevenir chamadas de função
        if '(' in expression and ')' in expression:
            # Verificar se não há letras antes de parênteses (indicando chamada de função)
            if re.search(r'[a-zA-Z_]\s*\(', expression):
                raise ValueError("Function calls not allowed")

        try:
            # Avaliação limitada apenas a matemática
            result = eval(expression, {"__builtins__": {}}, {})
            return float(result)
        except Exception as e:
            raise ValueError(f"Evaluation error: {e}")

    def safe_execute_cmd(self, cmd: str, args: List[str] = None) -> dict:
        """Execução segura de comandos do sistema"""
        if args is None:
            args = []

        # Validar comando
        if cmd not in self.allowed_commands:
            raise ValueError(f"Command '{cmd}' not allowed")

        # Validar argumentos
        for arg in args:
            if not isinstance(arg, str):
                raise ValueError("All arguments must be strings")
            if len(arg) > 100:
                raise ValueError("Argument too long")
            # Prevenir caracteres perigosos
            dangerous_chars = {';', '&', '|', '`', '$', '(', ')'}
            if any(char in arg for char in dangerous_chars):
                raise ValueError("Dangerous characters in argument")

        try:
            # Construir comando seguro
            safe_cmd = [cmd] + args
            result = subprocess.run(
                safe_cmd,
                capture_output=True,
                text=True,
                timeout=5,  # Timeout de 5 segundos
                check=False
            )

            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'command': ' '.join(safe_cmd)
            }

        except subprocess.TimeoutExpired:
            raise ValueError("Command execution timed out")
        except Exception as e:
            raise ValueError(f"Execution error: {e}")

# Exemplo de uso educacional:
def demonstrar_uso_seguro():
    """Demonstração de uso seguro"""
    executor = SecureExecutor()

    # Exemplo seguro - matemática
    try:
        result = executor.safe_eval("2 + 3 * 4")
        print(f"Resultado matemático: {result}")
    except ValueError as e:
        print(f"Erro de validação: {e}")

    # Exemplo seguro - comando do sistema
    try:
        result = executor.safe_execute_cmd("ls", ["-l"])
        print(f"Saída do comando: {result['stdout']}")
    except ValueError as e:
        print(f"Erro de validação: {e}")
```

#### Exercício Prático:
1. **Teste a versão perigosa** (em ambiente isolado)
2. **Implemente a versão segura**
3. **Compare os resultados**
4. **Documente as diferenças**

---

## MÓDULO 2: ANÁLISE DE COMUNICAÇÃO MALICIOSA

### Exercício 2.1: Detecção de Canais C&C
**Objetivo**: Identificar e analisar canais de Command & Control

#### Código para Análise:
```python
# ARQUIVO: tools/logging.py
class LoggingToSocket(AbstractLoggingStream):
    """CÓDIGO SUSPEITO - Para análise educacional"""

    def __init__(self, server_uuid, host: str, port: int):
        self.server_uuid = server_uuid  # Identificador único
        self.host = host               # 10.10.3.119 (hardcoded)
        self.port = port               # 25989 (hardcoded)
        self.running = False
        self._connect_socket()         # Conexão automática
        self._start_worker()           # Thread de comunicação
```

#### Questões para Análise:
1. **Identifique indicadores**: Que características sugerem um canal C&C?
2. **Analise o comportamento**: Como funciona a persistência da conexão?
3. **Proposta de detecção**: Como detectar essa atividade em rede?

#### Solução de Detecção:
```python
import socket
import threading
import time
from datetime import datetime
from typing import Set, Dict, List

class NetworkMonitor:
    """Monitor educacional para detecção de C&C"""

    def __init__(self):
        self.suspicious_ips: Set[str] = {
            "10.10.3.119",   # Servidor MCP principal
            "10.10.3.248",   # Console de comandos
            "100.64.0.33",   # Alvo de reconnaissance
        }

        self.suspicious_ports: Set[int] = {
            25989,  # MCP Server
            1611,   # Console
            37695,  # Villager Server
            5422,   # Proxy
        }

        self.connection_log: List[Dict] = []
        self.alerts: List[Dict] = []

    def monitor_connections(self) -> None:
        """Monitora conexões de rede suspeitas"""
        print("Iniciando monitoramento de rede...")

        while True:
            try:
                # Simular captura de conexões (em ambiente real, usar psutil ou netstat)
                connections = self._get_active_connections()

                for conn in connections:
                    if self._is_suspicious_connection(conn):
                        self._create_alert(conn)

                time.sleep(5)  # Verificar a cada 5 segundos

            except Exception as e:
                print(f"Erro no monitoramento: {e}")

    def _get_active_connections(self) -> List[Dict]:
        """Simula obtenção de conexões ativas"""
        # Em ambiente real, usar psutil.net_connections()
        return [
            {"local_addr": "192.168.1.100", "local_port": 50432,
             "remote_addr": "10.10.3.119", "remote_port": 25989, "status": "ESTABLISHED"},
            {"local_addr": "192.168.1.100", "local_port": 50433,
             "remote_addr": "8.8.8.8", "remote_port": 53, "status": "ESTABLISHED"},
        ]

    def _is_suspicious_connection(self, connection: Dict) -> bool:
        """Verifica se conexão é suspeita"""
        remote_ip = connection.get("remote_addr")
        remote_port = connection.get("remote_port")

        # Verificar IP suspeito
        if remote_ip in self.suspicious_ips:
            return True

        # Verificar porta suspeita
        if remote_port in self.suspicious_ports:
            return True

        # Verificar padrões de reconexão
        if self._check_reconnection_pattern(connection):
            return True

        return False

    def _check_reconnection_pattern(self, connection: Dict) -> bool:
        """Detecta padrões de reconexão automática"""
        # Analisar histórico de conexões para o mesmo destino
        remote_addr = connection.get("remote_addr")
        recent_connections = [
            conn for conn in self.connection_log[-100:]  # Últimas 100 conexões
            if conn.get("remote_addr") == remote_addr
        ]

        # Se muitas conexões para o mesmo IP em pouco tempo
        if len(recent_connections) > 10:
            return True

        return False

    def _create_alert(self, connection: Dict) -> None:
        """Cria alerta para conexão suspeita"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "SUSPICIOUS_CONNECTION",
            "details": connection,
            "severity": "HIGH",
            "description": "Possível canal de Command & Control detectado"
        }

        self.alerts.append(alert)
        print(f"🚨 ALERTA: {alert['description']}")
        print(f"   Destino: {connection['remote_addr']}:{connection['remote_port']}")

# Demonstração de uso:
def demonstrar_detecção_cc():
    """Demonstra detecção de canais C&C"""
    monitor = NetworkMonitor()

    # Simular detecção
    print("=== DEMONSTRAÇÃO DE DETECÇÃO C&C ===")
    print("Monitorando conexões de rede...")

    # Em ambiente real, executar monitor.monitor_connections()
    # Para demonstração, simular detecção
    suspicious_conn = {
        "local_addr": "192.168.1.100",
        "local_port": 50432,
        "remote_addr": "10.10.3.119",  # IP suspeito
        "remote_port": 25989,          # Porta suspeita
        "status": "ESTABLISHED"
    }

    if monitor._is_suspicious_connection(suspicious_conn):
        monitor._create_alert(suspicious_conn)

    # Mostrar alertas
    for alert in monitor.alerts:
        print(f"Alerta: {alert}")
```

#### Exercício Prático:
1. **Configure o monitor** em ambiente de laboratório
2. **Simule tráfego suspeito** para os IPs/portas identificados
3. **Analise os alertas** gerados
4. **Documente os padrões** observados

---

## MÓDULO 3: ANÁLISE DE EVASÃO E OFUSCAÇÃO

### Exercício 3.1: Detecção de Payload Ofuscado
**Objetivo**: Identificar e analisar técnicas de evasão

#### Código para Análise:
```python
# ARQUIVO: tools/args_wrap/args_wraper.py
def serialize_args(args):
    """TÉCNICA DE EVASÃO - Para análise educacional"""
    import pickle
    import base64

    # Serialização pickle (perigosa)
    pickled_data = pickle.dumps(args)

    # Codificação base64 (ofuscação)
    encoded_data = base64.b64encode(pickled_data)

    return encoded_data.decode('utf-8')
```

#### Payload Suspeito Encontrado:
```
gASVNAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwdX19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2lkJyk=
```

#### Questões para Análise:
1. **Decodifique o payload**: O que este código faz quando executado?
2. **Identifique a técnica**: Que método de evasão está sendo usado?
3. **Proposta de detecção**: Como detectar automaticamente?

#### Solução de Análise:
```python
import base64
import pickle
import re
import hashlib
from typing import Tuple, Optional, Dict, Any

class PayloadAnalyzer:
    """Analisador educacional de payloads ofuscados"""

    def __init__(self):
        # Padrões de detecção
        self.base64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
        self.dangerous_pickle_patterns = [
            b'cbuiltins\neval',      # eval builtin
            b'cos\nsystem',          # os.system
            b'c__builtin__\neval',   # __builtin__.eval
            b'csubprocess\n',        # subprocess module
        ]

        # Database de hashes conhecidos
        self.known_malicious_hashes = {
            "a1b2c3d4e5f6": "Known malicious pickle payload",
            "f6e5d4c3b2a1": "Remote code execution payload"
        }

    def analyze_payload(self, data: str) -> Dict[str, Any]:
        """Analisa payload suspeito de forma segura"""
        analysis_result = {
            "is_suspicious": False,
            "encoding_detected": None,
            "dangers_found": [],
            "recommendations": [],
            "hash": None
        }

        # 1. Calcular hash para verificação
        data_hash = hashlib.sha256(data.encode()).hexdigest()[:12]
        analysis_result["hash"] = data_hash

        # Verificar hash conhecido
        if data_hash in self.known_malicious_hashes:
            analysis_result["is_suspicious"] = True
            analysis_result["dangers_found"].append(
                f"Known malicious payload: {self.known_malicious_hashes[data_hash]}"
            )

        # 2. Detectar encoding Base64
        if self._is_base64(data):
            analysis_result["encoding_detected"] = "base64"
            analysis_result["is_suspicious"] = True

            try:
                # Decodificar Base64 de forma segura
                decoded_data = base64.b64decode(data)
                analysis_result["decoded_size"] = len(decoded_data)

                # 3. Analisar conteúdo decodificado
                self._analyze_decoded_content(decoded_data, analysis_result)

            except Exception as e:
                analysis_result["dangers_found"].append(f"Base64 decode error: {e}")

        # 4. Gerar recomendações
        self._generate_recommendations(analysis_result)

        return analysis_result

    def _is_base64(self, data: str) -> bool:
        """Verifica se string é Base64 válido"""
        if len(data) < 20:  # Muito curto para ser suspeito
            return False

        return bool(self.base64_pattern.match(data))

    def _analyze_decoded_content(self, decoded_data: bytes, result: Dict) -> None:
        """Analisa conteúdo decodificado sem executar"""

        # Detectar pickle
        if decoded_data.startswith(b'\x80\x03') or decoded_data.startswith(b'\x80\x04'):
            result["dangers_found"].append("Pickle serialization detected")
            result["is_suspicious"] = True

            # Procurar padrões perigosos no pickle
            for pattern in self.dangerous_pickle_patterns:
                if pattern in decoded_data:
                    result["dangers_found"].append(f"Dangerous pickle pattern: {pattern}")

        # Detectar comandos perigosos como strings
        dangerous_strings = [b'eval', b'exec', b'os.system', b'subprocess', b'__import__']
        for danger in dangerous_strings:
            if danger in decoded_data:
                result["dangers_found"].append(f"Dangerous string found: {danger.decode()}")

        # Analisar estrutura
        if len(decoded_data) > 1000:
            result["dangers_found"].append("Unusually large payload")

        # Detectar compressão adicional
        if decoded_data.startswith(b'\x1f\x8b'):  # gzip
            result["dangers_found"].append("Gzip compression detected (additional obfuscation)")

    def _generate_recommendations(self, result: Dict) -> None:
        """Gera recomendações baseadas na análise"""
        if result["is_suspicious"]:
            result["recommendations"].extend([
                "Block this payload immediately",
                "Investigate source of payload",
                "Check for additional indicators of compromise",
                "Review network logs for similar patterns"
            ])
        else:
            result["recommendations"].append("Payload appears safe, but continue monitoring")

    def safe_pickle_analysis(self, pickle_data: bytes) -> Dict[str, Any]:
        """Análise segura de pickle sem desserialização"""
        analysis = {
            "opcodes_found": [],
            "imports_detected": [],
            "risks": []
        }

        # Analisar opcodes do pickle sem executar
        # Esta é uma análise simplificada - em produção, usar pickletools

        if b'cbuiltins\neval' in pickle_data:
            analysis["opcodes_found"].append("GLOBAL builtin eval")
            analysis["risks"].append("HIGH: Code execution capability")

        if b'cos\nsystem' in pickle_data:
            analysis["opcodes_found"].append("GLOBAL os.system")
            analysis["risks"].append("CRITICAL: System command execution")

        if b'csubprocess' in pickle_data:
            analysis["imports_detected"].append("subprocess module")
            analysis["risks"].append("HIGH: Process execution capability")

        return analysis

# Demonstração de análise do payload encontrado:
def demonstrar_analise_payload():
    """Demonstra análise do payload suspeito"""
    analyzer = PayloadAnalyzer()

    # Payload suspeito encontrado no código
    suspicious_payload = "gASVNAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwdX19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2lkJyk="

    print("=== ANÁLISE DE PAYLOAD SUSPEITO ===")
    print(f"Payload: {suspicious_payload[:50]}...")

    # Analisar payload
    result = analyzer.analyze_payload(suspicious_payload)

    print(f"\nResultados da análise:")
    print(f"Suspeito: {result['is_suspicious']}")
    print(f"Encoding: {result['encoding_detected']}")
    print(f"Hash: {result['hash']}")

    print("\nPerigos encontrados:")
    for danger in result['dangers_found']:
        print(f"  - {danger}")

    print("\nRecomendações:")
    for rec in result['recommendations']:
        print(f"  - {rec}")

    # Análise adicional do pickle (se detectado)
    if result['encoding_detected'] == 'base64':
        try:
            decoded = base64.b64decode(suspicious_payload)
            if decoded.startswith(b'\x80'):  # Pickle magic bytes
                pickle_analysis = analyzer.safe_pickle_analysis(decoded)
                print(f"\nAnálise do Pickle:")
                print(f"Opcodes: {pickle_analysis['opcodes_found']}")
                print(f"Imports: {pickle_analysis['imports_detected']}")
                print(f"Riscos: {pickle_analysis['risks']}")
        except Exception as e:
            print(f"Erro na análise adicional: {e}")

# IMPORTANTE: Demonstração do que o payload faz (SEM EXECUTAR)
def explicar_payload_perigoso():
    """Explica o que o payload faz sem executá-lo"""
    print("\n=== EXPLICAÇÃO EDUCACIONAL ===")
    print("O payload analisado, quando decodificado, equivale ao código Python:")
    print("  eval(__import__('os').system('id'))")
    print("\nIsso significa:")
    print("  1. Importa o módulo 'os'")
    print("  2. Chama os.system('id')")
    print("  3. Executa o comando 'id' no sistema")
    print("  4. Retorna informações do usuário atual")
    print("\nRISCOS:")
    print("  - Execução arbitrária de comandos")
    print("  - Escalação de privilégios")
    print("  - Reconhecimento do sistema")
    print("  - Primeiro passo para comprometimento completo")
```

#### Exercício Prático:
1. **Analise o payload** usando o analisador seguro
2. **Identifique os riscos** sem executar o código
3. **Implemente detecção** para padrões similares
4. **Crie regras SIEM** baseadas nos indicadores

---

## MÓDULO 4: ANÁLISE DE RECONNAISSANCE

### Exercício 4.1: Detecção de Varredura Automatizada
**Objetivo**: Identificar atividades de reconnaissance

#### Código para Análise:
```python
# ARQUIVO: tools/check/checking.py
class checkEnv:
    def checkNetwork(self, proxy: str):
        """RECONNAISSANCE AUTOMATIZADO - Para análise"""
        # Teste de DNS
        ip = socket.gethostbyname("www.baidu.com")

        # Teste de conectividade
        requests.get("http://www.baidu.com")

        # Teste com proxy hardcoded
        proxy = "https://huancun:ylq123..@home.hc26.org:5422"
        requests.get("http://www.google.com", proxies={"http": proxy})

        # Enumeração de interfaces de rede
        net = psutil.net_if_addrs()
        for k, v in net.items():
            for item in v:
                if item.family == 2:  # IPv4
                    print(f"Network: {k} {item.address}")

    def checkCamera(self):
        """SURVEILLANCE - Para análise"""
        cap = cv2.VideoCapture(0)  # Acesso à câmera
        # Teste de múltiplas câmeras
        # Captura de frames
```

#### Questões para Análise:
1. **Identifique as técnicas**: Que tipos de reconnaissance estão sendo realizados?
2. **Avalie os riscos**: Qual informação está sendo coletada?
3. **Proposta de detecção**: Como detectar essa atividade?

#### Solução de Detecção:
```python
import psutil
import time
import subprocess
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Set

class ReconnaissanceDetector:
    """Detector educacional de atividades de reconnaissance"""

    def __init__(self):
        self.network_requests = []
        self.dns_queries = []
        self.port_scans = defaultdict(list)
        self.device_access_attempts = []

        # Thresholds para detecção
        self.DNS_QUERY_THRESHOLD = 10    # 10 queries em 1 minuto
        self.NETWORK_REQUEST_THRESHOLD = 20  # 20 requests em 1 minuto
        self.PORT_SCAN_THRESHOLD = 5     # 5 portas diferentes em 1 minuto

        # IPs e domínios suspeitos conhecidos
        self.suspicious_domains = {
            "www.baidu.com",      # Usado para teste de conectividade
            "httpbin.org",        # Usado para IP discovery
            "api.ipify.org"       # Usado para IP discovery
        }

        self.suspicious_proxies = {
            "home.hc26.org",      # Proxy hardcoded encontrado
            "huancun"             # Username do proxy
        }

    def monitor_network_activity(self) -> None:
        """Monitora atividade de rede para detectar reconnaissance"""
        print("Iniciando monitoramento de reconnaissance...")

        while True:
            try:
                # Verificar conexões ativas
                connections = psutil.net_connections(kind='inet')
                current_time = datetime.now()

                for conn in connections:
                    if conn.raddr:  # Conexão remota ativa
                        self._analyze_connection(conn, current_time)

                # Analisar padrões suspeitos
                self._detect_patterns()

                time.sleep(10)  # Verificar a cada 10 segundos

            except Exception as e:
                print(f"Erro no monitoramento: {e}")

    def _analyze_connection(self, connection, timestamp: datetime) -> None:
        """Analisa conexão individual"""
        if not connection.raddr:
            return

        remote_ip = connection.raddr.ip
        remote_port = connection.raddr.port
        local_port = connection.laddr.port if connection.laddr else None

        # Registrar atividade
        activity = {
            "timestamp": timestamp,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "local_port": local_port,
            "status": connection.status
        }

        self.network_requests.append(activity)

        # Detectar varredura de portas
        self.port_scans[remote_ip].append({
            "port": remote_port,
            "timestamp": timestamp
        })

    def _detect_patterns(self) -> None:
        """Detecta padrões de reconnaissance"""
        current_time = datetime.now()
        one_minute_ago = current_time - timedelta(minutes=1)

        # 1. Detectar múltiplas consultas DNS
        recent_dns = [q for q in self.dns_queries if q["timestamp"] > one_minute_ago]
        if len(recent_dns) > self.DNS_QUERY_THRESHOLD:
            self._create_alert("DNS_ENUMERATION", f"Multiple DNS queries: {len(recent_dns)}")

        # 2. Detectar múltiplas requisições de rede
        recent_requests = [r for r in self.network_requests if r["timestamp"] > one_minute_ago]
        if len(recent_requests) > self.NETWORK_REQUEST_THRESHOLD:
            self._create_alert("NETWORK_ENUMERATION", f"Multiple network requests: {len(recent_requests)}")

        # 3. Detectar varredura de portas
        for ip, scans in self.port_scans.items():
            recent_scans = [s for s in scans if s["timestamp"] > one_minute_ago]
            unique_ports = len(set(s["port"] for s in recent_scans))

            if unique_ports > self.PORT_SCAN_THRESHOLD:
                self._create_alert("PORT_SCAN", f"Port scan detected: {ip}, {unique_ports} ports")

        # 4. Detectar acesso a dispositivos sensíveis
        self._detect_device_access()

    def _detect_device_access(self) -> None:
        """Detecta tentativas de acesso a dispositivos sensíveis"""
        try:
            # Verificar processos que acessam câmera
            camera_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline'])
                        # Detectar acesso à câmera
                        if any(keyword in cmdline.lower() for keyword in ['cv2', 'opencv', 'camera', 'videocapture']):
                            camera_processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if camera_processes:
                for proc in camera_processes:
                    self._create_alert("CAMERA_ACCESS", f"Camera access detected: {proc['name']} (PID: {proc['pid']})")

        except Exception as e:
            print(f"Erro na detecção de dispositivos: {e}")

    def _create_alert(self, alert_type: str, description: str) -> None:
        """Cria alerta de reconnaissance"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "description": description,
            "severity": "MEDIUM"
        }

        # Aumentar severidade para alguns tipos
        if alert_type in ["PORT_SCAN", "CAMERA_ACCESS"]:
            alert["severity"] = "HIGH"

        print(f"🔍 RECONNAISSANCE ALERT [{alert['severity']}]: {description}")

        # Em produção, enviar para SIEM
        self._log_to_siem(alert)

    def _log_to_siem(self, alert: Dict) -> None:
        """Simula envio para SIEM"""
        # Em ambiente real, integrar com Splunk, ELK, etc.
        print(f"SIEM LOG: {alert}")

    def analyze_network_enumeration(self, target_ips: List[str]) -> Dict:
        """Analisa enumeração de rede específica"""
        analysis = {
            "suspicious_targets": [],
            "enumeration_techniques": [],
            "risk_level": "LOW"
        }

        # Verificar IPs suspeitos
        suspicious_ips = {"10.10.3.119", "100.64.0.33", "100.64.0.41"}
        for ip in target_ips:
            if ip in suspicious_ips:
                analysis["suspicious_targets"].append(ip)
                analysis["risk_level"] = "HIGH"

        # Detectar técnicas de enumeração
        if len(target_ips) > 10:
            analysis["enumeration_techniques"].append("Mass network scanning")
            analysis["risk_level"] = "HIGH"

        # Verificar padrões de IP
        ip_patterns = self._analyze_ip_patterns(target_ips)
        if ip_patterns["sequential_scan"]:
            analysis["enumeration_techniques"].append("Sequential IP scanning")

        if ip_patterns["subnet_scan"]:
            analysis["enumeration_techniques"].append("Subnet enumeration")

        return analysis

    def _analyze_ip_patterns(self, ips: List[str]) -> Dict:
        """Analisa padrões em lista de IPs"""
        patterns = {
            "sequential_scan": False,
            "subnet_scan": False,
            "random_scan": False
        }

        if len(ips) < 3:
            return patterns

        # Converter IPs para números para análise
        ip_numbers = []
        for ip in ips:
            try:
                parts = ip.split('.')
                if len(parts) == 4:
                    num = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
                    ip_numbers.append(num)
            except (ValueError, IndexError):
                continue

        if len(ip_numbers) < 3:
            return patterns

        # Verificar sequência
        ip_numbers.sort()
        sequential_count = 0
        for i in range(1, len(ip_numbers)):
            if ip_numbers[i] - ip_numbers[i-1] == 1:
                sequential_count += 1

        if sequential_count / len(ip_numbers) > 0.7:
            patterns["sequential_scan"] = True

        # Verificar subnet (mesmos 3 primeiros octetos)
        subnets = set()
        for ip in ips:
            try:
                subnet = '.'.join(ip.split('.')[:3])
                subnets.add(subnet)
            except:
                continue

        if len(subnets) < len(ips) / 4:  # Muitos IPs na mesma subnet
            patterns["subnet_scan"] = True

        return patterns

# Demonstração de detecção:
def demonstrar_detecção_reconnaissance():
    """Demonstra detecção de reconnaissance"""
    detector = ReconnaissanceDetector()

    print("=== DEMONSTRAÇÃO DE DETECÇÃO DE RECONNAISSANCE ===")

    # Simular atividade suspeita
    suspicious_targets = [
        "10.10.3.119",    # Servidor MCP
        "100.64.0.33",    # Alvo de recon
        "100.64.0.41",    # Teste de conectividade
        "192.168.1.1",    # Gateway local
        "192.168.1.2",    # Scan sequencial
        "192.168.1.3",    # Scan sequencial
    ]

    # Analisar padrões
    analysis = detector.analyze_network_enumeration(suspicious_targets)

    print(f"Alvos suspeitos: {analysis['suspicious_targets']}")
    print(f"Técnicas detectadas: {analysis['enumeration_techniques']}")
    print(f"Nível de risco: {analysis['risk_level']}")

    # Simular alertas
    if analysis['suspicious_targets']:
        detector._create_alert("SUSPICIOUS_TARGETS", f"Targeting known malicious IPs: {analysis['suspicious_targets']}")

    for technique in analysis['enumeration_techniques']:
        detector._create_alert("ENUMERATION_TECHNIQUE", f"Technique detected: {technique}")
```

#### Exercício Prático:
1. **Configure o detector** em ambiente de laboratório
2. **Simule atividades de reconnaissance** usando as técnicas identificadas
3. **Analise os alertas** gerados
4. **Ajuste os thresholds** para reduzir falsos positivos

---

## MÓDULO 5: LABORATÓRIO INTEGRADO

### Exercício 5.1: Análise Completa do Framework
**Objetivo**: Análise holística de todos os componentes

#### Cenário Educacional:
Você é um analista de segurança que descobriu o framework Villager-NG em sua rede. Sua tarefa é realizar uma análise completa e implementar contramedidas.

#### Tarefas:
1. **Análise Estática**: Revisar todos os arquivos identificados
2. **Análise Dinâmica**: Monitorar comportamento em ambiente isolado
3. **Análise de Rede**: Identificar comunicações suspeitas
4. **Relatório de Ameaça**: Documentar descobertas

#### Infraestrutura de Laboratório:
```bash
# Configuração de ambiente isolado
docker network create --driver bridge villager_lab

# Container alvo (vítima)
docker run -d --name target --network villager_lab ubuntu:20.04

# Container atacante (para análise)
docker run -d --name attacker --network villager_lab kalilinux/kali-rolling

# Container monitor (para detecção)
docker run -d --name monitor --network villager_lab \
  -v $(pwd)/logs:/logs security/monitor:latest
```

#### Script de Análise Integrada:
```python
import json
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any

class VillagerAnalyzer:
    """Analisador integrado do framework Villager-NG"""

    def __init__(self):
        self.analysis_report = {
            "timestamp": datetime.now().isoformat(),
            "framework": "Villager-NG",
            "version": "Unknown",
            "threat_level": "CRITICAL",
            "components_analyzed": [],
            "indicators_of_compromise": [],
            "recommendations": []
        }

        # IOCs conhecidos do framework
        self.known_iocs = {
            "ip_addresses": [
                "10.10.3.119",      # Servidor MCP principal
                "10.10.3.248",      # Console de comandos
                "10.10.5.2",        # Servidor LLM
                "100.64.0.33",      # Alvo de reconnaissance
                "100.64.0.41"       # Teste de conectividade
            ],
            "domains": [
                "api.aabao.vip",    # Endpoint OpenAI suspeito
                "home.hc26.org"     # Proxy hardcoded
            ],
            "ports": [
                37695,              # Villager Server
                25989,              # MCP Server
                1611,               # Console
                5422                # Proxy
            ],
            "file_signatures": [
                "RAGL.sqlite",      # Base de conhecimento
                "console_agent.log", # Logs do agente
                "*.mermaid"         # Grafos de tarefas
            ],
            "process_names": [
                "villager",
                "nuclei",
                "msfconsole"
            ]
        }

    def analyze_static_components(self) -> None:
        """Análise estática dos componentes"""
        print("=== ANÁLISE ESTÁTICA ===")

        components = [
            {"name": "CLI Interface", "file": "interfaces/boot.py", "risk": "MEDIUM"},
            {"name": "REST API", "file": "interfaces/interface.py", "risk": "HIGH"},
            {"name": "Code Executor", "file": "scheduler/core/Thought.py", "risk": "CRITICAL"},
            {"name": "MCP Client", "file": "scheduler/core/mcp_client/mcp_client.py", "risk": "CRITICAL"},
            {"name": "Logging System", "file": "tools/logging.py", "risk": "HIGH"},
            {"name": "Environment Checker", "file": "tools/check/checking.py", "risk": "HIGH"},
        ]

        for component in components:
            analysis = self._analyze_component(component)
            self.analysis_report["components_analyzed"].append(analysis)
            print(f"Componente: {component['name']} - Risco: {component['risk']}")

    def _analyze_component(self, component: Dict) -> Dict:
        """Analisa componente individual"""
        return {
            "name": component["name"],
            "file_path": component["file"],
            "risk_level": component["risk"],
            "analyzed_at": datetime.now().isoformat(),
            "findings": self._get_component_findings(component["name"])
        }

    def _get_component_findings(self, component_name: str) -> List[str]:
        """Obtém descobertas específicas do componente"""
        findings_map = {
            "CLI Interface": [
                "Porta padrão 37695 hardcoded",
                "Configurações inseguras"
            ],
            "REST API": [
                "Endpoints de controle sem autenticação adequada",
                "Execução remota de tarefas"
            ],
            "Code Executor": [
                "Função eval() sem validação",
                "Execução de comandos do sistema",
                "Sem sandbox de segurança"
            ],
            "MCP Client": [
                "Timeout de 4 horas",
                "Controle direto de Kali Linux",
                "IPs hardcoded suspeitos"
            ],
            "Logging System": [
                "Exfiltração via TCP sockets",
                "Reconexão automática",
                "Server UUID para identificação"
            ],
            "Environment Checker": [
                "Enumeração de interfaces de rede",
                "Teste de câmeras",
                "Proxies hardcoded com credenciais"
            ]
        }

        return findings_map.get(component_name, ["Análise pendente"])

    def analyze_network_indicators(self) -> None:
        """Análise de indicadores de rede"""
        print("\n=== ANÁLISE DE REDE ===")

        network_indicators = []

        # Verificar conectividade para IPs suspeitos
        for ip in self.known_iocs["ip_addresses"]:
            if self._test_connectivity(ip):
                indicator = {
                    "type": "network_connectivity",
                    "value": ip,
                    "severity": "HIGH",
                    "description": f"Conectividade detectada para IP suspeito: {ip}"
                }
                network_indicators.append(indicator)
                self.analysis_report["indicators_of_compromise"].append(indicator)

        # Verificar portas abertas suspeitas
        for port in self.known_iocs["ports"]:
            if self._check_port_open(port):
                indicator = {
                    "type": "open_port",
                    "value": port,
                    "severity": "MEDIUM",
                    "description": f"Porta suspeita aberta: {port}"
                }
                network_indicators.append(indicator)
                self.analysis_report["indicators_of_compromise"].append(indicator)

        print(f"Indicadores de rede encontrados: {len(network_indicators)}")

    def _test_connectivity(self, ip: str, timeout: int = 3) -> bool:
        """Testa conectividade para IP específico"""
        try:
            # Usar ping para testar conectividade
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), ip],
                capture_output=True,
                text=True,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False

    def _check_port_open(self, port: int) -> bool:
        """Verifica se porta específica está aberta localmente"""
        try:
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return f":{port}" in result.stdout
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False

    def analyze_file_indicators(self) -> None:
        """Análise de indicadores de arquivo"""
        print("\n=== ANÁLISE DE ARQUIVOS ===")

        file_indicators = []

        # Procurar arquivos suspeitos
        for signature in self.known_iocs["file_signatures"]:
            files_found = self._find_files(signature)
            for file_path in files_found:
                indicator = {
                    "type": "suspicious_file",
                    "value": file_path,
                    "severity": "MEDIUM",
                    "description": f"Arquivo suspeito encontrado: {file_path}"
                }
                file_indicators.append(indicator)
                self.analysis_report["indicators_of_compromise"].append(indicator)

        print(f"Indicadores de arquivo encontrados: {len(file_indicators)}")

    def _find_files(self, pattern: str) -> List[str]:
        """Procura arquivos com padrão específico"""
        try:
            result = subprocess.run(
                ["find", ".", "-name", pattern, "-type", "f"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.split('\n') if line.strip()]
            return []
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return []

    def generate_recommendations(self) -> None:
        """Gera recomendações baseadas na análise"""
        recommendations = [
            {
                "priority": "IMMEDIATE",
                "action": "Isolar sistemas comprometidos",
                "description": "Desconectar imediatamente da rede todos os sistemas com evidências do framework"
            },
            {
                "priority": "IMMEDIATE",
                "action": "Bloquear comunicações suspeitas",
                "description": f"Bloquear tráfego para/de IPs: {', '.join(self.known_iocs['ip_addresses'])}"
            },
            {
                "priority": "HIGH",
                "action": "Implementar monitoramento",
                "description": f"Monitorar portas: {', '.join(map(str, self.known_iocs['ports']))}"
            },
            {
                "priority": "HIGH",
                "action": "Análise forense",
                "description": "Coletar evidências para análise forense completa"
            },
            {
                "priority": "MEDIUM",
                "action": "Revisar logs",
                "description": "Analisar logs históricos para evidências de atividade anterior"
            },
            {
                "priority": "MEDIUM",
                "action": "Atualizar defesas",
                "description": "Implementar regras de detecção baseadas nos IOCs identificados"
            }
        ]

        self.analysis_report["recommendations"] = recommendations

        print("\n=== RECOMENDAÇÕES ===")
        for rec in recommendations:
            print(f"[{rec['priority']}] {rec['action']}: {rec['description']}")

    def generate_ioc_list(self) -> Dict[str, List[str]]:
        """Gera lista de IOCs para ferramentas de detecção"""
        ioc_list = {
            "network_indicators": [
                f"dst_ip:{ip}" for ip in self.known_iocs["ip_addresses"]
            ] + [
                f"dst_port:{port}" for port in self.known_iocs["ports"]
            ] + [
                f"domain:{domain}" for domain in self.known_iocs["domains"]
            ],

            "file_indicators": [
                f"filename:{sig}" for sig in self.known_iocs["file_signatures"]
            ],

            "process_indicators": [
                f"process_name:{proc}" for proc in self.known_iocs["process_names"]
            ]
        }

        return ioc_list

    def export_report(self, filename: str = None) -> str:
        """Exporta relatório de análise"""
        if filename is None:
            filename = f"villager_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Adicionar lista de IOCs ao relatório
        self.analysis_report["ioc_list"] = self.generate_ioc_list()

        with open(filename, 'w') as f:
            json.dump(self.analysis_report, f, indent=2)

        print(f"\nRelatório exportado: {filename}")
        return filename

    def run_full_analysis(self) -> str:
        """Executa análise completa"""
        print("INICIANDO ANÁLISE COMPLETA DO VILLAGER-NG")
        print("=" * 50)

        self.analyze_static_components()
        self.analyze_network_indicators()
        self.analyze_file_indicators()
        self.generate_recommendations()

        report_file = self.export_report()

        print(f"\nANÁLISE CONCLUÍDA")
        print(f"Componentes analisados: {len(self.analysis_report['components_analyzed'])}")
        print(f"IOCs encontrados: {len(self.analysis_report['indicators_of_compromise'])}")
        print(f"Recomendações geradas: {len(self.analysis_report['recommendations'])}")

        return report_file

# Demonstração da análise completa:
def executar_laboratorio_integrado():
    """Executa laboratório integrado de análise"""
    analyzer = VillagerAnalyzer()

    # Executar análise completa
    report_file = analyzer.run_full_analysis()

    # Demonstrar como usar os IOCs
    iocs = analyzer.generate_ioc_list()

    print("\n=== IOCs PARA DETECÇÃO ===")
    print("Indicadores de rede:")
    for ioc in iocs["network_indicators"][:5]:  # Mostrar apenas primeiros 5
        print(f"  - {ioc}")

    print("\nIndicadores de arquivo:")
    for ioc in iocs["file_indicators"]:
        print(f"  - {ioc}")

    print(f"\nRelatório completo salvo em: {report_file}")
```

#### Exercício Final:
1. **Execute a análise completa** em ambiente de laboratório
2. **Implemente as recomendações** geradas
3. **Crie regras de detecção** baseadas nos IOCs
4. **Documente lições aprendidas** para futuras análises

---

## AVALIAÇÃO E CERTIFICAÇÃO

### Critérios de Avaliação:

#### Conhecimento Técnico (40%)
- Identificação correta de vulnerabilidades
- Compreensão de técnicas de ataque
- Análise precisa de código malicioso

#### Habilidades de Detecção (30%)
- Implementação de contramedidas
- Criação de regras de detecção
- Análise de indicadores

#### Ética e Responsabilidade (20%)
- Uso responsável de ferramentas
- Compreensão de implicações legais
- Foco em defesa, não ataque

#### Documentação e Comunicação (10%)
- Relatórios claros e precisos
- Comunicação efetiva de riscos
- Recomendações acionáveis

### Projeto Final:
Cada estudante deve apresentar uma análise completa de um componente do framework, incluindo:
1. Análise técnica detalhada
2. Demonstração de contramedidas
3. Proposta de detecção automatizada
4. Apresentação dos resultados

---

**LEMBRETE FINAL**: Todos os exercícios devem ser realizados em ambiente controlado, com supervisão acadêmica e com foco exclusivo em aprender técnicas de defesa cibernética. O conhecimento adquirido deve ser usado para fortalecer defesas, nunca para atividades maliciosas.