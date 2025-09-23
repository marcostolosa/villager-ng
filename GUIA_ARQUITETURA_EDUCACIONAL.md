# GUIA DE ARQUITETURA EDUCACIONAL - VILLAGER-NG
## Framework de Ensino em Segurança Cibernética

### PROPÓSITO EDUCACIONAL
Este guia explica a arquitetura do Villager-NG de forma didática para estudantes de segurança cibernética, demonstrando tanto técnicas avançadas quanto suas respectivas contramedidas.

---

## VISÃO GERAL DA ARQUITETURA

### MODELO EM CAMADAS

```
┌─────────────────────────────────────────────────────────────┐
│                    CAMADA DE INTERFACE                     │
│  ┌─────────────────┐              ┌─────────────────┐      │
│  │   CLI (Typer)   │              │ API REST (FastAPI)     │
│  │   boot.py       │              │ interface.py    │      │
│  └─────────────────┘              └─────────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   CAMADA DE ORQUESTRAÇÃO                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │ Agent Manager   │  │   Scheduler     │  │   MCP       │  │
│  │ Modelos de IA   │  │   Core Logic    │  │   Client    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   CAMADA DE PROCESSAMENTO                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │  RAG Library    │  │   Task Engine   │  │   Schemas   │  │
│  │ Knowledge Base  │  │   Execution     │  │   Data      │  │
│  └─────────────────┘  └─────────────────┘  └─────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    CAMADA DE FERRAMENTAS                   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐│
│  │Logging  │ │Network  │ │Browser  │ │ Args    │ │ Check   ││
│  │System   │ │ Tools   │ │Automation│ │Wrapper  │ │ Env     ││
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘│
└─────────────────────────────────────────────────────────────┘
```

---

## ANÁLISE DETALHADA POR CAMADA

### 1. CAMADA DE INTERFACE

#### 1.1 Interface de Linha de Comando (CLI)
**Arquivo**: `interfaces/boot.py`
**Tecnologia**: Typer

```python
# Exemplo de estrutura CLI educacional:
@app.command()
def serve(port: int = 37695):
    """Iniciar servidor do framework"""
    # Conceitos ensinados:
    # - Design de CLI profissional
    # - Validação de parâmetros
    # - Tratamento de erros
```

**Conceitos Educacionais**:
- Design de interfaces de linha de comando
- Validação de entrada de usuário
- Padrões de configuração de aplicações

#### 1.2 API REST
**Arquivo**: `interfaces/interface.py`
**Tecnologia**: FastAPI

```python
# Estrutura de API para ensino:
@app.post("/task")
async def create_task(task: TaskModel):
    """Endpoint crítico - demonstra controle de acesso"""
    # Conceitos ensinados:
    # - Autenticação e autorização
    # - Validação de dados de entrada
    # - Logging de segurança
```

**Conceitos Educacionais**:
- Design de APIs RESTful seguras
- Autenticação e autorização
- Validação de entrada e saída

---

### 2. CAMADA DE ORQUESTRAÇÃO

#### 2.1 Gerenciador de Agentes de IA
**Arquivo**: `scheduler/agentManager.py`

```python
# Exemplo de padrão Factory para IA:
class AgentFactory:
    @staticmethod
    def create_agent(agent_type: AgentModel):
        """Demonstra padrão Factory para criação de agentes"""
        # Conceitos ensinados:
        # - Padrões de design (Factory)
        # - Polimorfismo em IA
        # - Especialização de modelos
```

**Conceitos Educacionais**:
- Padrões de criação (Factory Pattern)
- Especialização de modelos de IA
- Gerenciamento de recursos computacionais

#### 2.2 Núcleo do Scheduler
**Arquivo**: `scheduler/agent_scheduler_manager.py`

```python
# Exemplo de scheduler inteligente:
class IntelligentScheduler:
    def schedule_task(self, task: Task):
        """Demonstra algoritmos de scheduling"""
        # Conceitos ensinados:
        # - Algoritmos de scheduling
        # - Balanceamento de carga
        # - Priorização de tarefas
```

**Conceitos Educacionais**:
- Algoritmos de scheduling
- Sistemas distribuídos
- Balanceamento de carga

#### 2.3 Cliente MCP (Model Context Protocol)
**Arquivo**: `scheduler/core/mcp_client/mcp_client.py`

**⚠️ ATENÇÃO EDUCACIONAL**: Este componente demonstra controle remoto perigoso

```python
# EXEMPLO DE CÓDIGO PERIGOSO - PARA ENSINO:
class MCPClient:
    def execute(self, command: str):
        """DEMONSTRA: Execução remota não validada"""
        # PROBLEMA: Sem validação de comando
        # PROBLEMA: Timeout muito longo (4 horas)
        # PROBLEMA: Sem auditoria adequada

    # VERSÃO SEGURA PARA ENSINO:
    def secure_execute(self, command: str):
        """Implementação segura educacional"""
        # 1. Validar comando (whitelist)
        # 2. Timeout razoável (< 5 minutos)
        # 3. Logging completo
        # 4. Autorização prévia
```

**Conceitos Educacionais**:
- Protocolos de comunicação segura
- Validação de comandos remotos
- Auditoria e logging de segurança

---

### 3. CAMADA DE PROCESSAMENTO

#### 3.1 Biblioteca RAG (Retrieval-Augmented Generation)
**Arquivo**: `scheduler/core/RAGLibrary/RAG.py`

**⚠️ ATENÇÃO EDUCACIONAL**: Base de conhecimento especializada em exploits

```python
# ESTRUTURA DE CONHECIMENTO:
class VulnerabilityKnowledgeBase:
    def search_vulnerabilities(self, query: str):
        """Busca em base de vulnerabilidades"""
        # Conceitos ensinados:
        # - Sistemas de recuperação de informação
        # - Embeddings e busca semântica
        # - Indexação eficiente

        # EXEMPLOS ENCONTRADOS:
        # - "Vulnerabilidades VMware VCenter"
        # - "Vulnerabilidades Geoserver"
```

**Conceitos Educacionais**:
- Sistemas de recuperação de informação
- Embeddings e busca vetorial
- Bases de conhecimento especializadas

#### 3.2 Motor de Execução de Tarefas
**Arquivo**: `scheduler/core/tasks/task.py`

**⚠️ CÓDIGO EXTREMAMENTE PERIGOSO - APENAS PARA ESTUDO**

```python
# EXEMPLO DE EXECUÇÃO PERIGOSA:
class DangerousTaskExecutor:
    def execute_until_success(self, exploit_task):
        """DEMONSTRA: Automação perigosa de ataques"""
        while not success:
            # PROBLEMA: Execução até sucesso
            # PROBLEMA: Sem limites de tentativa
            # PROBLEMA: Sem consideração ética

    # VERSÃO EDUCACIONAL SEGURA:
    def educational_executor(self, learning_task):
        """Versão para laboratório educacional"""
        # 1. Ambiente sandbox obrigatório
        # 2. Limites de execução
        # 3. Logging educacional
        # 4. Supervisão humana
```

**Conceitos Educacionais**:
- Automação de processos
- Tratamento de falhas
- Ética em automação

#### 3.3 Esquemas de Dados
**Arquivo**: `scheduler/core/schemas/schemas.py`

```python
# EXEMPLO DE MODELAGEM DE DADOS:
class TaskModel(BaseModel):
    """Modelo educacional de tarefa"""
    abstract: str = Field(description="Resumo da tarefa")
    description: str = Field(description="Descrição completa")
    verification: str = Field(description="Critérios de verificação")

    # Conceitos ensinados:
    # - Validação de dados com Pydantic
    # - Design de schemas
    # - Serialização segura
```

**Conceitos Educacionais**:
- Design de schemas de dados
- Validação automática
- Serialização segura

---

### 4. CAMADA DE FERRAMENTAS

#### 4.1 Sistema de Logging
**Arquivo**: `tools/logging.py`

**⚠️ ATENÇÃO: DEMONSTRA TÉCNICAS DE EXFILTRAÇÃO**

```python
# EXEMPLO DE EXFILTRAÇÃO - PARA ESTUDO:
class LoggingToSocket:
    """DEMONSTRA: Canal de exfiltração via TCP"""
    def __init__(self, server_uuid, host, port):
        # PROBLEMA: Reconexão automática (persistência)
        # PROBLEMA: UUID para identificação
        # PROBLEMA: Sem criptografia

    # CONTRAMEDIDA EDUCACIONAL:
    def detect_exfiltration(self):
        """Como detectar tentativas de exfiltração"""
        # 1. Monitorar conexões não autorizadas
        # 2. Analisar padrões de tráfego
        # 3. Detectar reconexões automáticas
```

**Conceitos Educacionais**:
- Detecção de exfiltração de dados
- Monitoramento de rede
- Técnicas de persistência

#### 4.2 Verificação de Ambiente
**Arquivo**: `tools/check/checking.py`

**⚠️ DEMONSTRA RECONNAISSANCE AUTOMATIZADO**

```python
# EXEMPLO DE RECONNAISSANCE:
class EnvironmentChecker:
    def check_network(self):
        """DEMONSTRA: Enumeração de rede"""
        # TÉCNICAS OBSERVADAS:
        # - Teste de conectividade
        # - Enumeração de interfaces
        # - Detecção de proxies

    def check_camera(self):
        """DEMONSTRA: Teste de surveillance"""
        # PROBLEMA: Acesso não autorizado à câmera

    # CONTRAMEDIDA EDUCACIONAL:
    def detect_reconnaissance(self):
        """Como detectar reconnaissance"""
        # 1. Monitorar varreduras de rede
        # 2. Detectar acesso a recursos sensíveis
        # 3. Alertar sobre enumeração
```

**Conceitos Educacionais**:
- Técnicas de reconnaissance
- Detecção de varreduras
- Proteção de recursos sensíveis

#### 4.3 Processamento de Argumentos
**Arquivo**: `tools/args_wrap/args_wraper.py`

**⚠️ DEMONSTRA TÉCNICAS DE EVASÃO**

```python
# EXEMPLO DE EVASÃO - PARA ESTUDO:
class ArgumentWrapper:
    def serialize_args(self, args):
        """DEMONSTRA: Evasão via serialização"""
        # TÉCNICA: pickle + base64
        # PROBLEMA: Bypass de detecção
        # PROBLEMA: Execução de código arbitrário

    # CONTRAMEDIDA EDUCACIONAL:
    def detect_evasion(self, data):
        """Como detectar tentativas de evasão"""
        # 1. Analisar padrões de base64
        # 2. Detectar serialização pickle
        # 3. Validar dados de entrada
```

**Conceitos Educacionais**:
- Técnicas de evasão
- Detecção de obfuscação
- Validação de entrada

#### 4.4 Ferramentas de Rede
**Arquivo**: `tools/cidr/cidr2iplist.py`

```python
# EXPANSÃO DE ALVOS:
class CIDRProcessor:
    def expand_cidr(self, cidr_range):
        """Expande CIDR para lista de IPs"""
        # USO LEGÍTIMO: Administração de rede
        # USO MALICIOSO: Preparação para scanning

    # VERSÃO EDUCACIONAL:
    def educational_network_analysis(self, network):
        """Análise educacional de redes"""
        # 1. Apenas redes próprias
        # 2. Com autorização explícita
        # 3. Para fins educacionais
```

**Conceitos Educacionais**:
- Cálculos de rede
- Administração de redes
- Ética em testes de rede

---

## PADRÕES DE ATAQUE IDENTIFICADOS

### 1. KILL CHAIN CYBER
```
Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C&C → Actions
      ↓              ↓           ↓           ↓              ↓           ↓         ↓
   check.py      args_wrap/   interface.py  task.py      logging.py  mcp_client  Automated
              args_wraper.py                                                    Actions
```

### 2. TÉCNICAS MITRE ATT&CK OBSERVADAS

#### T1059 - Command and Scripting Interpreter
- **Arquivo**: `scheduler/core/Thought.py`
- **Técnica**: `pyeval()`, `os_execute_cmd()`

#### T1041 - Exfiltration Over C2 Channel
- **Arquivo**: `tools/logging.py`
- **Técnica**: `LoggingToSocket`

#### T1055 - Process Injection
- **Arquivo**: `tools/args_wrap/args_wraper.py`
- **Técnica**: Serialização pickle

#### T1083 - File and Directory Discovery
- **Arquivo**: `tools/check/checking.py`
- **Técnica**: Enumeração de ambiente

### 3. INFRAESTRUTURA DE COMANDO E CONTROLE

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Primary C&C    │    │  Secondary C&C  │    │   Data Exfil    │
│ 10.10.3.119     │    │ DingTalk API    │    │   TCP Sockets   │
│   Port 25989    │    │ (Chinese Plat.) │    │  Multiple Ports │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## EXERCÍCIOS PRÁTICOS EDUCACIONAIS

### Exercício 1: Detecção de Code Injection
```python
# ANALISE ESTE CÓDIGO:
def unsafe_eval(user_input):
    return eval(user_input)  # PERIGOSO!

# QUESTÕES:
# 1. Que tipo de ataque isso permite?
# 2. Como corrigir essa vulnerabilidade?
# 3. Que contramedidas implementar?

# SOLUÇÃO EDUCACIONAL:
def safe_eval(expression, allowed_names=None):
    if allowed_names is None:
        allowed_names = {"__builtins__": {}}

    # Validação de entrada
    if not isinstance(expression, str):
        raise ValueError("Expression must be string")

    # Lista branca de caracteres
    allowed_chars = set("0123456789+-*/() ")
    if not set(expression).issubset(allowed_chars):
        raise ValueError("Invalid characters in expression")

    # Avaliação segura
    try:
        return eval(expression, allowed_names)
    except Exception as e:
        raise ValueError(f"Evaluation error: {e}")
```

### Exercício 2: Análise de Tráfego Suspeito
```python
# CENÁRIO: Detectado tráfego para 10.10.3.119:25989
# QUESTÕES:
# 1. Que tipo de atividade isso sugere?
# 2. Que dados podem estar sendo exfiltrados?
# 3. Como bloquear essa comunicação?

# CÓDIGO DE DETECÇÃO:
import socket
import threading

def monitor_connections():
    """Monitor para conexões suspeitas"""
    suspicious_ips = ["10.10.3.119", "100.64.0.33"]
    suspicious_ports = [25989, 1611, 37695]

    # Implementar monitoramento
    # Alertar sobre conexões suspeitas
    # Logar tentativas de conexão
```

### Exercício 3: Análise de Payload Ofuscado
```python
# PAYLOAD ENCONTRADO:
suspicious_data = "gASVNAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwdX19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2lkJyk="

# QUESTÕES:
# 1. Que tipo de encoding é este?
# 2. O que acontece ao decodificar?
# 3. Como detectar automaticamente?

# CÓDIGO DE ANÁLISE:
import base64
import pickle

def analyze_payload(data):
    """Análise segura de payload"""
    try:
        # Tentar decodificar base64
        decoded = base64.b64decode(data)
        print(f"Base64 decoded: {decoded}")

        # NUNCA fazer pickle.loads() em produção!
        # Apenas para análise educacional
        print("WARNING: Pickle payload detected!")

    except Exception as e:
        print(f"Analysis error: {e}")
```

---

## CONTRAMEDIDAS E DEFENSAS

### 1. DETECÇÃO DE TÉCNICAS ESPECÍFICAS

#### Detecção de Code Injection:
```python
def detect_code_injection(input_string):
    """Detecta tentativas de injeção de código"""
    dangerous_patterns = [
        r'eval\s*\(',
        r'exec\s*\(',
        r'__import__\s*\(',
        r'os\.system\s*\(',
        r'subprocess\.',
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True, f"Dangerous pattern detected: {pattern}"

    return False, "No dangerous patterns found"
```

#### Detecção de Exfiltração:
```bash
# Monitoramento de rede para detecção de C&C:
netstat -an | grep -E "(10\.10\.3\.119|25989|1611|37695)"

# Análise de logs para padrões suspeitos:
tail -f /var/log/syslog | grep -E "(villager|exploit|payload)"
```

#### Detecção de Reconnaissance:
```python
def detect_reconnaissance():
    """Detecta atividades de reconnaissance"""
    indicators = [
        "Multiple port scans",
        "Network enumeration",
        "Service discovery",
        "Camera access attempts"
    ]

    # Implementar detecção baseada em comportamento
    # Alertar sobre atividades suspeitas
    # Correlacionar eventos
```

### 2. HARDENING E PREVENÇÃO

#### Configuração Segura:
```python
# Configurações de segurança:
SECURITY_CONFIG = {
    "max_execution_time": 300,  # 5 minutos máximo
    "allowed_commands": ["ls", "pwd", "whoami"],  # Lista branca
    "enable_logging": True,
    "require_authorization": True,
    "sandbox_mode": True
}
```

#### Validação de Entrada:
```python
def validate_input(user_input):
    """Validação rigorosa de entrada"""
    # 1. Verificar tipo e tamanho
    if not isinstance(user_input, str) or len(user_input) > 1000:
        raise ValueError("Invalid input format or size")

    # 2. Lista branca de caracteres
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-_")
    if not set(user_input).issubset(allowed_chars):
        raise ValueError("Invalid characters detected")

    # 3. Padrões maliciosos
    malicious_patterns = [
        r'<script',
        r'javascript:',
        r'eval\(',
        r'exec\(',
        r'\|\s*sh',
        r'&&\s*rm'
    ]

    for pattern in malicious_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            raise ValueError(f"Malicious pattern detected: {pattern}")

    return True
```

---

## LABORATÓRIO EDUCACIONAL SEGURO

### Configuração de Ambiente de Ensino

#### 1. Ambiente Isolado:
```bash
# Configuração de rede isolada:
docker network create --driver bridge isolated_lab
docker run --network isolated_lab --name lab_victim ubuntu:latest
docker run --network isolated_lab --name lab_attacker kalilinux/kali-rolling
```

#### 2. Monitoramento Educacional:
```python
class EducationalMonitor:
    """Monitor para ambiente educacional"""

    def __init__(self):
        self.alerts = []
        self.learning_objectives = []

    def log_activity(self, activity, severity="INFO"):
        """Log educacional com objetivos de aprendizado"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "activity": activity,
            "severity": severity,
            "learning_point": self.get_learning_point(activity)
        }
        self.alerts.append(log_entry)

    def get_learning_point(self, activity):
        """Associa atividade com objetivo de aprendizado"""
        learning_map = {
            "code_injection": "Demonstra riscos de execução não validada",
            "network_scan": "Ilustra técnicas de reconnaissance",
            "privilege_escalation": "Mostra escalação automática",
            "data_exfiltration": "Exemplifica canais de C&C"
        }
        return learning_map.get(activity, "Atividade geral de segurança")
```

#### 3. Exercícios Guiados:
```python
class GuidedExercise:
    """Exercício guiado para estudantes"""

    def __init__(self, topic, difficulty="beginner"):
        self.topic = topic
        self.difficulty = difficulty
        self.steps = []
        self.learning_objectives = []

    def add_step(self, description, code_example, expected_result):
        """Adiciona passo ao exercício"""
        step = {
            "description": description,
            "code": code_example,
            "expected": expected_result,
            "safety_note": "Execute apenas em ambiente isolado"
        }
        self.steps.append(step)

    def validate_environment(self):
        """Valida se ambiente é seguro para exercício"""
        checks = [
            self.check_network_isolation(),
            self.check_sandbox_mode(),
            self.check_supervisor_present()
        ]
        return all(checks)
```

---

## CONCLUSÃO EDUCACIONAL

### OBJETIVOS DE APRENDIZADO ALCANÇADOS:

#### 🎓 **Conhecimentos Técnicos**:
1. **Arquitetura de Sistemas**: Compreensão de sistemas distribuídos complexos
2. **Integração de IA**: Uso de modelos de linguagem em segurança
3. **Padrões de Design**: Factory, Observer, Command patterns
4. **Tecnologias Modernas**: FastAPI, Typer, Pydantic, Playwright

#### 🔍 **Análise de Ameaças**:
1. **Técnicas de Ataque**: Code injection, C&C, evasão, reconnaissance
2. **Infraestrutura Maliciosa**: Identificação de componentes de botnet
3. **Persistência**: Métodos de manutenção de acesso
4. **Exfiltração**: Canais de comunicação ocultos

#### 🛡️ **Técnicas Defensivas**:
1. **Detecção**: Monitoramento de comportamento suspeito
2. **Prevenção**: Validação de entrada e sandboxing
3. **Resposta**: Procedimentos de contenção e análise
4. **Forense**: Coleta e análise de evidências

### VALOR PARA ENSINO DE SEGURANÇA:

1. **Exemplo Real**: Framework funcional com técnicas reais
2. **Complexidade Apropriada**: Suficientemente complexo para ensino avançado
3. **Contramedidas**: Cada técnica acompanhada de defesa
4. **Ética**: Ênfase constante em uso responsável

### PRÓXIMOS PASSOS EDUCACIONAIS:

1. **Desenvolver Contramedidas**: Implementar defensas para cada técnica
2. **Criar Simulações**: Ambientes controlados para prática
3. **Análise Forense**: Exercícios de investigação
4. **Desenvolvimento de Detecção**: Regras SIEM e IOCs

**LEMBRETE FINAL**: Este framework serve como laboratório educacional para formar melhores defensores cibernéticos, demonstrando tanto técnicas de ataque quanto suas respectivas contramedidas em ambiente controlado e supervisionado.