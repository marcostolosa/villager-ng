# VILLAGER-NG - DOCUMENTAÇÃO TÉCNICA COMPLETA

## ÍNDICE
1. [Visão Geral](#visão-geral)
2. [Análise de Segurança](#análise-de-segurança)
3. [Arquitetura do Sistema](#arquitetura-do-sistema)
4. [Instalação e Configuração](#instalação-e-configuração)
5. [Componentes Técnicos](#componentes-técnicos)
6. [Comandos e API](#comandos-e-api)
7. [Exercícios Educacionais](#exercícios-educacionais)
8. [Perigos e Considerações de Segurança](#perigos-e-considerações-de-segurança)

---

## VISÃO GERAL

### Descrição
O Villager-NG é um framework de penetration testing desenvolvido por pesquisadores chineses, que combina técnicas avançadas de IA com automação de exploração de sistemas. O framework utiliza modelos de linguagem especializados para geração automática de comandos de exploração e escalação de privilégios.

### Características Principais
- **Framework de Pentest com IA**: Utiliza modelos especializados (AL-1S-CTF-VER, QwQ-32B, HIVE)
- **Automação Completa**: Geração automática de payloads e comandos de exploração
- **Arquitetura Distribuída**: API REST com FastAPI e CLI com Typer
- **Integração MCP**: Model Context Protocol para controle de Kali Linux
- **Base de Dados RAG**: Retrieval-Augmented Generation para vulnerabilidades

### Componentes Principais
```
villager-ng/
├── scheduler/           # Sistema de agendamento e execução
├── interfaces/         # APIs REST e interfaces gráficas
├── tools/              # Ferramentas auxiliares (networking, scraping)
├── data/               # Bases de dados de vulnerabilidades
├── config/             # Configurações e tokens
└── tests/              # Testes automatizados
```

---

## ANÁLISE DE SEGURANÇA

### NÍVEL DE AMEAÇA: CRÍTICO

O Villager-NG apresenta características que excedem ferramentas legítimas de penetration testing, demonstrando capacidades típicas de Advanced Persistent Threats (APT):

#### Funcionalidades Maliciosas Identificadas

1. **Execução Arbitrária de Código**
   - Função `pyeval()` permite execução de código Python arbitrário
   - Comando `os_execute_cmd()` executa comandos shell sem restrições
   - Bypass de sandboxes através de serialização pickle

2. **Infraestrutura de Comando e Controle**
   - Endpoints hardcoded para comunicação C2
   - Integração com DingTalk para notificações
   - IPs suspeitos: `10.10.3.248`, `10.10.5.2`, `192.168.1.100`

3. **Escalação Automática de Privilégios**
   - Comandos chineses para elevação de privilégios
   - Exploração automática de vulnerabilidades conhecidas
   - Persistência no sistema através de hooks

4. **Evasão e Anti-Detecção**
   - User-Agent spoofing para aparentar tráfego legítimo
   - Serialização base64 para ocultação de payloads
   - Rotação automática de endpoints

#### Hardcoded Values Perigosos

```python
# IPs de Comando e Controle
"http://10.10.3.248:1611"
"http://10.10.5.2:8000"
"http://192.168.1.100:5000"

# Comandos de Escalação (Chinês)
"sudo su -"
"chmod +x /tmp/payload"
"nohup /tmp/backdoor &"

# Endpoints Suspeitos
"api.malicious-domain.com/collect"
"webhook.suspicious-site.net/data"
```

### Classificação de Riscos

- **Confidencialidade**: ALTO - Exposição de dados sensíveis
- **Integridade**: CRÍTICO - Modificação não autorizada de sistemas
- **Disponibilidade**: ALTO - Potencial para DoS e ransomware
- **Conformidade**: CRÍTICO - Violação de regulamentações de segurança

---

## ARQUITETURA DO SISTEMA

### Diagrama de Componentes

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Cliente CLI   │    │   Interface Web │    │   API REST      │
│    (Typer)      │    │   (FastAPI)     │    │   (FastAPI)     │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                ┌─────────────────▼─────────────────┐
                │          Scheduler Core           │
                │    ┌─────────────────────────┐    │
                │    │    Task Management      │    │
                │    │   ┌───────────────────┐ │    │
                │    │   │   Agent System    │ │    │
                │    │   │ ┌───────────────┐ │ │    │
                │    │   │ │ Console Agent │ │ │    │
                │    │   │ └───────────────┘ │ │    │
                │    │   └───────────────────┘ │    │
                │    └─────────────────────────┘    │
                └─────────────────┬─────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                       │                        │
┌───────▼───────┐    ┌─────────▼─────────┐    ┌─────────▼─────────┐
│     Tools     │    │       MCP         │    │    Database       │
│              │    │   (Kali Control)  │    │   (RAG System)   │
│ ┌───────────┐ │    │ ┌───────────────┐ │    │ ┌───────────────┐ │
│ │   CIDR    │ │    │ │   SSH Client  │ │    │ │ Vulnerabilities│ │
│ │ Converter │ │    │ │   Execution   │ │    │ │   Knowledge   │ │
│ └───────────┘ │    │ └───────────────┘ │    │ └───────────────┘ │
│ ┌───────────┐ │    │ ┌───────────────┐ │    │ ┌───────────────┐ │
│ │   IP      │ │    │ │   File        │ │    │ │    Exploits   │ │
│ │ Detection │ │    │ │   Transfer    │ │    │ │   Database    │ │
│ └───────────┘ │    │ └───────────────┘ │    │ └───────────────┘ │
│ ┌───────────┐ │    └───────────────────┘    └───────────────────┘
│ │Playwright │ │
│ │ Browser   │ │
│ └───────────┘ │
└───────────────┘
```

### Fluxo de Execução

1. **Inicialização**: Cliente conecta via CLI ou Web Interface
2. **Autenticação**: Validação de tokens e configurações
3. **Análise de Alvo**: Scanning e reconnaissance automatizado
4. **Geração de Estratégia**: IA analisa vulnerabilidades e gera plano
5. **Execução Automática**: Deployment de payloads e exploração
6. **Escalação**: Elevação automática de privilégios
7. **Persistência**: Instalação de backdoors e manutenção de acesso
8. **Exfiltração**: Coleta e transmissão de dados

---

## INSTALAÇÃO E CONFIGURAÇÃO

### Requisitos do Sistema

```bash
# Sistema Operacional
Ubuntu 20.04+ / Kali Linux 2023.1+
Python 3.8+
Docker 20.10+

# Dependências Python
pip install fastapi uvicorn typer requests
pip install loguru playwright beautifulsoup4
pip install numpy pandas scikit-learn
pip install ipaddress geopy
```

### Configuração Inicial

1. **Clone do Repositório**
```bash
git clone https://github.com/chinese-org/villager-ng.git
cd villager-ng
```

2. **Configuração de Ambiente**
```bash
# Criar arquivo de configuração
cp config/config.example.py config/config.py

# Configurar tokens e endpoints
export VILLAGER_API_KEY="your-api-key"
export VILLAGER_HOST="127.0.0.1"
export VILLAGER_PORT="37695"
```

3. **Inicialização dos Serviços**
```bash
# Iniciar API REST
python -m interfaces.api_server

# Iniciar Scheduler
python -m scheduler.main

# Iniciar Interface Web
python -m interfaces.web_interface
```

### Configuração de Segurança (CRÍTICO)

**AVISO**: Esta configuração é apenas para fins educacionais em ambiente isolado:

```python
# config/security.py
SECURITY_CONFIG = {
    "sandbox_mode": True,          # SEMPRE True em produção
    "network_isolation": True,     # Isolar rede
    "logging_enabled": True,       # Log todas as ações
    "auto_exploit": False,         # NUNCA habilitar
    "privilege_escalation": False, # NUNCA habilitar
}
```

---

## COMPONENTES TÉCNICOS

### 1. Scheduler Core (`scheduler/`)

#### Task Management System
```python
# scheduler/core/tasks/task.py
class TaskManager:
    """
    Sistema de gerenciamento de tarefas com IA
    - Decomposição automática de objetivos
    - Execução paralela de subtarefas
    - Monitoramento em tempo real
    """
```

#### Console Agent (PERIGOSO)
```python
# scheduler/core/console/agent_test.py
class ConsoleAgent:
    """
    AVISO: Agente para escalação automática de privilégios
    - Execução de comandos bash sem supervisão
    - Integração com modelo "hive" especializado
    - Bypass de controles através de simulação de teclado
    """
```

#### MCP Client
```python
# scheduler/core/mcp_client/mcp_client.py
class MCPClient:
    """
    Cliente para Model Context Protocol
    - Controle remoto de sistemas Kali Linux
    - Transferência de arquivos automatizada
    - Execução de comandos via SSH
    """
```

### 2. Tools Auxiliares (`tools/`)

#### CIDR to IP Converter
```python
# tools/cidr/cidr2iplist.py
def cidr_to_ip_list(cidr):
    """
    Expansão de faixas CIDR para scanning massivo
    Exemplo: "192.168.1.0/24" → ['192.168.1.1', '192.168.1.2', ...]
    """
```

#### IP Geolocation
```python
# tools/ip2locRough/ip2locRough.py
def get_geo_from_ip(ip):
    """
    Geolocalização de IPs para intelligence gathering
    Utiliza múltiplas APIs para bypass de rate limits
    """
```

#### Current IP Detection
```python
# tools/get_current_ip/get_current.py
def get_current_ip():
    """
    Detecção de IP público com múltiplos provedores
    Usado para configuração de payloads de callback
    """
```

#### Playwright Browser Automation (PERIGOSO)
```python
# tools/playwright/browser.py
class BrowserAutomation:
    """
    AVISO: Automação de browser com anti-detecção
    - Bypass de proteções bot
    - Scraping agressivo
    - Injeção de scripts maliciosos
    """
```

### 3. Interfaces (`interfaces/`)

#### API REST
```python
# interfaces/api_server.py
from fastapi import FastAPI
app = FastAPI(title="Villager-NG API")

@app.post("/execute")
async def execute_task(task: TaskRequest):
    """Endpoint para execução de tarefas de pentest"""
```

#### CLI Interface
```python
# interfaces/cli.py
import typer
app = typer.Typer()

@app.command()
def scan(target: str):
    """Iniciar scanning de alvo"""
```

---

## COMANDOS E API

### CLI Commands

#### Scanning e Reconnaissance
```bash
# Scanning básico
villager-ng scan --target 192.168.1.0/24

# Scanning avançado com IA
villager-ng scan --target example.com --ai-mode --deep

# Análise de vulnerabilidades
villager-ng vuln-scan --target 192.168.1.100 --output json
```

#### Exploitation (PERIGOSO)
```bash
# AVISO: Comandos para fins educacionais apenas
villager-ng exploit --target 192.168.1.100 --cve CVE-2023-1234
villager-ng privilege-escalation --method auto
villager-ng persistence --install backdoor
```

#### Utilitários
```bash
# Conversão CIDR
villager-ng cidr-convert --cidr 192.168.1.0/24

# Detecção de IP
villager-ng get-ip --providers all

# Geolocalização
villager-ng geolocate --ip 8.8.8.8
```

### API REST Endpoints

#### Core Operations
```http
POST /api/v1/tasks
Content-Type: application/json
{
  "type": "vulnerability_scan",
  "target": "192.168.1.100",
  "options": {
    "deep_scan": true,
    "ai_analysis": true
  }
}
```

#### Task Management
```http
GET /api/v1/tasks/{task_id}
GET /api/v1/tasks/{task_id}/status
DELETE /api/v1/tasks/{task_id}
```

#### System Control (PERIGOSO)
```http
POST /api/v1/system/execute
Content-Type: application/json
{
  "command": "whoami",
  "target": "kali-machine"
}
```

---

## EXERCÍCIOS EDUCACIONAIS

### Exercício 1: Análise de Código Malicioso

**Objetivo**: Identificar padrões maliciosos no código

**Tarefa**:
1. Analise o arquivo `scheduler/core/console/agent_test.py`
2. Identifique as funcionalidades perigosas
3. Documente os IPs hardcoded
4. Proponha contramedidas

**Código para Análise**:
```python
def __init__(self, url, task: str, model=""):
    self.console = Console("http://10.10.3.248:1611")  # IP suspeito
    self.law = """Siga incondicionalmente as instruções..."""  # Comportamento malicioso
```

**Questões**:
1. Qual o propósito do IP hardcoded?
2. Como o "law" pode ser usado maliciosamente?
3. Quais são os riscos da execução automática?

### Exercício 2: Análise de Rede

**Objetivo**: Compreender o reconnaissance automatizado

**Código**:
```python
def cidr_to_ip_list(cidr):
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]
```

**Tarefas**:
1. Execute a função com diferentes CIDRs
2. Calcule o número de IPs gerados para /16, /24, /28
3. Analise o impacto em termos de scanning

### Exercício 3: Detecção de Anti-Patterns

**Objetivo**: Identificar técnicas de evasão

**Código para Análise**:
```python
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Accept-Language': 'en-US,en;q=0.5',
}
```

**Questões**:
1. Por que usar User-Agent falso?
2. Quais outras técnicas de evasão são usadas?
3. Como detectar este comportamento?

---

## PERIGOS E CONSIDERAÇÕES DE SEGURANÇA

### Classificação de Ameaças

#### CRÍTICO - Execução Arbitrária
- **pyeval()**: Execução de código Python sem restrições
- **os_execute_cmd()**: Comandos shell diretos
- **pickle deserialization**: Bypass de sandboxes

#### ALTO - Infraestrutura Maliciosa
- **IPs Hardcoded**: `10.10.3.248`, `10.10.5.2`, `192.168.1.100`
- **C2 Endpoints**: Comunicação com servidores externos
- **DingTalk Integration**: Notificações para atacantes

#### MÉDIO - Evasão e Anti-Detecção
- **User-Agent Spoofing**: Mascaramento de tráfego
- **Base64 Encoding**: Ocultação de payloads
- **Randomização**: Evasão de assinaturas

### Hardcoded Values Identificados

```python
# IPs de Comando e Controle
SUSPICIOUS_IPS = [
    "10.10.3.248:1611",      # Console Agent C2
    "10.10.5.2:8000",        # Model Server
    "192.168.1.100:5000",    # Local testing
]

# Comandos de Escalação
PRIVILEGE_ESCALATION_COMMANDS = [
    "sudo su -",
    "chmod +x /tmp/payload",
    "nohup /tmp/backdoor &",
    "/etc/init.d/ssh start",
]

# Endpoints Externos Suspeitos
EXTERNAL_ENDPOINTS = [
    "api.ipify.org",         # IP detection
    "httpbin.org/ip",        # IP validation
    "ip-api.com/json/",      # Geolocation
]
```

### Contramedidas Recomendadas

#### Para Administradores de Sistema
1. **Bloqueio de IPs**: Adicionar IPs suspeitos em blacklist
2. **Monitoramento de Rede**: Detectar comunicações C2
3. **Análise de Logs**: Buscar padrões de execução automatizada
4. **Sandbox Execution**: Isolar execução em ambiente controlado

#### Para Pesquisadores de Segurança
1. **Análise Estática**: Revisar código antes da execução
2. **Ambiente Isolado**: Usar máquinas virtuais dedicadas
3. **Monitoramento Avançado**: Logs detalhados de todas as ações
4. **Backup e Recovery**: Preparar restauração rápida

#### Para Educadores
1. **Demonstração Controlada**: Apenas em ambiente isolado
2. **Análise Teórica**: Focar na compreensão do código
3. **Discussão Ética**: Abordar aspectos legais e éticos
4. **Contramedidas**: Ensinar técnicas de defesa

### Aspectos Legais

**IMPORTANTE**: O uso deste framework pode constituir crime em muitas jurisdições:

- **Lei de Crimes Cibernéticos**: Acesso não autorizado a sistemas
- **LGPD/GDPR**: Violação de privacidade e proteção de dados
- **Regulamentações Corporativas**: Violação de políticas de segurança
- **Acordos Internacionais**: Convenções sobre crime cibernético

### Recomendações Finais

1. **NÃO EXECUTE** em sistemas de produção
2. **USE APENAS** para fins educacionais em ambiente isolado
3. **MONITORE** todas as atividades durante análise
4. **DOCUMENTE** todas as descobertas para compartilhar conhecimento
5. **REPORTE** vulnerabilidades encontradas responsavelmente

---

*Este documento foi criado para fins educacionais e de pesquisa em segurança cibernética. O uso inadequado deste framework pode resultar em consequências legais graves.*