# VILLAGER-NG

Framework avançado de penetration testing com automação baseada em IA.

## DOCUMENTAÇÃO

- **[DOCUMENTAÇÃO COMPLETA](DOCUMENTACAO_COMPLETA.md)** - Guia técnico abrangente
- **[GUIA DE SEGURANÇA](GUIA_SEGURANCA.md)** - Análise de ameaças e contramedidas

## Visão Geral

**Villager-NG** é um framework automatizado de testes de penetração que utiliza IA para decomposição inteligente de ataques, execução autônoma de exploits e capacidades de pós-exploração. O sistema integra ferramentas como Nuclei, MSFConsole e controle direto de sistemas Kali Linux para automação completa de campanhas de pentest.

### Principais Funcionalidades

- **Automação de Ataques**: Execução automática de ferramentas como Nuclei, MSFConsole e exploits personalizados
- **Escalação de Privilégios**: Sistema automatizado para elevação de privilégios em sistemas comprometidos
- **Controle de Kali Linux**: Integração direta com distribuições de pentest via MCP (Model Context Protocol)
- **Base de Exploits**: RAG (Retrieval-Augmented Generation) otimizada para busca de vulnerabilidades e exploits
- **Command & Control**: Canais C&C via DingTalk e sockets TCP com reconexão automática
- **Evasão de Detecção**: Serialização base64+pickle, proxies e técnicas anti-forense
- **Reconhecimento Massivo**: Expansão CIDR, automação de browsers e geolocalização de alvos
- **Persistência**: Retry automático e execução até sucesso do objetivo

## Arquitetura

### Componentes Principais

```
villager-ng/
├── interfaces/           # API REST e CLI
├── scheduler/            # Núcleo de execução de tarefas
│   ├── core/             # Lógica principal
│   │   ├── mcp_client/   # Model Context Protocol
│   │   ├── RAGLibrary/   # Base de conhecimento
│   │   ├── tasks/        # Motor de execução
│   │   └── console/      # Agente de escalação
├── tools/                # Ferramentas auxiliares
└── config/               # Configurações e tokens
```

### Stack Tecnológico

- **Framework Web**: FastAPI
- **IA/ML**: LangChain + Modelos especializados (HIVE, AL-1S-CTF-VER)
- **MCP**: Model Context Protocol para controle de Kali
- **CLI**: Typer
- **Logging**: Loguru

## Instalação

### AVISO CRÍTICO DE SEGURANÇA

**ESTE SOFTWARE É EXTREMAMENTE PERIGOSO**
- Execute APENAS em ambiente completamente isolado
- Requer autorização explícita antes do uso
- Monitore toda atividade de rede
- Consulte GUIA_SEGURANCA.md antes da instalação

### Pré-requisitos

#### Sistema Operacional
- **Linux recomendado**: Ubuntu 20.04+, Kali Linux 2023.1+, Debian 11+
- **Windows**: Windows 10+ com WSL2 (para funcionalidades completas)
- **macOS**: 11+ (funcionalidades limitadas)

#### Software Base
```bash
# Python e dependências
Python 3.11+
pip (versão mais recente)
git
curl

# Para funcionalidades completas (Kali Linux)
nuclei
nmap
msfconsole
```

#### Hardware Mínimo
- **RAM**: 4GB mínimo, 8GB recomendado
- **Disco**: 10GB de espaço livre
- **CPU**: 2 cores mínimo
- **Rede**: Isolado da rede de produção

### Configuração de Ambiente

#### 1. Preparação do Sistema

```bash
# Ubuntu/Debian - Instalar dependências do sistema
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip git curl

# Kali Linux - Ferramentas adicionais
sudo apt install nuclei nmap metasploit-framework

# Verificar versões
python3.11 --version
pip --version
```

#### 2. Clone e Configuração Inicial

```bash
# Clone em ambiente isolado
git clone https://github.com/marcostolosa/villager-ng.git
cd villager-ng

# Verificar estrutura
ls -la

# Criar ambiente virtual isolado
python3.11 -m venv venv_isolated

# Ativar ambiente virtual
# Linux/macOS:
source venv_isolated/bin/activate
# Windows:
# venv_isolated\Scripts\activate

# Verificar ativação
which python
which pip
```

#### 3. Instalação de Dependências

```bash
# Atualizar pip
pip install --upgrade pip

# Opção 1: Instalar via requirements (recomendado)
pip install -r requirements.txt

# Opção 2: Instalar via wheel (se disponível)
pip install villager-0.2.1rc1-py3-none-any.whl

# Opção 3: Instalar dependências principais manualmente
pip install fastapi uvicorn typer loguru
pip install langchain langchain-openai langchain-core
pip install requests beautifulsoup4 playwright
pip install numpy pandas scikit-learn
pip install kink pydantic
```

#### 4. Configuração de Variáveis de Ambiente

```bash
# Copiar template de configuração
cp .env.template .env

# Editar configurações
nano .env
```

**Exemplo de arquivo `.env`:**
```bash
# === CONFIGURAÇÕES BÁSICAS ===
VILLAGER_HOST=127.0.0.1
VILLAGER_PORT=37695
VILLAGER_DEBUG=False
ENVIRONMENT=development

# === CONFIGURAÇÕES DE IA ===
# OpenAI (obrigatório para funcionalidade completa)
OPENAI_API_KEY=sk-sua-chave-aqui
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4
OPENAI_TEMPERATURE=0.95

# Modelos locais (opcional)
LOCAL_LLM_URL=http://localhost:8000
LOCAL_LLM_MODEL=hive

# === CONFIGURAÇÕES MCP ===
# URLs dos servidores MCP (configurar conforme seu ambiente)
MCP_CLIENT_URL=http://127.0.0.1:25989
KALI_DRIVER_URL=http://10.10.3.119:25989
BROWSER_USE_URL=http://10.10.3.119:25990
MCP_CONSOLE_URL=http://10.10.3.248:1611
LLM_SERVER_URL=http://10.10.5.2:8000

# === CONFIGURAÇÕES DE SEGURANÇA ===
SANDBOX_MODE=True
ALLOW_EVAL=False
ALLOW_SYSTEM_COMMANDS=False
LOG_ALL_COMMANDS=True

# === CONFIGURAÇÕES DE REDE ===
PROXY_ENABLED=False
HTTP_PROXY=
HTTPS_PROXY=
CONNECT_TIMEOUT=10
READ_TIMEOUT=30

# === CONFIGURAÇÕES DE TESTE ===
TEST_MODE=False
MOCK_DANGEROUS=True
SKIP_NETWORK_TESTS=True
```

#### 5. Instalação de Ferramentas Externas (Opcional)

```bash
# Nuclei (scanner de vulnerabilidades)
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Verificar instalação
nuclei -version

# Playwright (automação de browser)
playwright install
playwright install-deps
```

### Verificação da Instalação

#### 1. Teste Básico do Sistema

```bash
# Ativar ambiente virtual
source venv_isolated/bin/activate

# Verificar configurações
python config.py

# Teste de dependências
python -c "import fastapi, langchain, requests; print('Dependências OK')"

# Verificar estrutura
python -c "from scheduler.core.init import global_llm; print('Core OK')"
```

#### 2. Teste de Configuração

```bash
# Validar arquivo de configuração
python -c "from config import validate_config; validate_config()"

# Teste de conectividade (se configurado)
python tools/get_current_ip/get_current.py

# Teste de ferramentas básicas
python tools/cidr/cidr2iplist.py
```

#### 3. Inicialização do Sistema

```bash
# Iniciar servidor (modo de teste)
python -m interfaces.boot serve --host 127.0.0.1 --port 37695

# Em outro terminal, testar API
curl http://localhost:37695/get/task/status
```

### Configuração Avançada

#### Configuração de Proxy

```bash
# Para ambientes corporativos
export HTTP_PROXY=http://proxy.empresa.com:8080
export HTTPS_PROXY=https://proxy.empresa.com:8080
export NO_PROXY=localhost,127.0.0.1
```

#### Configuração de Logging

```bash
# Criar diretório de logs
mkdir -p logs

# Configurar rotação de logs
export LOGGING_LEVEL=DEBUG
export LOGGING_FILE=logs/villager.log
export LOGGING_MAX_SIZE=100MB
```

#### Configuração de Docker (Alternativa)

```dockerfile
# Dockerfile para isolamento adicional
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install -r requirements.txt

EXPOSE 37695

CMD ["python", "-m", "interfaces.boot", "serve", "--host", "0.0.0.0", "--port", "37695"]
```

```bash
# Build e execução
docker build -t villager-ng .
docker run -p 37695:37695 --env-file .env villager-ng
```

### Solução de Problemas

#### Problemas Comuns

**1. Erro de dependência Python:**
```bash
pip install --upgrade pip setuptools wheel
pip install --force-reinstall -r requirements.txt
```

**2. Erro de permissão:**
```bash
# Linux/macOS
sudo chown -R $USER:$USER venv_isolated/
chmod +x interfaces/boot.py
```

**3. Erro de porta em uso:**
```bash
# Verificar porta
netstat -tulpn | grep :37695
# Alterar porta
export VILLAGER_PORT=37696
```

**4. Erro de API OpenAI:**
```bash
# Verificar chave
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

#### Logs de Debug

```bash
# Ativar logs detalhados
export LOGGING_LEVEL=DEBUG
export VILLAGER_DEBUG=True

# Executar com logs
python -m interfaces.boot serve 2>&1 | tee logs/debug.log
```

### Próximos Passos

1. **Leia a documentação**: [DOCUMENTACAO_COMPLETA.md](DOCUMENTACAO_COMPLETA.md)
2. **Revise segurança**: [GUIA_SEGURANCA.md](GUIA_SEGURANCA.md)
3. **Execute testes**: `python test/test.py`
4. **Configure MCP**: Configurar servidores MCP conforme necessidade
5. **Teste API**: Usar exemplos da seção "Comandos Principais"

## Comandos Principais

### Servidor API

```bash
# Iniciar servidor principal
python -m interfaces.boot serve --host 127.0.0.1 --port 37695
```

### API REST

```bash
# Criar tarefa
curl -X POST http://localhost:37695/task \
  -H "Content-Type: application/json" \
  -d '{
    "abstract": "Resumo da tarefa",
    "description": "Descrição detalhada",
    "verification": "Critérios de verificação"
  }'

# Status das tarefas
curl -X GET http://localhost:37695/get/task/status

# Visualizar grafo
curl -X GET "http://localhost:37695/tree?task_id={task_id}"
```

### Ferramentas Auxiliares

```bash
# Conversão CIDR
python tools/cidr/cidr2iplist.py

# Detecção de IP público
python tools/get_current_ip/get_current.py

# Geolocalização
python tools/ip2locRough/ip2locRough.py

# Automação de browser
python tools/playwright/browser.py
```

### Testes

```bash
# Executar testes
python test/test.py
python test/unitest/test_tool_manager.py
python test/unitest/api_test.py
```

## Funcionalidades Avançadas

### Decomposição Automática de Tarefas

O sistema usa IA para quebrar automaticamente tarefas complexas:

```python
# Exemplo: "Auditoria de segurança"
# Automaticamente decomposta em:
[
    "Scanning de rede e portas",
    "Enumeração de serviços",
    "Varredura de vulnerabilidades",
    "Exploração de falhas críticas",
    "Escalação de privilégios",
    "Persistência no sistema"
]
```

### Sistema de Verificação

Cada tarefa inclui critérios de verificação automática:

```python
TaskModel(
    abstract="Scanning de vulnerabilidades",
    description="Executar Nuclei no alvo",
    verification="Scanner deve completar e gerar relatório com descobertas"
)
```

### Monitoramento

- Status em tempo real via API
- Gráficos Mermaid de execução
- Logs detalhados de todas as operações
- Visualização de dependências entre tarefas

## CONSIDERAÇÕES CRÍTICAS DE SEGURANÇA

Este software tem características de:
- **Advanced Persistent Threat (APT)**
- **Infraestrutura de Botnet**
- **Framework de Cyber-arma**

### Perigos 

- **EXECUÇÃO ARBITRÁRIA**: Funções sem validação de segurança
- **ESCALAÇÃO AUTOMÁTICA**: Sistema projetado para elevar privilégios
- **C&C DISTRIBUÍDO**: Canais de comando via múltiplos protocolos
- **EVASÃO AVANÇADA**: Técnicas anti-detecção e anti-forense
- **PERSISTÊNCIA AGRESSIVA**: Reconexão e retry até sucesso

### Infraestrutura Maliciosa

```bash
# IPs hardcoded suspeitos
10.10.3.248:1611    # Console de escalação
10.10.5.2:8000      # Servidor de modelos IA
api.aabao.vip       # Endpoint não oficial
```

### Contramedidas

```bash
# Bloqueio de infraestrutura
iptables -A OUTPUT -d 10.10.3.0/24 -j DROP
iptables -A OUTPUT -d 10.10.5.0/24 -j DROP

# Detecção de processos
ps aux | grep -E "(villager|nuclei|msfconsole)"
netstat -an | grep -E "(37695|1611|8000)"
```

## AVISO LEGAL

### RESPONSABILIDADE

O uso deste framework pode constituir crime. Use APENAS:
- Para fins educacionais em ambiente isolado
- Com autorização explícita por escrito
- Em compliance com leis locais
- Para pesquisa de segurança responsável

### RECOMENDAÇÕES

1. **NÃO EXECUTE** em sistemas de produção
2. **USE APENAS** em ambiente air-gapped
3. **MONITORE** todas as atividades
4. **DOCUMENTE** descobertas para educação
5. **REPORTE** vulnerabilidades responsavelmente

---

**VILLAGER-NG** - Framework com capacidades de malware avançado para fins educacionais

**AVISO DE SEGURANÇA CRÍTICO**: Este framework contém funcionalidades maliciosas típicas de APT (Advanced Persistent Threat). Use APENAS para fins educacionais em ambiente completamente isolado.

**ESTE SOFTWARE REQUER EXTREMA CAUTELA E DEVE SER TRATADO COMO AMEAÇA CRÍTICA**