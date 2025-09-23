# CHECKLIST EDUCACIONAL COMPLETO - VILLAGER-NG
## Guia Didático para Ensino de Segurança Cibernética

### IMPORTANTE: USO EDUCACIONAL APENAS
Este checklist foi criado para fins educacionais em cursos de segurança cibernética. Todos os exemplos devem ser executados APENAS em ambiente controlado e isolado.

---

## ESTRUTURA GERAL DO PROJETO

### ARQUITETURA DO FRAMEWORK

```
villager-ng/
├── interfaces/          # Camada de Interface (CLI e API REST)
├── scheduler/           # Núcleo de Processamento com IA
├── tools/              # Arsenal de Ferramentas de Segurança
├── test/               # Testes e Validação
└── .github/workflows/  # Automação CI/CD
```

---

## ANÁLISE ARQUIVO POR ARQUIVO

### 1. INTERFACES - CAMADA DE INTERAÇÃO

#### 1.1 `interfaces/__init__.py`
- **Status**: ✓ Validado
- **Função**: Arquivo de inicialização do módulo
- **Conteúdo**: Vazio (padrão Python)
- **Propósito Educacional**: Demonstra estrutura de pacotes Python

#### 1.2 `interfaces/boot.py`
- **Status**: ✓ Validado
- **Função**: Interface de linha de comando (CLI)
- **Tecnologia**: Typer (framework CLI moderno)
- **Funcionalidades**:
  - Inicialização do servidor na porta 37695
  - Gerenciamento de configurações
  - Controle de lifecycle da aplicação
- **Conceitos Ensinados**:
  - Design de CLI profissional
  - Padrões de inicialização de serviços
  - Gerenciamento de configuração

```python
# Exemplo de uso educacional:
# Demonstra como criar CLI robusta para ferramentas de segurança
```

#### 1.3 `interfaces/interface.py`
- **Status**: ✓ Validado
- **Função**: API REST para controle remoto
- **Tecnologia**: FastAPI (framework web assíncrono)
- **Endpoints Críticos**:
  - `POST /task` - Submissão de tarefas
  - `GET /task/{id}/tree` - Visualização de estrutura
  - `PUT /task/{id}/stop` - Controle de execução
- **Conceitos Ensinados**:
  - Design de APIs RESTful
  - Padrões de autenticação
  - Controle de acesso a recursos críticos

---

### 2. SCHEDULER - NÚCLEO INTELIGENTE

#### 2.1 Gerenciamento de Agentes

##### `scheduler/agentManager.py`
- **Status**: ✓ Validado
- **Função**: Gerenciador de modelos de IA especializados
- **Modelos Identificados**:
  - `AL-1S-CTF-VER`: Especializado em Capture The Flag
  - `QwQ-32B`: Modelo de raciocínio avançado
  - `HIVE`: Modelo personalizado
- **Conceitos Ensinados**:
  - Integração de múltiplos modelos de IA
  - Especialização de agentes por domínio
  - Padrões de factory para criação de objetos

##### `scheduler/agent_scheduler_manager.py`
- **Status**: ✓ Validado
- **Função**: Orquestração de execução de agentes
- **Características**:
  - Scheduling inteligente
  - Balanceamento de carga
  - Monitoramento de performance
- **Conceitos Ensinados**:
  - Padrões de scheduler
  - Gerenciamento de recursos computacionais
  - Monitoramento de sistemas distribuídos

#### 2.2 Núcleo de Processamento

##### `scheduler/core/init.py`
- **Status**: ✓ Validado
- **Função**: Configurações centrais do sistema
- **Parâmetros Críticos**:
  - Temperature: 0.95 (alta criatividade)
  - Configurações de timeout
  - Inicialização de dependências
- **Conceitos Ensinados**:
  - Padrões de configuração de sistemas
  - Injeção de dependências
  - Configuração de parâmetros de IA

##### `scheduler/core/Thought.py`
- **Status**: ✓ Validado - **ATENÇÃO: CÓDIGO PERIGOSO**
- **Função**: Motor de execução de código
- **Funcionalidades Perigosas**:
  - `pyeval()`: Execução de código Python arbitrário
  - `os_execute_cmd()`: Execução de comandos de sistema
- **Propósito Educacional**:
  - **DEMONSTRA**: Como NOT fazer execução de código
  - **ENSINA**: Riscos de execução não validada
  - **EXEMPLO**: Vulnerabilidades de code injection

```python
# EXEMPLO EDUCACIONAL - NUNCA FAÇA ISSO EM PRODUÇÃO:
def pyeval(code: str):
    return eval(code)  # EXTREMAMENTE PERIGOSO!

# VERSÃO SEGURA PARA ENSINAR:
def safe_eval(expression: str, allowed_names: dict):
    # Validação de entrada
    # Lista branca de funções
    # Sandbox de execução
    pass
```

##### `scheduler/core/sharegpt_logger.py`
- **Status**: ✓ Validado
- **Função**: Sistema de logging para treinamento de IA
- **Características**:
  - Formato ShareGPT padrão
  - Logging assíncrono de alta performance
  - Backup automático em falhas
- **Conceitos Ensinados**:
  - Padrões de logging profissional
  - Design de sistemas assíncronos
  - Tratamento de falhas e recovery

#### 2.3 Cliente MCP (Model Context Protocol)

##### `scheduler/core/mcp_client/mcp_client.py`
- **Status**: ✓ Validado - **ATENÇÃO: CONTROLE REMOTO**
- **Função**: Interface para controle de sistemas Kali Linux
- **Características Críticas**:
  - Timeout de 4 horas para operações longas
  - Controle direto de ferramentas de pentest
  - Streaming de resultados em tempo real
- **IPs Hardcoded Identificados**:
  - `10.10.3.119`: Servidor MCP principal
- **Conceitos Ensinados**:
  - Protocolos de comunicação segura
  - Controle remoto de sistemas
  - Streaming de dados em tempo real

##### `scheduler/core/mcp_client/mcp_console.py`
- **Status**: ✓ Validado
- **Função**: Console interativo para MCP
- **Conceitos Ensinados**:
  - Design de interfaces interativas
  - Protocolos de console remoto
  - Tratamento de input/output assíncrono

#### 2.4 Biblioteca RAG (Retrieval-Augmented Generation)

##### `scheduler/core/RAGLibrary/RAG.py`
- **Status**: ✓ Validado - **ATENÇÃO: BASE DE EXPLOITS**
- **Função**: Busca inteligente em base de vulnerabilidades
- **Exemplos de Busca Identificados**:
  - "Vulnerabilidades VMware VCenter"
  - "Vulnerabilidades Geoserver"
- **Tecnologias**:
  - FAISS para busca vetorial
  - Embeddings de texto
  - Cache persistente
- **Conceitos Ensinados**:
  - Sistemas de recuperação de informação
  - Embeddings e busca semântica
  - Otimização de performance em IA

##### `scheduler/core/RAGLibrary/RAGL_Calc.py`
- **Status**: ✓ Validado
- **Função**: Cálculos de similaridade e ranking
- **Algoritmos**:
  - TF-IDF para relevância textual
  - Cosine similarity para embeddings
  - Ranking ponderado de resultados
- **Conceitos Ensinados**:
  - Algoritmos de recuperação de informação
  - Métodos de ranking e scoring
  - Otimização de busca

#### 2.5 Esquemas de Dados

##### `scheduler/core/schemas/schemas.py`
- **Status**: ✓ Validado
- **Função**: Definições de estruturas de dados
- **Modelos Principais**:
  - `TaskModel`: Estrutura de tarefas
  - `TaskStatus`: Estados de execução
  - `TaskExecuteStatusModel`: Resultados de execução
- **Conceitos Ensinados**:
  - Design de schemas com Pydantic
  - Validação de dados
  - Serialização JSON

##### `scheduler/core/schemas/structure/ToT.py`
- **Status**: ✓ Validado
- **Função**: Tree of Thoughts para decomposição de tarefas
- **Características**:
  - Serialização YAML segura
  - Conversão recursiva de tipos
  - Suporte a Unicode
- **Conceitos Ensinados**:
  - Estruturas de dados hierárquicas
  - Serialização segura
  - Padrões de conversão de tipos

##### `scheduler/core/schemas/structure/task_relation_manager.py`
- **Status**: ✓ Validado
- **Função**: Gerenciamento de relações entre tarefas
- **Características**:
  - Grafos direcionais
  - Busca em profundidade e largura
  - Geração de diagramas Mermaid
- **Conceitos Ensinados**:
  - Teoria de grafos aplicada
  - Algoritmos de busca
  - Visualização de dados

#### 2.6 Sistema de Tarefas

##### `scheduler/core/tasks/task.py`
- **Status**: ✓ Validado - **ATENÇÃO: AUTOMAÇÃO DE ATAQUES**
- **Função**: Núcleo de execução de tarefas de pentest
- **Características Críticas**:
  - Decomposição inteligente de ataques via IA
  - Execução até sucesso do exploit
  - Integração com Nuclei e MSFConsole
- **Conceitos Ensinados**:
  - Automação de processos complexos
  - Integração de ferramentas heterogêneas
  - Tratamento de falhas e retry

##### `scheduler/core/tasks/agents/console_agent.py`
- **Status**: ✓ Validado
- **Função**: Agente para interação via console
- **Características**:
  - Janela deslizante para controle de contexto
  - Streaming de respostas
  - Tratamento de JSON malformado
- **Conceitos Ensinados**:
  - Design de agentes conversacionais
  - Gestão de memória em IA
  - Protocolos de streaming

#### 2.7 Cadeia de Ferramentas

##### `scheduler/toolschain/tools_manager.py`
- **Status**: ✓ Validado
- **Função**: Gerenciador de pool de ferramentas
- **Características**:
  - Reflexão de assinaturas de função
  - Validação de estruturas JSON
  - Registry dinâmico de ferramentas
- **Conceitos Ensinados**:
  - Padrões de registry
  - Reflexão em Python
  - Validação dinâmica

---

### 3. TOOLS - ARSENAL DE FERRAMENTAS

#### 3.1 Sistema de Logging

##### `tools/logging.py`
- **Status**: ✓ Validado - **ATENÇÃO: EXFILTRAÇÃO**
- **Função**: Sistema de logging com capacidades de exfiltração
- **Características Críticas**:
  - `LoggingToSocket`: Exfiltração via TCP
  - Reconexão automática para persistência
  - Server UUID para identificação
- **Conceitos Ensinados**:
  - **ENSINA**: Como detectar exfiltração de dados
  - **DEMONSTRA**: Técnicas de persistência
  - **EXEMPLO**: Canais de comunicação ocultos

#### 3.2 Verificação de Ambiente

##### `tools/check/checking.py`
- **Status**: ✓ Validado - **ATENÇÃO: RECONNAISSANCE**
- **Função**: Verificação completa de ambiente e capacidades
- **Características**:
  - Teste de conectividade com proxies
  - Enumeração de interfaces de rede
  - Teste de câmeras (surveillance)
  - Verificação de memória disponível
- **Proxy Hardcoded**: `huancun:ylq123..@home.hc26.org:5422`
- **Conceitos Ensinados**:
  - Técnicas de reconnaissance
  - Detecção de ambiente
  - Verificação de recursos

#### 3.3 Processamento de Argumentos

##### `tools/args_wrap/args_wraper.py`
- **Status**: ✓ Validado - **ATENÇÃO: EVASÃO**
- **Função**: Empacotamento e ofuscação de argumentos
- **Características**:
  - Serialização pickle + base64
  - Evasão de detecção
  - Execução remota de código
- **Conceitos Ensinados**:
  - **ENSINA**: Como detectar evasão
  - **DEMONSTRA**: Técnicas de ofuscação
  - **EXEMPLO**: Serialização insegura

##### `tools/args_wrap/loading.py`
- **Status**: ✓ Validado
- **Função**: Simulação de carregamento com animação
- **Conceitos Ensinados**:
  - Interfaces de usuário para CLI
  - Threading para animações
  - Feedback visual em operações longas

#### 3.4 Processamento de Rede

##### `tools/cidr/cidr2iplist.py`
- **Status**: ✓ Validado - **ATENÇÃO: SCANNING MASSIVO**
- **Função**: Expansão de CIDR para lista de IPs
- **Uso Típico**: Preparação para scanning em massa
- **Conceitos Ensinados**:
  - Cálculos de rede e subnetting
  - Geração de alvos para scanning
  - Processamento eficiente de ranges IP

##### `tools/get_current_ip/get_current.py`
- **Status**: ✓ Validado
- **Função**: Detecção de IP público atual
- **Métodos**:
  - API ipify.org
  - Serviço httpbin.org
  - Fallback múltiplo
- **Conceitos Ensinados**:
  - Detecção de IP público
  - Padrões de fallback
  - Integração com APIs externas

##### `tools/ip2locRough/ip2locRough.py`
- **Status**: ✓ Validado - **ATENÇÃO: GEOLOCALIZAÇÃO**
- **Função**: Geolocalização de endereços IP
- **Uso**: Targeting geográfico de alvos
- **Conceitos Ensinados**:
  - Serviços de geolocalização
  - Targeting baseado em localização
  - APIs de inteligência geográfica

#### 3.5 Gerenciamento de Eventos

##### `tools/eventManager/eventManager.py`
- **Status**: ✓ Validado
- **Função**: Sistema de eventos para coordenação
- **Características**:
  - Classificação por nível de severidade
  - Registry de eventos
  - Tratamento de erros
- **Conceitos Ensinados**:
  - Padrões de event-driven architecture
  - Sistemas de notificação
  - Coordenação de componentes

#### 3.6 Utilitários Funcionais

##### `tools/func/retry_decorator.py`
- **Status**: ✓ Validado
- **Função**: Decorator para retry automático
- **Características**:
  - Backoff exponencial
  - Tratamento de exceções específicas
  - Logging de tentativas
- **Conceitos Ensinados**:
  - Padrões de retry e resilência
  - Decorators avançados em Python
  - Tratamento robusto de falhas

##### `tools/func/result_tidy_up.py`
- **Status**: ✓ Validado
- **Função**: Organização e limpeza de resultados
- **Conceitos Ensinados**:
  - Processamento de dados
  - Formatação de saída
  - Organização de resultados

#### 3.7 Integração Web

##### `tools/playwright/browser.py`
- **Status**: ✓ Validado - **ATENÇÃO: WEB RECONNAISSANCE**
- **Função**: Automação de navegador para reconnaissance
- **Características**:
  - Crawling automatizado
  - Headless browsing
  - Extração de conteúdo
- **IP Alvo Identificado**: `100.64.0.33`
- **Conceitos Ensinados**:
  - Automação de navegadores
  - Web scraping avançado
  - Reconnaissance web automatizado

#### 3.8 Processamento de Dados

##### `tools/output/formatter.py`
- **Status**: ✓ Validado
- **Função**: Formatação de saída para âncoras offline
- **Conceitos Ensinados**:
  - Formatação de dados
  - Processamento de listas
  - Dedução de duplicatas

##### `tools/xlsxwork/xlsxMerge/merge.py`
- **Status**: ✓ Validado - **ATENÇÃO: GESTÃO DE CAMPANHA**
- **Função**: Consolidação de "fingerprints web de alto risco"
- **Propósito**: Gestão de campanhas de scanning
- **Conceitos Ensinados**:
  - Processamento de planilhas
  - Consolidação de dados de múltiplas fontes
  - Gestão de campañas de segurança

---

### 4. TESTES - VALIDAÇÃO E EXEMPLOS

#### 4.1 Testes Principais

##### `test/test.py`
- **Status**: ✓ Validado
- **Função**: Teste de sistema de relações entre tarefas
- **Exemplo de Grafo**:
```
A → B → C
↓
D → F → H
↓       ↓
E → G   I
```
- **Conceitos Ensinados**:
  - Testes de estruturas de dados complexas
  - Validação de algoritmos de grafo
  - Debugging visual de estruturas

##### `test/token_test.py`
- **Status**: ✓ Validado
- **Função**: Teste de integração com LLMs
- **Características**:
  - Teste de APIs Langchain
  - Validação de respostas de IA
  - Exemplo de prompt de ataque (ping 100.64.0.41)
- **Conceitos Ensinados**:
  - Integração com modelos de linguagem
  - Testes de sistemas de IA
  - Validação de respostas

##### `test/streaming_response.py`
- **Status**: ✓ Validado
- **Função**: Teste de respostas em streaming
- **Conceitos Ensinados**:
  - Protocolos de streaming
  - Testes de performance
  - Comunicação assíncrona

#### 4.2 Testes Unitários

##### `test/unitest/api_test.py`
- **Status**: ✓ Validado (problemas de encoding detectados)
- **Função**: Testes da API REST
- **Conceitos Ensinados**:
  - Testes de APIs
  - Validação de endpoints
  - Tratamento de encoding

##### `test/unitest/test_tool_manager.py`
- **Status**: ✓ Validado
- **Função**: Testes do gerenciador de ferramentas
- **Conceitos Ensinados**:
  - Testes de componentes
  - Validação de registry
  - Mocking de dependências

---

### 5. CI/CD - AUTOMAÇÃO E VALIDAÇÃO

#### 5.1 GitHub Actions

##### `.github/workflows/tests.yml`
- **Status**: ✓ Configurado
- **Função**: Pipeline de CI/CD com validação de segurança
- **Características**:
  - Multi-versão Python (3.9, 3.10, 3.11)
  - Verificação de sintaxe
  - Validação de tradução
  - Alerts de segurança
- **Conceitos Ensinados**:
  - DevSecOps practices
  - Automação de testes
  - Validação contínua

---

## ANÁLISE DE SEGURANÇA EDUCACIONAL

### PADRÕES DE ATAQUE IDENTIFICADOS

#### 1. **Command & Control (C&C)**
- **Arquivos**: `tools/logging.py`, `tools/dingtalk/sender.py`
- **Técnicas**: Múltiplos canais de comunicação
- **Ensino**: Como detectar e mitigar C&C

#### 2. **Evasão de Detecção**
- **Arquivos**: `tools/args_wrap/args_wraper.py`
- **Técnicas**: Serialização + Base64
- **Ensino**: Técnicas de detecção de evasão

#### 3. **Persistence Mechanisms**
- **Arquivos**: `scheduler/core/mcp_client/mcp_client.py`
- **Técnicas**: Reconexão automática, timeouts longos
- **Ensino**: Detecção de persistência

#### 4. **Privilege Escalation**
- **Arquivos**: `scheduler/core/console/agent_test.py`
- **Técnicas**: Automação de escalação
- **Ensino**: Prevenção de escalação

### INFRAESTRUTURA IDENTIFICADA

#### IPs e Endpoints Hardcoded:
- `10.10.3.119`: Servidor MCP principal
- `10.10.3.248:1611`: Console de comandos
- `100.64.0.33`: Alvo de reconnaissance
- `api.aabao.vip`: Endpoint suspeito

### MODELOS DE IA ESPECIALIZADOS:
- `AL-1S-CTF-VER`: CTF specialist
- `QwQ-32B`: Advanced reasoning
- `HIVE`: Custom model

---

## EXERCÍCIOS PRÁTICOS PARA ENSINO

### Exercício 1: Análise de Código Perigoso
```python
# Encontre os problemas de segurança neste código:
def execute_command(user_input):
    return eval(user_input)  # PROBLEMA 1: Code injection

def run_system_cmd(cmd):
    os.system(cmd)  # PROBLEMA 2: Command injection
```

### Exercício 2: Detecção de Evasão
```python
# Como detectar esta técnica de evasão?
import base64, pickle
data = base64.b64encode(pickle.dumps(malicious_payload))
```

### Exercício 3: Análise de C&C
```python
# Identifique os indicadores de C&C neste código:
class LoggingToSocket:
    def __init__(self, server_uuid, host, port):
        self.reconnect_on_failure = True  # Persistência
        self.heartbeat_interval = 30      # Keep-alive
```

---

## CONTRAMEDIDAS E DEFENSAS

### 1. **Detecção de Code Injection**
```python
# Implementação segura:
def safe_eval(expression, allowed_names):
    # Validar entrada
    # Lista branca de funções
    # Sandbox de execução
    pass
```

### 2. **Detecção de C&C**
```bash
# Monitoramento de rede:
netstat -an | grep -E "(37695|1611|25989)"
```

### 3. **Detecção de Evasão**
```python
# Detectar serialização suspeita:
import re
pattern = r'[A-Za-z0-9+/]{20,}={0,2}'  # Base64
```

---

## CONCLUSÃO EDUCACIONAL

### O QUE ESTE FRAMEWORK ENSINA:

#### ✓ **Aspectos Técnicos Positivos**:
1. Arquitetura de sistemas distribuídos
2. Integração de IA em segurança
3. Padrões de design robustos
4. Automação inteligente

#### ⚠️ **Aspectos de Segurança Críticos**:
1. Técnicas de ataque automatizado
2. Métodos de evasão avançados
3. Infraestrutura de C&C
4. Persistência e reconnaissance

#### 📚 **Valor Educacional**:
- Exemplo real de threat intelligence
- Demonstração de técnicas de APT
- Estudo de caso de automação maliciosa
- Laboratório para desenvolvimento de defensas

### RECOMENDAÇÕES PARA ENSINO:

1. **Ambiente Isolado Obrigatório**
2. **Supervisão Constante**
3. **Foco em Defesa, não Ataque**
4. **Documentação de Contramedidas**
5. **Ética em Segurança Cibernética**

---

**LEMBRETE FINAL**: Este framework deve ser usado EXCLUSIVAMENTE para ensino de segurança defensiva, demonstrando técnicas de ataque para melhor preparar defensores cibernéticos.