# ANÁLISE COMPLETA DO VILLAGER-NG - FRAMEWORK DE PENTEST CHINÊS

## RESUMO EXECUTIVO - NÍVEL DE AMEAÇA: CRÍTICO

O Villager-NG é um framework de pentest extremamente sofisticado com capacidades que excedem ferramentas legítimas, incluindo características típicas de malware avançado e infraestrutura de botnet. O sistema possui automação completa de ataques, evasão de detecção, e canais de command & control.

### ARQUITETURA GERAL
✅ **ANÁLISE COMPLETA** - Framework modular com 3 componentes principais:
- **Interfaces**: API REST e CLI para controle
- **Scheduler**: Núcleo de execução com IA
- **Tools**: Arsenal de ferramentas ofensivas

### CAPACIDADES IDENTIFICADAS

#### AUTOMAÇÃO OFENSIVA
- Escalação automática de privilégios (`帮我提权`)
- Decomposição inteligente de ataques complexos via IA
- Execução persistente até sucesso do exploit
- Integração com Nuclei, MSFConsole, Kali Linux

#### EVASÃO E PERSISTÊNCIA
- Serialização base64 + pickle para ofuscação
- Reconexão automática em canais C&C
- Sistema de proxies para mascaramento
- Retry exponencial para contornar defesas

#### COMMAND & CONTROL
- Canal primário via DingTalk (plataforma chinesa)
- Canal secundário via sockets TCP
- Sistema de "âncoras" distribuídas
- Logging centralizado para ShareGPT

#### RECONHECIMENTO MASSIVO
- Expansão CIDR para scanning em massa
- Automação de browsers para web recon
- Geolocalização de alvos
- Detecção de ambiente e recursos

### ANÁLISE DETALHADA POR DIRETÓRIO

## /interfaces - CONTROLE E ACESSO
✅ **ANALISADO COMPLETAMENTE**

### Arquivos Principais:
- `boot.py`: CLI com Typer (porta padrão 37695)
- `interface.py`: API REST com FastAPI

### Descobertas Críticas:
- **Execução automática** via SERVER_UUID único
- **Controle remoto** de tarefas via API REST
- **Visualização** em tempo real com grafos Mermaid
- **Cancelamento** de tarefas em execução

### Endpoints Perigosos:
- `POST /task` - Executa tarefas de pentest
- `GET /task/{id}/tree` - Visualiza estrutura de ataque
- `PUT /task/{id}/stop` - Para execução
- `GET /task/{id}/context` - Obtém contexto de execução

## /scheduler - NÚCLEO DE EXECUÇÃO IA
✅ **ANALISADO COMPLETAMENTE**

### Componentes Críticos:

#### Gerenciamento de Agentes (`agentManager.py`)
- **Modelos especializados**: AL-1S-CTF-VER, QwQ-32B para CTF
- **Modelo HIVE** personalizado
- **Integração** com OpenAI, Llama, DeepSeek

#### Núcleo de Execução (`core/`)
- **`init.py`**: Temperatura 0.95 (alta criatividade)
- **`Thought.py`**: Execução de código via `pyeval`, `os_execute_cmd`
- **`task.py`**: Automação completa de ataques

#### Capacidades MCP (`mcp_client/`)
- **Timeout 4 horas** para operações longas
- **kali_driver**: Controle direto de Kali Linux
- **browser_use**: Automação de navegadores
- **IP hardcoded**: 10.10.3.119 (ambiente de teste)

#### Base de Conhecimento RAG (`RAGLibrary/`)
- **Busca por vulnerabilidades**: "Vmware VCenter 漏洞"
- **Embedding** otimizado para exploits
- **Cache persistente** via pickle/FAISS
- **Base SQLite** com conhecimento de hacking

#### Esquemas de Dados (`schemas/`)
- **TaskModel**: Estrutura de tarefas de ataque
- **Critérios de verificação** personalizáveis
- **Árvore 2D** para relacionamentos complexos
- **Grafos Mermaid** para visualização

### Descobertas EXTREMAMENTE CRÍTICAS:
1. **Execução arbitrária**: `pyeval()` e `os_execute_cmd()`
2. **Controle de Kali Linux**: Acesso direto via MCP
3. **Escalação automática**: Comando explícito no código
4. **Base de exploits**: RAG otimizada para vulnerabilidades
5. **Timeout de 4 horas**: Permite ataques prolongados

## /tools - ARSENAL OFENSIVO
✅ **ANALISADO COMPLETAMENTE** (33 arquivos, 13 módulos)

### Módulos de Alta Periculosidade:

#### `logging.py` - Sistema de Exfiltração
- **LoggingToSocket**: Exfiltração via TCP
- **Reconexão automática** para persistência
- **Server UUID** para identificação C&C

#### `args_wrap/` - Evasão e Ofuscação
- **Serialização pickle + base64** para bypass
- **Execução remota** de código arbitrário
- **Wrapper** para evasão de detecção

#### `check/checking.py` - Reconhecimento Ambiental
- **Teste de conectividade** e proxies
- **Enumeração de interfaces** de rede
- **Acesso a webcams** para surveillance
- **Proxy hardcoded**: `huancun:ylq123..@home.hc26.org:5422`

#### `dingtalk/sender.py` - Canal C&C Principal
- **Integração completa** com DingTalk API
- **Autenticação HMAC** criptográfica
- **Multi-threading** para comunicação assíncrona
- **Exfiltração disfarçada** em tráfego legítimo

#### `playwright/browser.py` - Reconhecimento Web
- **Crawling automatizado** de domínios
- **Extração massiva** de conteúdo
- **Headless browsing** para evasão
- **IP alvo**: 100.64.0.33 (ambiente corporativo)

#### `xlsxwork/merge.py` - Gestão de Campanha
- **Consolidação** de "web高危指纹" (fingerprints de alto risco)
- **Relatórios automatizados** de vulnerabilidades
- **Priorização** de alvos por nível de risco

### Outros Módulos Relevantes:
- **`cidr/`**: Expansão de alvos para scanning massivo
- **`ip2locRough/`**: Geolocalização para targeting
- **`eventManager/`**: Orquestração de operações
- **`func/`**: Utilitários de persistência e retry
- **`get_current_ip/`**: Detecção de IP próprio
- **`ini/`**: Configurações com endpoint suspeito (api.aabao.vip)

## DESCOBERTAS EXTREMAMENTE CRÍTICAS

### Infraestrutura de Rede Identificada:
- **10.10.3.119**: Servidor MCP principal
- **10.10.3.248:1611**: Console de comandos
- **10.10.5.2:8000**: Servidor LLM personalizado
- **100.64.0.33**: Alvo de reconhecimento web
- **100.64.0.41**: Teste de conectividade
- **api.aabao.vip**: Endpoint não oficial suspeito

### Comandos Explícitos de Ataque:
- `帮我提权` (ajude-me a escalar privilégios)
- `帮我ping一下100.64.0.41` (teste de conectividade)
- **Uso direto de nuclei e msfconsole**
- **Execução até sucesso do exploit**

### Capacidades de Malware:
1. **Execução arbitrária de código** sem validação
2. **Persistência** via reconexão automática
3. **Evasão** de detecção por múltiplos métodos
4. **Exfiltração** via canais encriptados
5. **C&C distribuído** com sistema de âncoras
6. **Surveillance** via acesso a câmeras

### Modelos IA Especializados:
- **AL-1S-CTF-VER**: Especializado em Capture The Flag
- **QwQ-32B**: Modelo avançado para reasoning
- **HIVE**: Modelo personalizado (possivelmente treinado em dados maliciosos)

## AVALIAÇÃO DE RISCO FINAL

### NÍVEL DE AMEAÇA: **CRÍTICO** ⚠️

Este framework excede significativamente as capacidades de ferramentas legítimas de pentest, demonstrando características de:

1. **Advanced Persistent Threat (APT)**
2. **Botnet Infrastructure**
3. **Automated Attack Platform**
4. **AI-Powered Malware**

### INDICADORES DE USO MALICIOSO:
- Endpoints hardcoded não oficiais
- Credenciais em código fonte
- Sistema de C&C distribuído
- Automação de escalação de privilégios
- Base de conhecimento focada em exploits
- Capacidades de surveillance
- Evasão avançada de detecção

### RECOMENDAÇÕES IMEDIATAS:
1. **ISOLAMENTO COMPLETO** - Não executar em ambiente produtivo
2. **ANÁLISE FORENSE** - Investigar origem e distribuição
3. **BLOQUEIO DE REDE** - Bloquear comunicação com infraestrutura identificada
4. **MONITORAMENTO** - Detectar padrões de comportamento em ambiente controlado
5. **ALERTA LEGAL** - Notificar autoridades competentes se apropriado

### CONCLUSÃO:
O Villager-NG representa uma ameaça de segurança significativa que combina IA avançada com técnicas de malware sofisticadas. O framework está claramente projetado para operações ofensivas automatizadas em escala, com capacidades que vão muito além de testes de penetração legítimos.