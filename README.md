# VILLAGER-NG

Framework avançado de penetration testing com automação baseada em IA.

**AVISO DE SEGURANÇA CRÍTICO**: Este framework contém funcionalidades maliciosas típicas de APT (Advanced Persistent Threat). Use APENAS para fins educacionais em ambiente completamente isolado.

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
├── scheduler/           # Núcleo de execução de tarefas
│   ├── core/           # Lógica principal
│   │   ├── mcp_client/ # Model Context Protocol
│   │   ├── RAGLibrary/ # Base de conhecimento
│   │   ├── tasks/      # Motor de execução
│   │   └── console/    # Agente de escalação
├── tools/              # Ferramentas auxiliares
└── config/             # Configurações e tokens
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

```bash
# Sistema isolado com:
- VM ou container sem acesso à rede produtiva
- Kali Linux para funcionalidades completas
- Python 3.11+
- Chave API OpenAI ou endpoint alternativo
```

### Configuração

```bash
# Clone em ambiente isolado
git clone https://github.com/marcostolosa/villager-ng.git
cd villager-ng

# Ambiente virtual
python -m venv venv_isolated
source venv_isolated/bin/activate

# Instalação
pip install villager-0.2.1rc1-py3-none-any.whl
```

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

### CLASSIFICAÇÃO: MALWARE AVANÇADO

Este software demonstra características de:
- **Advanced Persistent Threat (APT)**
- **Infraestrutura de Botnet**
- **Framework de Cyber-arma**

### Perigos Identificados

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

**ESTE SOFTWARE REQUER EXTREMA CAUTELA E DEVE SER TRATADO COMO AMEAÇA CRÍTICA**