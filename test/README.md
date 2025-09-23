# Testes do Villager-NG

Este diretório contém os testes para o framework Villager-NG, um sistema de pentest automatizado com IA.

##  AVISO DE SEGURANÇA CRÍTICO 

**ESTE É UM FRAMEWORK DE PENTEST AVANÇADO COM CAPACIDADES DE MALWARE**

-  Use APENAS em ambientes controlados e isolados
-  Consulte `ANALISE_COMPLETA.md` e `PERIGOS_E_HARDCODED.md` para análise completa de riscos
-  NÃO execute em ambientes de produção
-  NÃO use para atividades ilegais

## Estrutura dos Testes

### Arquivos de Teste

#### `test.py`
- **Descrição**: Teste principal do sistema de gerenciamento de relações entre tarefas
- **Funcionalidade**: Testa a classe `TaskRelationManager` e estruturas de nós
- **Uso**: Validação de grafos de tarefas e relacionamentos direcionais

```python
# Exemplo de execução
python test.py
```

#### `token_test.py`
- **Descrição**: Teste de integração com LLMs via Langchain
- **Funcionalidade**: Testa chamadas de API para modelos de linguagem
- **Uso**: Validação de comunicação com sistemas de IA

```python
# Requer configuração de API keys
python token_test.py
```

#### `streaming_response.py`
- **Descrição**: Teste de respostas em streaming
- **Funcionalidade**: Validação de comunicação assíncrona
- **Uso**: Teste de performance de streaming

#### `sharegpt_test.py`
- **Descrição**: Teste do sistema de logging ShareGPT
- **Funcionalidade**: Validação de formato de dados para treinamento de IA

#### Testes Unitários (`unitest/`)

##### `api_test.py`
- Testes de API REST do framework
- Validação de endpoints de controle

##### `avg.py`
- Testes de cálculos de média e estatísticas

##### `test_tool_manager.py`
- Testes do gerenciador de ferramentas ofensivas

## Configuração do Ambiente de Teste

### Dependências Obrigatórias

```bash
# Dependências principais
pip install loguru kink requests pydantic
pip install langchain-core langchain-openai
pip install sentence-transformers faiss-cpu
pip install scikit-learn numpy tqdm
pip install typer fastapi uvicorn
pip install psutil opencv-python pyyaml orjson
```

### Variáveis de Ambiente

```bash
# Configurações de logging
export LOGGING_LEVEL=0

# Configurações de API (CUIDADO: Use apenas em ambiente isolado)
export OPENAI_API_KEY="your-key-here"
export LLM_ENDPOINT="http://localhost:8000"
```

## Execução dos Testes

### Teste Básico (Seguro)
```bash
# Apenas teste de importação e estruturas
python test.py
```

### Testes Avançados (AMBIENTE ISOLADO APENAS)
```bash
# Testes que requerem conectividade
python token_test.py
python streaming_response.py
```

### Validação Completa via CI
```bash
# Executar via GitHub Actions
git push origin main
```

## Infraestrutura de Teste Identificada

###  ENDEREÇOS HARDCODED PERIGOSOS 

**ATENÇÃO**: Os seguintes endereços estão hardcoded no código e representam riscos de segurança:

#### Servidores de Controle
- `10.10.3.119:25989` - Servidor MCP principal
- `10.10.3.248:1611` - Console de comandos
- `10.10.5.2:8000` - Servidor LLM personalizado

#### Alvos de Teste
- `100.64.0.33` - Alvo de reconhecimento web
- `100.64.0.41` - Teste de conectividade

#### Proxies e Endpoints
- `home.hc26.org:5422` - Proxy com credenciais hardcoded
- `api.aabao.vip` - Endpoint OpenAI não oficial

## Capacidades Testadas

### Automação de Ataques
-  Decomposição inteligente via IA
-  Escalação automática de privilégios
-  Integração com Nuclei, MSFConsole
-  Execução persistente até sucesso

### Evasão e Persistência
-  Serialização base64 + pickle
-  Reconexão automática C&C
-  Sistema de proxies
-  Retry exponencial

### Command & Control
-  Canal DingTalk (plataforma chinesa)
-  Canal TCP secundário
-  Sistema de âncoras distribuídas
-  Logging centralizado ShareGPT

## Análise de Risco dos Testes

### NÍVEL DE AMEAÇA: EXTREMO

#### Indicadores de Malware Detectados:
1. **Execução arbitrária**: `pyeval()` e `os_execute_cmd()`
2. **Controle de Kali Linux**: Acesso direto via MCP
3. **Base de exploits**: RAG otimizada para vulnerabilidades
4. **C&C distribuído**: Múltiplos canais de comunicação
5. **Evasão avançada**: Técnicas anti-detecção

#### Classificação Final:
**ADVANCED PERSISTENT THREAT (APT) COM CAPACIDADES DE BOTNET**

## Diretrizes de Segurança para Testes

###  PERMITIDO
- Análise estática de código
- Testes de importação e sintaxe
- Validação de estruturas de dados
- Execução em ambiente sandbox isolado

###  PROIBIDO
- Execução em redes corporativas
- Testes contra alvos reais
- Uso de credenciais de produção
- Conexão com infraestrutura de C&C

## Monitoramento Durante Testes

### Indicadores de Comprometimento (IOCs)

```bash
# Processos suspeitos
ps aux | grep -E "(villager|nuclei|msfconsole)"

# Conexões de rede
netstat -an | grep -E "(37695|1611|25989)"

# Arquivos criados
find /tmp -name "*.mermaid" -o -name "RAGL.sqlite"
```

### Logs de Segurança
```bash
# Monitorar logs do sistema
tail -f /var/log/syslog | grep -E "(villager|exploit|privilege)"
```

## Contribuição para Testes

### Antes de Adicionar Novos Testes

1. **Análise de Segurança**: Todo novo teste deve ser analisado quanto a riscos
2. **Ambiente Isolado**: Garantir execução apenas em sandbox
3. **Documentação**: Documentar todos os riscos e capacidades
4. **Validação**: Testar em ambiente controlado primeiro

### Estrutura de Novo Teste

```python
# Cabeçalho obrigatório para novos testes
"""
TESTE DE SEGURANÇA - VILLAGER-NG
NÍVEL DE RISCO: [BAIXO/MÉDIO/ALTO/EXTREMO]
DESCRIÇÃO: [Descrição das capacidades testadas]
AMBIENTE: [Requisitos de ambiente isolado]
"""

def test_funcionalidade():
    # Implementação do teste com validações de segurança
    pass
```

## Relatórios de Teste

### Formato de Saída
```json
{
  "timestamp": "2024-01-20T15:30:00Z",
  "test_suite": "villager-ng",
  "security_level": "EXTREMO",
  "results": {
    "passed": 10,
    "failed": 2,
    "skipped": 5
  },
  "security_warnings": [
    "Detectado código de execução arbitrária",
    "Identificada infraestrutura de C&C"
  ]
}
```

## Contato de Segurança

Para relatar vulnerabilidades ou questões de segurança relacionadas aos testes:

- **Análise Completa**: Consulte `ANALISE_COMPLETA.md`
- **Perigos Identificados**: Consulte `PERIGOS_E_HARDCODED.md`
- **Classificação**: Advanced Persistent Threat (APT)

---

**LEMBRETE FINAL**: Este framework possui capacidades que excedem ferramentas legítimas de pentest. Use com extrema cautela e apenas para pesquisa de segurança em ambiente controlado.