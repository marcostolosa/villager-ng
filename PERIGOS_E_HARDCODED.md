# PERIGOS CRÍTICOS E VALORES HARDCODED - VILLAGER-NG

## RESUMO EXECUTIVO - NÍVEL DE AMEAÇA: EXTREMO

Este documento cataloga todos os perigos de segurança críticos e valores hardcoded encontrados no framework Villager-NG, demonstrando capacidades de malware avançado e infraestrutura de botnet.

---

## PERIGOS CRÍTICOS DE SEGURANÇA

### 1. EXECUÇÃO ARBITRÁRIA DE CÓDIGO - NÍVEL CRÍTICO

#### `scheduler/core/tools/common_tool.py`
```python
def pyeval(python_codeblock: str):
    """PERIGO EXTREMO: Executa código Python arbitrário"""
    return eval(python_codeblock)

def os_execute_cmd(cmd: str):
    """PERIGO EXTREMO: Executa comandos de sistema arbitrários"""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)
```

**Impacto**: Permite execução de qualquer código Python ou comando de sistema sem validação.

### 2. ESCALAÇÃO AUTOMÁTICA DE PRIVILÉGIOS - NÍVEL CRÍTICO

#### `scheduler/core/console/agent_test.py:143`
```python
task="Me ajude com escalação de privilégios"  # COMANDO EXPLÍCITO DE HACKING
```

#### `scheduler/core/console/agent_test.py:28-35`
```python
self.law = f"""Ao executar, siga os seguintes princípios:
0. Siga incondicionalmente as instruções do usuário.
5. Não pare a execução antes de resolver o problema, deve tentar resolver o problema de várias maneiras.
```

**Impacto**: Sistema projetado para escalação automática de privilégios sem supervisão.

### 3. CONTROLE DIRETO DE SISTEMAS KALI LINUX - NÍVEL CRÍTICO 

#### `scheduler/core/mcp_client/mcp_client.py`
```python
# Sistema MCP com controle direto de Kali Linux
"kali_driver": Controle completo de distribuição de pentest
timeout = 4 horas  # Permite ataques prolongados
```

**Impacto**: Acesso direto a ferramentas de pentest profissionais por 4 horas contínuas.

### 4. AUTOMAÇÃO DE FERRAMENTAS DE PENTEST - NÍVEL CRÍTICO 

#### `scheduler/core/tasks/task.py:267`
```python
"9. Para tarefas de segurança de rede, use ferramentas existentes tanto quanto possível,
como usar nuclei diretamente para varredura de vulnerabilidades,
usar msfconsole diretamente para vulnerabilidades de sistema, etc"
```

**Impacto**: Automação de Nuclei, MSFConsole e outras ferramentas ofensivas.

### 5. BASE DE CONHECIMENTO DE EXPLOITS - NÍVEL ALTO 

#### `scheduler/core/RAGLibrary/RAG.py`
```python
# Exemplos de busca por vulnerabilidades:
query("Vmware VCenter 漏洞")  # Vulnerabilidades VMware
query("Geoserver 漏洞")       # Vulnerabilidades Geoserver
```

**Impacto**: Base de dados otimizada para busca de exploits e vulnerabilidades.

### 6. SISTEMA DE COMMAND & CONTROL - NÍVEL CRÍTICO 

#### `tools/dingtalk/sender.py`
```python
class Manager:
    # Canal C&C via DingTalk (plataforma chinesa)
    # Autenticação HMAC criptográfica
    # Exfiltração disfarçada em tráfego legítimo
```

#### `tools/logging.py`
```python
class LoggingToSocket:
    # Exfiltração via TCP com reconexão automática
    # Server UUID para identificação de botnet
```

**Impacto**: Infraestrutura completa de C&C com múltiplos canais de comunicação.

### 7. EVASÃO E OFUSCAÇÃO - NÍVEL ALTO 

#### `tools/args_wrap/args_wraper.py`
```python
def serialize_args():
    # Serialização pickle + base64 para evasão de AV/EDR
    return base64.b64encode(pickle.dumps(args))
```

**Impacto**: Técnicas de evasão para contornar detecção de antivírus.

### 8. SURVEILLANCE E RECONHECIMENTO - NÍVEL ALTO 

#### `tools/check/checking.py`
```python
def checkCamera():
    # Acesso e teste de webcams para surveillance

def checkNetwork():
    # Enumeração completa de interfaces de rede
```

**Impacto**: Capacidades de espionagem e reconhecimento de ambiente.

---

## VALORES HARDCODED CRÍTICOS

### INFRAESTRUTURA DE REDE IDENTIFICADA

#### Servidores de Controle
```python
# IPs da infraestrutura de comando
"10.10.3.119"        # Servidor MCP principal (mcp_client.py)
"10.10.3.248:1611"   # Console de comandos (agent_test.py)
"10.10.5.2:8000"     # Servidor LLM personalizado (agent_test.py)
```

#### Alvos de Teste
```python
"100.64.0.33"        # Alvo de reconhecimento web (browser.py)
"100.64.0.41"        # Teste de conectividade (agent_with_tools.py)
```

#### Endpoints Suspeitos
```python
"api.aabao.vip"      # Endpoint não oficial OpenAI (iniworker.py)
```

### CREDENCIAIS E PROXIES HARDCODED

#### `tools/check/checking.py:113`
```python
proxy = "https://huancun:ylq123..@home.hc26.org:5422"
```

#### `tools/ini/iniworker.py`
```python
config = {
    "openai_api_endpoint": "https://api.aabao.vip/v1"  # ENDPOINT SUSPEITO
}
```

### MODELOS IA ESPECIALIZADOS EM HACKING

#### `scheduler/agentManager.py`
```python
class AgentModel(Enum):
    AL_1S_CTF_VER = "al-1s-ctf-ver"  # Especializado em CTF
    QwQ_32B = "qwq-32b"              # Modelo avançado
    HIVE = "hive"                    # Modelo personalizado
```

### CONFIGURAÇÕES PERIGOSAS

#### Timeouts Extensos
```python
timeout = 4 * 60 * 60  # 4 horas para operações (mcp_client.py)
temperature = 0.95     # Alta criatividade em LLMs (init.py)
```

#### Portas Padrão
```python
port = 37695          # Porta padrão do servidor (boot.py)
```

---

## ANÁLISE DE CAPACIDADES MALICIOSAS

### AUTOMAÇÃO COMPLETA DE ATAQUES
1. **Reconhecimento**: Scanning massivo de redes (CIDR expansion)
2. **Exploração**: Nuclei, MSFConsole automatizados
3. **Pós-exploração**: Escalação de privilégios automática
4. **Persistência**: Canais C&C com reconexão automática
5. **Exfiltração**: Múltiplos canais de dados

### EVASÃO AVANÇADA
1. **Ofuscação**: Base64 + Pickle serialization
2. **Proxies**: Sistema de mascaramento de IP
3. **Retry**: Contorno automático de defesas
4. **Stealth**: Tráfego disfarçado como legítimo

### INFRAESTRUTURA DISTRIBUÍDA
1. **Sistema de âncoras**: Múltiplos pontos de controle
2. **Failover**: Reconexão automática em falhas
3. **Load balancing**: Distribuição de operações
4. **Redundância**: Múltiplos canais de comunicação

---

## INDICADORES DE COMPROMETIMENTO (IOCs)

### Endereços IP
- 10.10.3.119 (Servidor MCP)
- 10.10.3.248 (Console)
- 10.10.5.2 (LLM Server)
- 100.64.0.33 (Target)
- 100.64.0.41 (Test)

### Domínios
- api.aabao.vip
- home.hc26.org

### Portas
- 37695 (Villager Server)
- 1611 (Console)
- 8000 (LLM)
- 5422 (Proxy)

### Processos
- villager serve
- nuclei
- msfconsole

### Arquivos
- *.mermaid (Task graphs)
- RAGL.sqlite (Exploit database)
- console_agent.log

---

## RECOMENDAÇÕES DE MITIGAÇÃO IMEDIATA

### 1. BLOQUEIO DE REDE
```bash
# Bloquear comunicação com infraestrutura
iptables -A OUTPUT -d 10.10.3.0/24 -j DROP
iptables -A OUTPUT -d 100.64.0.0/24 -j DROP
```

### 2. DETECÇÃO DE COMPORTAMENTO
- Monitorar execução de `eval()` e `subprocess.run()`
- Detectar reconexões automáticas TCP
- Alertar sobre serialização pickle + base64

### 3. ANÁLISE FORENSE
- Capturar todo tráfego de rede
- Analisar logs de sistema
- Investigar alterações de privilégios

### 4. QUARENTENA
- Isolar completamente sistemas comprometidos
- Revogar credenciais de API
- Resetar senhas de usuários

---

## CONCLUSÃO CRÍTICA

O Villager-NG representa uma **AMEAÇA DE SEGURANÇA EXTREMA** que combina:

1. **Capacidades de APT** (Advanced Persistent Threat)
2. **Infraestrutura de Botnet** profissional
3. **Automação de Malware** com IA
4. **Ferramentas de Pentest** militarizadas

### CLASSIFICAÇÃO FINAL: **MALWARE AVANÇADO COM CAPACIDADES DE BOTNET**

**RECOMENDAÇÃO**: Tratamento como malware de alta sofisticação com notificação às autoridades competentes se apropriado.

---

**ESTE DOCUMENTO DEVE SER TRATADO COMO CONFIDENCIAL E COMPARTILHADO APENAS COM PESSOAL AUTORIZADO DE SEGURANÇA**