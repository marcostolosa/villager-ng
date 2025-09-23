# -*- coding: utf-8 -*-
"""
Arquivo de configuração do Villager-NG
Contém todas as configurações de sistema, APIs e variáveis de ambiente.

IMPORTANTE: Este arquivo contém configurações para fins educacionais.
            Em produção, usar variáveis de ambiente e cofres seguros.
"""

import os
from typing import Dict, Any

# ====================================================================
# CONFIGURAÇÕES DE SERVIDOR
# ====================================================================

SERVER_CONFIG = {
    "host": os.getenv("VILLAGER_HOST", "127.0.0.1"),
    "port": int(os.getenv("VILLAGER_PORT", "37695")),
    "debug": os.getenv("VILLAGER_DEBUG", "False").lower() == "true",
    "workers": int(os.getenv("VILLAGER_WORKERS", "1")),
}

# ====================================================================
# CONFIGURAÇÕES DE LOGGING
# ====================================================================

LOGGING_CONFIG = {
    "level": os.getenv("LOGGING_LEVEL", "INFO"),
    "format": os.getenv("LOGGING_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
    "file": os.getenv("LOGGING_FILE", "villager.log"),
    "max_size": os.getenv("LOGGING_MAX_SIZE", "10MB"),
    "backup_count": int(os.getenv("LOGGING_BACKUP_COUNT", "5")),
}

# ====================================================================
# CONFIGURAÇÕES DE IA / LLM
# ====================================================================

# AVISO: Em produção, NUNCA colocar API keys no código!
# Usar variáveis de ambiente ou serviços de gerenciamento de segredos

LLM_CONFIG = {
    # OpenAI Configuration
    "openai": {
        "api_key": os.getenv("OPENAI_API_KEY", ""),  # Definir como variável de ambiente
        "base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        "model": os.getenv("OPENAI_MODEL", "gpt-3.5-turbo"),
        "temperature": float(os.getenv("OPENAI_TEMPERATURE", "0.95")),
        "max_tokens": int(os.getenv("OPENAI_MAX_TOKENS", "2048")),
        "timeout": int(os.getenv("OPENAI_TIMEOUT", "30")),
    },

    # Configuração para modelos locais
    "local": {
        "base_url": os.getenv("LOCAL_LLM_URL", "http://localhost:8000"),
        "model": os.getenv("LOCAL_LLM_MODEL", "hive"),
        "timeout": int(os.getenv("LOCAL_LLM_TIMEOUT", "300")),
    },

    # Configuração para modelos especializados
    "specialized": {
        "ctf_model": os.getenv("CTF_MODEL", "al-1s-ctf-ver"),
        "reasoning_model": os.getenv("REASONING_MODEL", "qwq-32b"),
        "hive_model": os.getenv("HIVE_MODEL", "hive"),
    }
}

# ====================================================================
# CONFIGURAÇÕES MCP (Model Context Protocol)
# ====================================================================

# AVISO: IPs hardcoded para fins educacionais
# Em produção, configurar dinamicamente

MCP = {
    "client": {
        "base_url": os.getenv("MCP_CLIENT_URL", "http://127.0.0.1:25989"),
        "timeout": int(os.getenv("MCP_TIMEOUT", "14400")),  # 4 horas em segundos
        "retry_attempts": int(os.getenv("MCP_RETRY", "3")),
        "retry_delay": int(os.getenv("MCP_RETRY_DELAY", "5")),
    },

    "server": {
        # DEMONSTRAÇÃO: Servidores hardcoded encontrados (APENAS EDUCACIONAL)
        "kali_driver": os.getenv("KALI_DRIVER_URL", "http://10.10.3.119:25989"),
        "browser_use": os.getenv("BROWSER_USE_URL", "http://10.10.3.119:25990"),
        "console": os.getenv("MCP_CONSOLE_URL", "http://10.10.3.248:1611"),
        "llm_server": os.getenv("LLM_SERVER_URL", "http://10.10.5.2:8000"),
    }
}

# ====================================================================
# CONFIGURAÇÕES DE REDE E PROXY
# ====================================================================

NETWORK_CONFIG = {
    # Configurações de proxy (EDUCACIONAL)
    "proxy": {
        "enabled": os.getenv("PROXY_ENABLED", "False").lower() == "true",
        "http": os.getenv("HTTP_PROXY", ""),
        "https": os.getenv("HTTPS_PROXY", ""),

        # DEMONSTRAÇÃO: Proxy hardcoded encontrado (APENAS EDUCACIONAL)
        "example_proxy": "https://huancun:SENHA_CENSURADA@home.hc26.org:5422"
    },

    # Configurações de timeout
    "timeouts": {
        "connect": int(os.getenv("CONNECT_TIMEOUT", "10")),
        "read": int(os.getenv("READ_TIMEOUT", "30")),
        "total": int(os.getenv("TOTAL_TIMEOUT", "60")),
    },

    # IPs de teste e alvos (EDUCACIONAL)
    "test_targets": {
        "connectivity_test": os.getenv("CONNECTIVITY_TEST_IP", "100.64.0.41"),
        "recon_target": os.getenv("RECON_TARGET_IP", "100.64.0.33"),
    }
}

# ====================================================================
# CONFIGURAÇÕES DE SEGURANÇA
# ====================================================================

SECURITY_CONFIG = {
    # Configurações de execução segura
    "execution": {
        "max_execution_time": int(os.getenv("MAX_EXECUTION_TIME", "300")),  # 5 minutos
        "sandbox_mode": os.getenv("SANDBOX_MODE", "True").lower() == "true",
        "allow_eval": os.getenv("ALLOW_EVAL", "False").lower() == "true",  # PERIGOSO!
        "allow_system_commands": os.getenv("ALLOW_SYSTEM_COMMANDS", "False").lower() == "true",  # PERIGOSO!
    },

    # Lista branca de comandos permitidos
    "allowed_commands": [
        "ls", "pwd", "whoami", "date", "echo", "cat",
        "grep", "find", "head", "tail", "wc"
    ],

    # Configurações de auditoria
    "audit": {
        "log_all_commands": os.getenv("LOG_ALL_COMMANDS", "True").lower() == "true",
        "log_api_calls": os.getenv("LOG_API_CALLS", "True").lower() == "true",
        "log_file_access": os.getenv("LOG_FILE_ACCESS", "True").lower() == "true",
    }
}

# ====================================================================
# CONFIGURAÇÕES DO RAG (Retrieval-Augmented Generation)
# ====================================================================

RAG_CONFIG = {
    "database": {
        "path": os.getenv("RAG_DB_PATH", "scheduler/core/RAGLibrary/RAGL.sqlite"),
        "backup_path": os.getenv("RAG_BACKUP_PATH", "backups/RAGL_backup.sqlite"),
    },

    "embeddings": {
        "model": os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2"),
        "dimension": int(os.getenv("EMBEDDING_DIMENSION", "384")),
        "batch_size": int(os.getenv("EMBEDDING_BATCH_SIZE", "32")),
    },

    "search": {
        "max_results": int(os.getenv("RAG_MAX_RESULTS", "5")),
        "similarity_threshold": float(os.getenv("RAG_SIMILARITY_THRESHOLD", "0.7")),
    }
}

# ====================================================================
# CONFIGURAÇÕES DE FERRAMENTAS
# ====================================================================

TOOLS_CONFIG = {
    # Configurações de verificação de ambiente
    "environment_check": {
        "min_memory_mb": int(os.getenv("MIN_MEMORY_MB", "256")),
        "check_camera": os.getenv("CHECK_CAMERA", "False").lower() == "true",
        "check_network": os.getenv("CHECK_NETWORK", "True").lower() == "true",
    },

    # Configurações de ferramentas externas
    "external_tools": {
        "nuclei_path": os.getenv("NUCLEI_PATH", "/usr/bin/nuclei"),
        "nmap_path": os.getenv("NMAP_PATH", "/usr/bin/nmap"),
        "msfconsole_path": os.getenv("MSFCONSOLE_PATH", "/usr/bin/msfconsole"),
    }
}

# ====================================================================
# CONFIGURAÇÕES DE DESENVOLVIMENTO
# ====================================================================

DEV_CONFIG = {
    "debug_mode": os.getenv("DEBUG_MODE", "False").lower() == "true",
    "reload_on_change": os.getenv("RELOAD_ON_CHANGE", "False").lower() == "true",
    "enable_profiling": os.getenv("ENABLE_PROFILING", "False").lower() == "true",
    "mock_external_services": os.getenv("MOCK_EXTERNAL", "False").lower() == "true",
}

# ====================================================================
# CONFIGURAÇÕES DE TESTE
# ====================================================================

TEST_CONFIG = {
    "test_mode": os.getenv("TEST_MODE", "False").lower() == "true",
    "isolated_environment": os.getenv("ISOLATED_ENV", "True").lower() == "true",
    "skip_network_tests": os.getenv("SKIP_NETWORK_TESTS", "True").lower() == "true",
    "mock_dangerous_functions": os.getenv("MOCK_DANGEROUS", "True").lower() == "true",
}

# ====================================================================
# FUNÇÕES AUXILIARES
# ====================================================================

def get_config(section: str) -> Dict[str, Any]:
    """
    Obtém seção específica de configuração.

    Args:
        section: Nome da seção (server, logging, llm, etc.)

    Returns:
        Dicionário com configurações da seção
    """
    config_map = {
        "server": SERVER_CONFIG,
        "logging": LOGGING_CONFIG,
        "llm": LLM_CONFIG,
        "mcp": MCP,
        "network": NETWORK_CONFIG,
        "security": SECURITY_CONFIG,
        "rag": RAG_CONFIG,
        "tools": TOOLS_CONFIG,
        "dev": DEV_CONFIG,
        "test": TEST_CONFIG,
    }

    return config_map.get(section, {})

def is_production() -> bool:
    """Verifica se está executando em produção."""
    return os.getenv("ENVIRONMENT", "development").lower() == "production"

def is_test_mode() -> bool:
    """Verifica se está em modo de teste."""
    return TEST_CONFIG["test_mode"]

def is_debug_mode() -> bool:
    """Verifica se está em modo debug."""
    return DEV_CONFIG["debug_mode"]

def validate_config() -> bool:
    """
    Valida configurações críticas.

    Returns:
        True se configurações estão válidas, False caso contrário
    """
    errors = []

    # Verificar configurações de segurança em produção
    if is_production():
        if SECURITY_CONFIG["execution"]["allow_eval"]:
            errors.append("ERRO: eval() habilitado em produção!")

        if SECURITY_CONFIG["execution"]["allow_system_commands"]:
            errors.append("ERRO: comandos de sistema habilitados em produção!")

        if not LLM_CONFIG["openai"]["api_key"]:
            errors.append("AVISO: API key do OpenAI não configurada")

    # Verificar configurações de rede
    if not NETWORK_CONFIG["timeouts"]["connect"] > 0:
        errors.append("ERRO: timeout de conexão inválido")

    # Mostrar erros/avisos
    for error in errors:
        print(f"CONFIG VALIDATION: {error}")

    return len([e for e in errors if e.startswith("ERRO:")]) == 0

# ====================================================================
# INICIALIZAÇÃO
# ====================================================================

# Validar configurações ao importar
if __name__ == "__main__":
    print("=== VALIDAÇÃO DE CONFIGURAÇÃO ===")
    print(f"Ambiente: {'PRODUÇÃO' if is_production() else 'DESENVOLVIMENTO'}")
    print(f"Modo teste: {is_test_mode()}")
    print(f"Modo debug: {is_debug_mode()}")

    if validate_config():
        print("✓ Configurações válidas")
    else:
        print("✗ Problemas de configuração encontrados")

    # Mostrar configurações (sem dados sensíveis)
    print(f"\nServidor: {SERVER_CONFIG['host']}:{SERVER_CONFIG['port']}")
    print(f"Logging: {LOGGING_CONFIG['level']}")
    print(f"Sandbox: {SECURITY_CONFIG['execution']['sandbox_mode']}")
else:
    # Validação silenciosa quando importado
    validate_config()

# ====================================================================
# EXEMPLO DE USO
# ====================================================================

"""
Exemplo de uso das configurações:

from config import get_config, is_test_mode

# Obter configurações específicas
server_config = get_config("server")
llm_config = get_config("llm")

# Verificar modo de execução
if is_test_mode():
    print("Executando em modo de teste")

# Usar configurações
app.run(
    host=server_config["host"],
    port=server_config["port"],
    debug=server_config["debug"]
)
"""