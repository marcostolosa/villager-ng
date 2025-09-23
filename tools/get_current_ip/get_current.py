"""
Módulo de detecção de IP público externo
Este módulo fornece funcionalidades para determinar o endereço IP público real
do sistema em execução, utilizando múltiplos serviços externos como fallback.

PROPÓSITO TÉCNICO:
- Detecção do IP público real para operações de networking
- Identificação da interface de saída para internet
- Verificação de conectividade externa
- Bypass de NAT/firewall para determinar IP real

FUNCIONALIDADES:
- Múltiplos provedores de IP para redundância
- Sistema de fallback automático entre serviços
- Sanitização automática de resposta
- Tratamento robusto de timeouts e erros de rede

APLICAÇÃO NO VILLAGER-NG:
- Identificação do IP de origem para operações de pentest
- Configuração automática de payloads com IP de callback
- Verificação de conectividade antes de operações remotas
- Setup de reverse shells e conexões de retorno

PROVEDORES UTILIZADOS:
- api.ipify.org (HTTPS) - Serviço primário confiável
- httpbin.org (HTTP) - Serviço de fallback com JSON

CONSIDERAÇÕES DE SEGURANÇA:
- Expõe IP público para serviços externos
- Pode revelar localização aproximada do operador
- Logs de acesso podem ser mantidos pelos provedores
"""

import logging
import time
import requests
from typing import Optional


def get_current_ip(timeout: int = 10, max_retries: int = 3) -> Optional[str]:
    """
    Obter endereço IP público atual usando múltiplos serviços externos.

    Implementa sistema de fallback robusto entre diferentes provedores de IP
    para garantir alta disponibilidade e confiabilidade na detecção.

    Args:
        timeout (int): Timeout para requisições HTTP em segundos (padrão: 10)
        max_retries (int): Número máximo de tentativas por serviço (padrão: 3)

    Returns:
        str: Endereço IP público em formato string (ex: "203.0.113.45")
        None: Se todos os métodos falharam

    Raises:
        requests.RequestException: Para erros persistentes de rede
        ValueError: Para respostas malformadas dos serviços

    Exemplo:
        >>> get_current_ip()
        '203.0.113.45'

        >>> get_current_ip(timeout=5, max_retries=2)
        '198.51.100.123'
    """
    # Lista de provedores de IP com métodos diferentes
    ip_providers = [
        {
            'name': 'ipify.org',
            'url': 'https://api.ipify.org',
            'method': 'text',
            'secure': True
        },
        {
            'name': 'httpbin.org',
            'url': 'http://httpbin.org/ip',
            'method': 'json',
            'json_key': 'origin',
            'secure': False
        },
        {
            'name': 'icanhazip.com',
            'url': 'http://icanhazip.com',
            'method': 'text',
            'secure': False
        },
        {
            'name': 'checkip.amazonaws.com',
            'url': 'https://checkip.amazonaws.com',
            'method': 'text',
            'secure': True
        }
    ]

    for provider in ip_providers:
        for attempt in range(max_retries):
            try:
                logging.debug(f"Tentativa {attempt + 1} para {provider['name']}")

                # Configurar headers para aparentar tráfego legítimo
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive'
                }

                # Fazer requisição HTTP
                response = requests.get(
                    provider['url'],
                    timeout=timeout,
                    headers=headers,
                    verify=provider.get('secure', True)  # Verificar SSL apenas para HTTPS
                )

                response.raise_for_status()  # Levantar exceção para códigos de erro HTTP

                # Processar resposta baseado no método
                if provider['method'] == 'text':
                    ip_address = response.text.strip()
                elif provider['method'] == 'json':
                    json_data = response.json()
                    ip_address = json_data.get(provider['json_key'], '').strip()
                else:
                    raise ValueError(f"Método desconhecido: {provider['method']}")

                # Validar formato de IP
                ip_address = sanitize_ip_response(ip_address)
                if validate_ip_format(ip_address):
                    logging.info(f"IP público obtido via {provider['name']}: {ip_address}")
                    return ip_address
                else:
                    raise ValueError(f"Formato de IP inválido recebido: {ip_address}")

            except requests.RequestException as e:
                logging.warning(f"Erro de rede ao consultar {provider['name']} (tentativa {attempt + 1}): {e}")
            except ValueError as e:
                logging.warning(f"Erro de parsing em {provider['name']} (tentativa {attempt + 1}): {e}")
            except Exception as e:
                logging.error(f"Erro inesperado em {provider['name']} (tentativa {attempt + 1}): {e}")

            # Aguardar antes da próxima tentativa (exceto na última)
            if attempt < max_retries - 1:
                time.sleep(1)

    # Se todos os provedores falharam
    logging.error("Falha ao obter IP público após tentar todos os provedores")
    return None


def sanitize_ip_response(ip_string: str) -> str:
    """
    Limpar e sanitizar resposta de IP de serviços externos.

    Args:
        ip_string (str): String bruta retornada pelo serviço

    Returns:
        str: IP limpo e sanitizado
    """
    if not ip_string:
        return ""

    # Remover quebras de linha, espaços e caracteres especiais
    sanitized = ip_string.strip().replace('\n', '').replace('\r', '')

    # Extrair apenas o primeiro IP se houver múltiplos (para casos como httpbin)
    if ',' in sanitized:
        sanitized = sanitized.split(',')[0].strip()

    return sanitized


def validate_ip_format(ip_address: str) -> bool:
    """
    Validar se string representa um endereço IP válido.

    Args:
        ip_address (str): String para validação

    Returns:
        bool: True se for IP válido, False caso contrário
    """
    if not ip_address or not isinstance(ip_address, str):
        return False

    try:
        import ipaddress
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def get_detailed_ip_info(include_geolocation: bool = False) -> Optional[dict]:
    """
    Obter informações detalhadas sobre o IP público atual.

    Args:
        include_geolocation (bool): Se deve incluir dados de geolocalização

    Returns:
        dict: Informações detalhadas do IP ou None se falhar
    """
    current_ip = get_current_ip()
    if not current_ip:
        return None

    result = {
        'ip_address': current_ip,
        'timestamp': time.time(),
        'is_private': False,  # Por definição, IPs obtidos externamente são públicos
        'version': 'IPv4' if '.' in current_ip else 'IPv6'
    }

    # Adicionar geolocalização se solicitado
    if include_geolocation:
        try:
            # Importar módulo de geolocalização se disponível
            from .ip2locRough.ip2locRough import get_geo_from_ip
            geo_info = get_geo_from_ip(current_ip)
            if geo_info:
                result['geolocation'] = geo_info
        except ImportError:
            logging.warning("Módulo de geolocalização não disponível")
        except Exception as e:
            logging.error(f"Erro ao obter geolocalização: {e}")

    return result


if __name__ == "__main__":
    # Teste de funcionalidade
    print("=== Teste de Detecção de IP Público ===")

    # Teste básico
    ip = get_current_ip()
    if ip:
        print(f"IP público detectado: {ip}")

        # Validar formato
        if validate_ip_format(ip):
            print(f"✓ Formato válido: {ip}")
        else:
            print(f"✗ Formato inválido: {ip}")

        # Teste de informações detalhadas
        detailed_info = get_detailed_ip_info()
        if detailed_info:
            print(f"Informações detalhadas:")
            for key, value in detailed_info.items():
                print(f"  {key}: {value}")
    else:
        print("✗ Falha ao detectar IP público")

    # Teste com parâmetros customizados
    print("\n=== Teste com Timeout Curto ===")
    ip_fast = get_current_ip(timeout=3, max_retries=1)
    print(f"IP com timeout curto: {ip_fast or 'Falhou'}")
