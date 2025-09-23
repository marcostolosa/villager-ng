"""
Módulo de geolocalização aproximada de endereços IP
Este módulo fornece funcionalidades para determinar a localização geográfica aproximada
de endereços IP utilizando APIs públicas de geolocalização.

PROPÓSITO TÉCNICO:
- Geolocalização de alvos durante reconnaissance
- Análise de infraestrutura geográfica de redes
- Identificação de localização de servidores e endpoints
- Cálculo de distâncias geográficas entre pontos

FUNCIONALIDADES:
- Consulta de geolocalização via API ip-api.com
- Cálculo de distância geodésica entre coordenadas
- Sistema de retry automático para requisições falhas
- Tratamento robusto de erros de rede

APLICAÇÃO NO VILLAGER-NG:
- Mapeamento geográfico de infraestrutura de alvos
- Identificação de CDNs e servidores distribuídos
- Análise de padrões geográficos de rede
- Intelligence gathering sobre localização física

DEPENDÊNCIAS:
- requests: Para requisições HTTP à API de geolocalização
- geopy: Para cálculos geodésicos precisos

LIMITAÇÕES:
- Precisão limitada pela qualidade da base de dados do provedor
- Rate limiting da API pública (45 req/min para ip-api.com)
- Geolocalização pode ser imprecisa para VPNs/proxies
"""

import logging
import time
import requests
from geopy.distance import geodesic


def get_geo_from_ip(ip, max_retries=5, retry_delay=1):
    """
    Obter coordenadas geográficas (latitude/longitude) de um endereço IP.

    Utiliza a API pública ip-api.com para consultar informações de geolocalização.
    Implementa sistema de retry automático para lidar com falhas temporárias.

    Args:
        ip (str): Endereço IP para geolocalização (IPv4 ou IPv6)
        max_retries (int): Número máximo de tentativas (padrão: 5)
        retry_delay (int): Delay entre tentativas em segundos (padrão: 1)

    Returns:
        dict: Dicionário contendo:
            - latitude (float): Latitude em graus decimais
            - longitude (float): Longitude em graus decimais
            - country (str): País identificado
            - city (str): Cidade identificada
            - isp (str): Provedor de internet
        None: Se todas as tentativas falharam

    Raises:
        ValueError: Se o IP fornecido for inválido
        requests.RequestException: Para erros de rede persistentes

    Exemplo:
        >>> get_geo_from_ip("8.8.8.8")
        {
            'latitude': 37.751,
            'longitude': -97.822,
            'country': 'United States',
            'city': 'Mountain View',
            'isp': 'Google LLC'
        }
    """
    if not ip or not isinstance(ip, str):
        raise ValueError(f"IP inválido fornecido: {ip}")

    for attempt in range(max_retries):
        try:
            # API ip-api.com - gratuita com limite de 45 req/min
            url = f'http://ip-api.com/json/{ip}'

            # Configurar timeout e headers para requisição
            headers = {
                'User-Agent': 'Villager-NG-GeoLookup/1.0',
                'Accept': 'application/json'
            }

            response = requests.get(url, timeout=30, headers=headers)
            data = response.json()

            # Verificar sucesso da API
            if response.status_code == 200 and data.get('status') == 'success':
                return {
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'zip_code': data.get('zip', 'Unknown')
                }
            else:
                # Log específico para falhas da API
                error_msg = data.get('message', 'Resposta inválida da API')
                logging.warning(f"Tentativa {attempt + 1}: Falha na geolocalização de {ip} - {error_msg}")

        except requests.RequestException as e:
            logging.error(f"Tentativa {attempt + 1}: Erro de rede ao consultar IP {ip}: {e}")
        except ValueError as e:
            logging.error(f"Tentativa {attempt + 1}: Erro de parsing JSON para IP {ip}: {e}")
        except Exception as e:
            logging.error(f"Tentativa {attempt + 1}: Erro inesperado ao consultar IP {ip}: {e}")

        # Aguardar antes da próxima tentativa (exceto na última)
        if attempt < max_retries - 1:
            time.sleep(retry_delay)

    logging.error(f"Falha após {max_retries} tentativas para IP {ip}")
    return None


def calculate_ip_distance(ip, target_latitude, target_longitude):
    """
    Calcular distância geodésica entre um IP e coordenadas de referência.

    Determina a localização geográfica do IP e calcula a distância em linha reta
    até as coordenadas de referência fornecidas.

    Args:
        ip (str): Endereço IP para geolocalização
        target_latitude (float): Latitude de referência em graus decimais
        target_longitude (float): Longitude de referência em graus decimais

    Returns:
        dict: Dicionário contendo:
            - distance_km (float): Distância em quilômetros
            - distance_miles (float): Distância em milhas
            - ip_location (dict): Informações de geolocalização do IP
            - target_location (tuple): Coordenadas de referência
        None: Se a geolocalização falhar

    Exemplo:
        >>> calculate_ip_distance("8.8.8.8", -23.5505, -46.6333)  # São Paulo
        {
            'distance_km': 10847.2,
            'distance_miles': 6741.8,
            'ip_location': {...},
            'target_location': (-23.5505, -46.6333)
        }
    """
    # Validar parâmetros de entrada
    if not isinstance(target_latitude, (int, float)) or not isinstance(target_longitude, (int, float)):
        raise ValueError("Coordenadas de referência devem ser números")

    if not (-90 <= target_latitude <= 90) or not (-180 <= target_longitude <= 180):
        raise ValueError("Coordenadas de referência fora do range válido")

    # Obter localização do IP
    ip_geo = get_geo_from_ip(ip)
    if not ip_geo or not ip_geo.get('latitude') or not ip_geo.get('longitude'):
        logging.error(f"Não foi possível obter geolocalização válida para IP {ip}")
        return None

    ip_latitude = ip_geo['latitude']
    ip_longitude = ip_geo['longitude']

    # Calcular distância geodésica usando geopy
    try:
        target_coords = (target_latitude, target_longitude)
        ip_coords = (ip_latitude, ip_longitude)

        distance = geodesic(target_coords, ip_coords)

        return {
            'distance_km': round(distance.kilometers, 2),
            'distance_miles': round(distance.miles, 2),
            'ip_location': ip_geo,
            'target_location': target_coords,
            'ip_coordinates': ip_coords
        }

    except Exception as e:
        logging.error(f"Erro ao calcular distância geodésica: {e}")
        return None


def judg_rough_ip2loc_dist(ip, latitude, longitude):
    """
    Função legada para compatibilidade com código existente.

    Args:
        ip (str): Endereço IP
        latitude (float): Latitude de referência
        longitude (float): Longitude de referência

    Returns:
        float: Distância em quilômetros, ou None se houver erro
    """
    result = calculate_ip_distance(ip, latitude, longitude)
    return result['distance_km'] if result else None


def bulk_geolocate_ips(ip_list, delay_between_requests=1.5):
    """
    Geolocalizar múltiplos IPs em lote respeitando rate limits.

    Args:
        ip_list (list): Lista de endereços IP
        delay_between_requests (float): Delay entre requisições para respeitar rate limit

    Returns:
        dict: Mapeamento IP -> informações de geolocalização

    Exemplo:
        >>> bulk_geolocate_ips(["8.8.8.8", "1.1.1.1"])
        {
            "8.8.8.8": {"latitude": 37.751, ...},
            "1.1.1.1": {"latitude": -27.4766, ...}
        }
    """
    results = {}
    total_ips = len(ip_list)

    logging.info(f"Iniciando geolocalização de {total_ips} endereços IP")

    for i, ip in enumerate(ip_list, 1):
        logging.info(f"Processando IP {i}/{total_ips}: {ip}")

        geo_info = get_geo_from_ip(ip)
        results[ip] = geo_info

        # Respeitar rate limit (exceto no último IP)
        if i < total_ips:
            time.sleep(delay_between_requests)

    success_count = sum(1 for result in results.values() if result is not None)
    logging.info(f"Geolocalização concluída: {success_count}/{total_ips} sucessos")

    return results


if __name__ == "__main__":
    # Teste de funcionalidade
    test_ips = [
        "8.8.8.8",          # Google DNS
        "1.1.1.1",          # Cloudflare DNS
        "208.67.222.222",   # OpenDNS
        "208.67.220.220"    # OpenDNS
    ]

    # Coordenadas de referência (São Paulo, Brasil)
    ref_lat, ref_lon = -23.5505, -46.6333

    print("=== Teste de Geolocalização ===")
    for ip in test_ips:
        print(f"\nTestando IP: {ip}")

        # Teste de geolocalização simples
        geo_info = get_geo_from_ip(ip)
        if geo_info:
            print(f"  Localização: {geo_info['city']}, {geo_info['country']}")
            print(f"  Coordenadas: {geo_info['latitude']}, {geo_info['longitude']}")
            print(f"  ISP: {geo_info['isp']}")

            # Teste de cálculo de distância
            distance_info = calculate_ip_distance(ip, ref_lat, ref_lon)
            if distance_info:
                print(f"  Distância de São Paulo: {distance_info['distance_km']} km")
        else:
            print(f"  Falha na geolocalização")

    print("\n=== Teste de Geolocalização em Lote ===")
    bulk_results = bulk_geolocate_ips(test_ips[:2])  # Testar apenas 2 IPs
    for ip, result in bulk_results.items():
        if result:
            print(f"{ip}: {result['city']}, {result['country']}")
        else:
            print(f"{ip}: Falha")
