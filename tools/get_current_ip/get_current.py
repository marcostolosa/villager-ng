import logging

import requests


def get_current_ip():
    """
    Obter IP atual de forma estável usando múltiplos métodos
    :return:
    """
    try:
        # Obter através de requisição para api.ipify.org
        ip = requests.get('https://api.ipify.org',timeout=10).text.strip()
        return ip.replace('\n', '')
    except Exception as e:
        logging.error(f"Falha na requisição para api.ipify.org {e}")
    try:
        # Obter através de requisição para httpbin.org
        ip = requests.get('http://httpbin.org/ip',timeout=10).json()['origin']
        return ip.replace('\n', '')
    except Exception as e:
        logging.error(f"Falha na requisição para httpbin.org {e}")
    return None


# print(get_current_ip())
