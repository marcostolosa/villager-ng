"""
Módulo de conversão CIDR para lista de IPs
Este módulo fornece funcionalidades para expandir notação CIDR em listas completas de endereços IP.
Usado no framework Villager-NG para reconnaissance de rede e scanning massivo de alvos.

PROPÓSITO TÉCNICO:
- Expansão de faixas de rede CIDR (ex: 192.168.1.0/24)
- Geração automática de listas de alvos para scanning
- Suporte a operações de reconhecimento em larga escala

FUNCIONALIDADES:
- Conversão CIDR para lista de IPs individuais
- Validação de formato CIDR
- Tratamento de exceções para entradas inválidas

EXEMPLO DE USO:
    cidr_to_ip_list("192.168.1.0/24")
    # Retorna: ['192.168.1.1', '192.168.1.2', ..., '192.168.1.254']

APLICAÇÃO NO VILLAGER-NG:
- Preprocessing de alvos para ferramentas como Nuclei
- Definição de escopo de scanning automatizado
- Geração de listas de IPs para exploitation
"""

import ipaddress


def cidr_to_ip_list(cidr):
    """
    Converter faixa CIDR para lista completa de endereços IP válidos.

    Esta função expande uma notação CIDR em todos os endereços IP host válidos
    dentro da faixa especificada. Exclui automaticamente endereços de rede
    e broadcast.

    Args:
        cidr (str): Notação CIDR, exemplo '192.168.1.0/24' ou '10.0.0.0/16'

    Returns:
        list: Lista de strings contendo todos os endereços IP host válidos

    Raises:
        ValueError: Se o formato CIDR for inválido ou malformado

    Exemplos:
        >>> cidr_to_ip_list("192.168.1.0/30")
        ['192.168.1.1', '192.168.1.2']

        >>> cidr_to_ip_list("10.0.0.0/24")
        ['10.0.0.1', '10.0.0.2', ..., '10.0.0.254']

    Nota:
        Para redes /31 e /32, comportamento especial conforme RFC 3021:
        - /32: Retorna apenas o endereço especificado
        - /31: Retorna ambos os endereços (sem rede/broadcast)
    """
    try:
        # Criar objeto de rede IPv4/IPv6 usando biblioteca ipaddress
        network = ipaddress.ip_network(cidr, strict=False)

        # Extrair apenas endereços host válidos (exclui rede e broadcast)
        # Para /31 e /32, network.hosts() já trata corretamente
        host_list = [str(ip) for ip in network.hosts()]

        # Para redes /32, network.hosts() retorna vazio, então retornar o próprio IP
        if network.prefixlen == 32:
            host_list = [str(network.network_address)]

        return host_list

    except ValueError as e:
        raise ValueError(f"Formato CIDR inválido: {cidr}, erro detalhado: {e}")
    except Exception as e:
        raise RuntimeError(f"Erro inesperado ao processar CIDR {cidr}: {e}")


def get_network_info(cidr):
    """
    Obter informações detalhadas sobre uma rede CIDR.

    Args:
        cidr (str): Notação CIDR

    Returns:
        dict: Informações da rede incluindo:
            - network_address: Endereço de rede
            - broadcast_address: Endereço de broadcast
            - netmask: Máscara de rede
            - num_hosts: Número total de hosts possíveis
            - prefixlen: Comprimento do prefixo
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)

        return {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'num_hosts': network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses,
            'prefixlen': network.prefixlen,
            'is_private': network.is_private,
            'is_multicast': network.is_multicast,
            'is_reserved': network.is_reserved
        }

    except ValueError as e:
        raise ValueError(f"Erro ao analisar rede CIDR {cidr}: {e}")


if __name__ == "__main__":
    # Teste de funcionalidade
    test_cidrs = [
        "192.168.1.0/24",
        "10.0.0.0/30",
        "172.16.1.0/28",
        "127.0.0.1/32"
    ]

    for cidr in test_cidrs:
        try:
            ips = cidr_to_ip_list(cidr)
            info = get_network_info(cidr)
            print(f"CIDR: {cidr}")
            print(f"  Hosts: {len(ips)} endereços")
            print(f"  Rede: {info['network_address']}")
            print(f"  Broadcast: {info['broadcast_address']}")
            print(f"  Primeiros IPs: {ips[:5]}")
            print("---")
