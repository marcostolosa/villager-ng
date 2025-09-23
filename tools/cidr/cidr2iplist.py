import ipaddress


def cidr_to_ip_list(cidr):
    """
    Converter faixa CIDR para lista de endereços IP
    :param cidr: str, exemplo '0.0.0.0/24'
    :return: list, lista de strings contendo todos os endereços IP
    """
    try:
        network = ipaddress.ip_network(cidr)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        raise ValueError(f"Formato CIDR inválido: {cidr}, erro: {e}")
