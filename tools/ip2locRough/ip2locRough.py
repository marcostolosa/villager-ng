import logging

import requests
from geopy.distance import geodesic


def get_geo_from_ip(ip):
    for i in range(5):
        try:
            url = f'http://ip-api.com/json/{ip}'
            response = requests.get(url,timeout=30)
            data = response.json()
            if response.status_code == 200 and data['status'] == 'success':
                return {'latitude': data['lat'], 'longitude': data['lon']}
            else:
                logging.error(f"Falha ao obter localização geográfica do endereço IP {ip}, informação de erro: {data}")
        except Exception as e:
            logging.error(f"Falha ao obter localização geográfica do endereço IP {ip}, informação de erro: {e}")
    return None


def judg_rough_ip2loc_dist(ip, latitude, longitude):
    # Obter localização geográfica a partir do IP
    ip_geo = get_geo_from_ip(ip)
    ip_latitude = ip_geo['latitude']
    ip_longitude = ip_geo['longitude']

    # Calcular distância
    user_loc = (latitude, longitude)
    ip_loc = (ip_latitude, ip_longitude)
    distance = geodesic(user_loc, ip_loc).kilometers
    return distance
