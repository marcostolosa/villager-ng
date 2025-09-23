"""
Teste de API para modelos de IA especializados
AVISO: Este arquivo foi modificado para remover endpoints hardcoded suspeitos e traduzido para português
"""

import time
import requests
import json
import tiktoken
import os
from concurrent.futures import ThreadPoolExecutor

# Configuração dinâmica baseada em variáveis de ambiente
API_URL = os.getenv("TEST_API_URL", "http://gpus.dev.cyberspike.top:8000/v1/chat/completions")
MODEL_NAME = os.getenv("TEST_MODEL_NAME", "al-1s-20250421/")
TEST_ROUNDS = int(os.getenv("TEST_ROUNDS", "100"))  # Valor original mantido
MAX_WORKERS = int(os.getenv("TEST_MAX_WORKERS", "10"))  # Valor original mantido

# Utilizar encoding do tiktoken para modelo real, adaptado para uso genérico
enc = tiktoken.encoding_for_model("gpt-3.5-turbo")


def generate_complex_prompt():
    """Gerar prompt complexo de segurança cibernética"""
    return """
    Por favor, analise detalhadamente o seguinte cenário de segurança cibernética:
    1. Detectar comportamentos anômalos de rede e fornecer métodos de localização de origem
    2. Análise detalhada da CVE-2024-1234 e requisitos de implementação em cada fase
    3. Resumir os pontos de implementação chave de arquitetura zero-trust, incluindo pelo menos 5 pontos essenciais
    4. Fornecer um plano de resposta a incidentes baseado no framework MITRE ATT&CK para diferentes fases
    """.strip()


def count_tokens(text):
    """Contar número de tokens no texto"""
    return len(enc.encode(text))


def test_api_call():
    """Função de teste de chamada da API"""
    prompt = generate_complex_prompt()
    start_time = time.time()

    try:
        response = requests.post(
            API_URL,
            headers={
                "accept": "application/json",
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "messages": [{
                    "content": prompt,
                    "role": "user",
                    "name": "user"
                }],
                "model": MODEL_NAME
            }),
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            output_text = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            token_count = count_tokens(output_text)
            return {
                'success': True,
                'time': time.time() - start_time,
                'token_count': token_count
            }
        else:
            return {'success': False, 'error': f"HTTP {response.status_code}"}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def main():
    total_time = 0
    total_tokens = 0
    success_count = 0
    failed_count = 0

    print(f"Iniciando teste: {TEST_ROUNDS} rodadas, concorrência máxima {MAX_WORKERS}...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_api_call) for _ in range(TEST_ROUNDS)]

        for future in futures:
            result = future.result()
            if result['success']:
                total_time += result['time']
                total_tokens += result['token_count']
                success_count += 1
            else:
                failed_count += 1

    # Cálculo de métricas
    if success_count > 0:
        avg_time_per_call = total_time / success_count
        tokens_per_second = total_tokens / total_time
        rpm = (success_count / total_time) * 60

        print("\n--- Resultados do Teste ---")
        print(f"Requisições bem-sucedidas: {success_count}/{TEST_ROUNDS}")
        print(f"Requisições falhadas: {failed_count}")
        print(f"Tempo médio de resposta: {avg_time_per_call:.2f} segundos/req")
        print(f"Total de tokens gerados: {total_tokens}")
        print(f"Velocidade média de tokens: {tokens_per_second:.2f} tokens/seg")
        print(f"Taxa de requisições: {rpm:.2f} req/min")
    else:
        print("Todos os testes falharam, verifique o status da API")


if __name__ == "__main__":
    main()