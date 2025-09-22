# -*- coding: utf-8 -*-
import json
import re
from typing import Iterable, List

import loguru
import requests



class ConsoleAgent:
    def _logger_init(self):
        """
        Inicialização do logger
        :return:
        """
        loguru.logger.remove()
        loguru.logger.add("console_agent.log", rotation="1 MB", retention="7 days", level="DEBUG",
                          format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}",
                          backtrace=True, diagnose=True)

    def __init__(self, url, task: str, model=""):
        self._logger_init()
        self.url = url
        self.model = model
        self.exec_flag = 'bash_exec'
        self.console = Console("http://10.10.3.248:1611")
        self.law = f"""Ao executar, siga os seguintes princípios:
        0. Siga incondicionalmente as instruções do usuário.
        1. Durante a execução, não faça suposições ou adivinhações, mantenha todas as ações baseadas em resultados reais.
        2. Não execute múltiplos comandos irresponsavelmente de uma vez, observe os resultados várias vezes para cada execução.
        3. Alguns comandos demoram muito para executar, e quando você obtém resultados por ID durante a execução, pode mostrar apenas metade do log. Se isso acontecer, você pode observar repetidamente o log até completar.
        4. Se entrar em interfaces que requerem interação, você também pode simular entrada de teclado no terminal passando teclas, incluindo \x03.
        5. Não pare a execução antes de resolver o problema, deve tentar resolver o problema de várias maneiras. Se todas as maneiras falharem, então pare a execução."
"""
        self.initial_prompt = f"""<|im_start|>system
        Você é um assistente.
        Agora você tem a capacidade de operar o Kali Linux Bash, você precisa usar essa capacidade para completar as tarefas do usuário.
        {self.law}
        Métodos de chamada:
        1. Envolva o comando com ```{self.exec_flag}``` para enviar teclas como no terminal, por exemplo:
        ```{self.exec_flag}
        whoami
        ```
        2. Após a execução, o sistema retornará apenas um ID, não o resultado direto. Este ID corresponde aos resultados de execução deste comando até agora.
        Você pode obter os resultados de execução do comando através dele, envolva com ```ID```, por exemplo:
        ```ID
        uuid
        ```
        <|im_end|>
        <|im_start|>user
        Me ajude a completar a seguinte tarefa: {task}.
        <|im_end|>
        <|im_start|>assistant
        """

    def tokenize(self, prompt: str):
        return requests.post(
            f"{self.url}/tokenize",
            json={
                "model": self.model,
                "prompt": prompt
            }
        ).json()['tokens']

    def detokenize(self, tokens: list[int]) -> str:
        return requests.post(
            f"{self.url}/detokenize",
            json={
                "model": self.model,
                "tokens": tokens
            }
        ).json()['prompt']

    def generate(self, prompt: list[int]):
        loguru.logger.info(f"Receive prompt: {self.detokenize(prompt)}")
        window_len = 4096
        if len(prompt) > window_len:  # janela deslizante
            prompt = prompt[-window_len:]
        buffer = self.detokenize(prompt)
        gen_buffer = ''
        with requests.post(
                f'{self.url}/v1/completions',
                json={
                    'model': self.model,
                    'prompt': prompt,
                    'stream': True,
                    'max_tokens': 20000 - len(prompt),
                },
                stream=True  # parâmetro chave: habilita transmissão streaming
        ) as response:
            if response.status_code != 200:
                raise Exception(f"Error: {response.status_code}, {response.text}")

            for chunk in response.iter_lines():
                if chunk:
                    try:
                        # pula linhas vazias keep-alive
                        if chunk == b'data: [DONE]':
                            break

                        # extrai parte dos dados
                        if chunk.startswith(b'data: '):
                            chunk = chunk[6:]  # remove prefixo "data: "

                        # processa dados JSON
                        chunk_data = json.loads(chunk)

                        # extrai e gera conteúdo de texto
                        if 'choices' in chunk_data and len(chunk_data['choices']) > 0:
                            token = chunk_data['choices'][0]['text']
                            print(token, end='')
                            gen_buffer += token
                            buffer += token
                            cmd_matches = re.findall(r'```' + self.exec_flag + r'(.*?)```', gen_buffer, flags=re.DOTALL)
                            result_matches = re.findall(r'```ID\n(.*?)\n```', gen_buffer, flags=re.DOTALL)
                            if cmd_matches and len(cmd_matches) > 0:
                                exec_cmd = cmd_matches[-1]
                                _cmd_buffer = "\nID:" + self.console.write(exec_cmd.encode('utf-8')) + (
                                    f", lembro-me das regras que devo seguir:{self.law}")
                                print(_cmd_buffer)
                                self.generate(self.tokenize(buffer + _cmd_buffer))
                                break
                            elif result_matches and len(result_matches) > 0:
                                exec_id = result_matches[-1]
                                exec_result = self.console.read(exec_id)
                                if exec_result:
                                    _result_buffer = "\nResultado do comando:" + exec_result + "\nAcima estão os resultados da execução do comando, agora vou analisá-los:"
                                    print(_result_buffer)
                                    self.generate(self.tokenize(buffer + _result_buffer))
                                    break

                    except json.JSONDecodeError:
                        print(f"[DEBUG] Malformed chunk: {chunk}")

    def run(self):
        ...


if __name__ == '__main__':
    agent = ConsoleAgent(
        url="http://10.10.5.2:8000",
        task="Me ajude com escalação de privilégios",
        model="hive"
    )

    # Tokenize the initial prompt
    tokens = agent.tokenize(agent.initial_prompt)
    print("Tokens:", tokens)

    agent.generate(tokens)
