"""
Teste de resposta streaming do LangChain
Este arquivo testa a funcionalidade de streaming de resposta do modelo de IA
"""

import asyncio
from datetime import datetime

from kink import inject
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from scheduler.core.init import global_llm


@inject
async def wrapped_main(task_id, llm):
    """
    Testar a resposta streaming do langchain

    Args:
        task_id: ID da tarefa de teste
        llm: Modelo de linguagem para teste

    Returns:
        None
    """
    result = ""
    prompt = ChatPromptTemplate.from_template("{input}")
    parser = StrOutputParser()
    chain = prompt | llm | parser

    counter = 0
    last_time = datetime.now().timestamp()

    async for event in chain.astream(
            {
                "input": """
                Por favor, complete o código
                """
            }

    ):
        content = str(event)
        print(str(event), end='')
        result += content
        token_count = len(content)
        counter += token_count

        if counter >= 100:
            current_time = datetime.now().timestamp()
            elapsed_time = current_time - last_time
            if elapsed_time == 0:
                elapsed_time = 1e-9
            speed = 100 / elapsed_time
            # print(f"Tarefa {task_id}: Velocidade atual é {speed:.2f} tokens/s", flush=True)

            counter -= 100
            last_time = current_time
    # print(result)


async def main():
    tasks = [wrapped_main(i) for i in range(1)]
    await asyncio.gather(*tasks)


if __name__ == '__main__':
    with global_llm():
        asyncio.run(main())
