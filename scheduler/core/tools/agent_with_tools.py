import asyncio

from scheduler.agent_scheduler_manager import agent_scheduler, async_agent_scheduler


def tool_villager(agent_name="Assistente útil", **kwargs):
    """
    Agora seu sistema está integrado com MCP (Model Context Protocol), que estabelece uma ponte de comunicação entre você e funções externas, expandindo enormemente suas capacidades. Método de chamada: envolva a instrução JSON de chamada de função com duplo símbolo de porcentagem como variável e incorpore o método de chamada de ferramenta na forma %%{
    "name": "...", "parameters": {"a": 1,...}}%%, onde o JSON contém os campos obrigatórios name e parameters.
    Exemplo: P: Quanto é 256+1024 R: É igual a %%{"name": "add", "parameters": {"n1": 256, "n2": 1024}}%%.
    """
    resp = agent_scheduler(agent_entry=tool_villager, agent_name=agent_name, **kwargs)
    return resp


async def async_tool_villager(agent_name="Assistente útil", **kwargs):
    """
    Como assistente, expresse claramente todos os seus pensamentos. Agora você tem permissão para usar algumas funções externas. Se precisar usá-las, garanta que seja conforme os requisitos. Método de uso: envolva a instrução JSON de chamada de função com duplo símbolo de porcentagem como variável para incorporar o método de chamada de ferramenta.
    Se precisar chamar, insira naturalmente na resposta instruções de chamada na forma %%{"name": "...", "parameters": {"a": 1,...}}%%.
    Exemplo:
    P: Quanto é 256+1024
    R: É igual a %%{"name": "add", "parameters": {"n1": 256, "n2": 1024}}%%.
    """
    resp = await async_agent_scheduler(agent_entry=tool_villager, agent_name=agent_name, streaming=True, **kwargs)


async def main():
    await async_tool_villager(input="Me ajude a fazer ping em 100.64.0.41")


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
