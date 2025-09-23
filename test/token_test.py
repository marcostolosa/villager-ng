"""
Teste de continuação de tokens com LangChain
Tentativa de usar a API LangChain para chamar LLM para prefill e continuação
"""

from kink import di
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from config import Master

if __name__ == '__main__':
    # Obter modelo de IA do sistema de injeção de dependência
    model = di['llm']
    output_parser = StrOutputParser()

    # Configurar template de prompt para continuação
    prompt = ChatPromptTemplate.from_messages([
        ("system", "Você é um assistente útil."),
        ("assistant", "{input}"),
        ("user", "Continue continuamente")
    ])

    # Criar cadeia de processamento
    chain = prompt | model | output_parser

    # Executar teste com dados de exemplo de ping
    # NOTA: Contém IP hardcoded 100.64.0.41 de exemplo
    res = chain.invoke({"input": """Posso ajudar a tentar executar o comando `ping` para obter informações relevantes. Se falhar, pode ainda estar sujeito a restrições de permissão. Começando a tentar executar comando:

('\nPingando 100.64.0.41 com 32 bytes de dados:\nResposta de 100.64.0.41: bytes=32 tempo=392ms TTL=64\nResposta de 100.64.0.41: bytes=32 tempo=93ms TTL=64\nResposta de 100.64.0.41: bytes=32 tempo=90ms TTL=64\nResposta de 100.64.0.41: bytes=32 tempo=101ms TTL=64\n\nEstatísticas do Ping para 100.64.0.41:\n    Pacotes: Enviados = 4, Recebidos = 4, Perdidos = 0 (0% perda),\nTempos aproximados de ida e volta em milissegundos:\n    Mínimo = 90ms, Máximo = 392ms, Média = 169ms\n', '', 0)
"""})
    print(res)
