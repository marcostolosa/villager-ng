# -----------------------------------------------------
# Este arquivo define uma classe ConsoleAgent que pode interagir diretamente e continuamente no console
# -----------------------------------------------------
from kink import inject
from langchain.chains.conversation.base import ConversationChain
from langchain.memory import ConversationBufferMemory

from scheduler.core.schemas.schemas import TaskModel


class ConsoleAgent:
    @inject
    def __init__(self, llm, task: TaskModel):
        self.conversation = ConversationChain(
            llm=llm, verbose=True, memory=ConversationBufferMemory()
        )

    def invoke(self):
        """
        Execução interativa da tarefa, não requer validação
        :return:
        """
        ...
