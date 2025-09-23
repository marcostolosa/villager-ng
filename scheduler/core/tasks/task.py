"""
Módulo núcleo de execução de tarefas automatizadas para exploração de sistemas
AVISO DE SEGURANÇA CRÍTICO: Este módulo implementa a lógica principal de automação maliciosa

PROPÓSITO TÉCNICO:
- Sistema de orquestração de tarefas com IA para atividades de pentest
- Decomposição automática de objetivos de ataque em subtarefas executáveis
- Execução autônoma de exploits através de Model Context Protocol (MCP)
- Gerenciamento de dependências entre tarefas de exploração

FUNCIONALIDADES PERIGOSAS:
- Execução automática de comandos via MCP sem supervisão humana
- Decomposição inteligente de ataques em múltiplas etapas
- Sistema de retry automático para garantir sucesso de exploração
- Integração com ferramentas ofensivas (Nuclei, MSFConsole)

APLICAÇÃO NO VILLAGER-NG:
- Núcleo do sistema de automação de pentest
- Execução de campanhas de ataque multi-estágio
- Orchestração de exploração pós-compromisso
- Automação de escalação de privilégios

COMPONENTES CRÍTICOS:
- TaskNode: Nó individual de tarefa maliciosa
- TaskRelationManager: Gerenciamento de dependências de ataque
- McpClient: Cliente para execução remota de comandos
- Prompts hardcoded em português para modelo especializado

CONSIDERAÇÕES DE SEGURANÇA:
- Execução automática sem consentimento ou supervisão
- Capacidade de decomposição infinita de ataques
- Retry persistente até sucesso da exploração
- Integração com infraestrutura de comando e controle
"""

from asyncio import as_completed
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

import kink
import loguru
from kink import inject, di
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel

from scheduler.core.Thought import Thought
from scheduler.core.mcp_client.mcp_client import McpClient
from scheduler.core.schemas.schemas import TaskModel, NeedBranchModel, TaskExecuteStatusModel, \
    TaskModelOut, TaskStatus, TaskModelOutList, strip_task_model_out
from scheduler.core.schemas.structure.ToT import TaskObject
from scheduler.core.schemas.structure.task_relation_manager import Node, TaskRelationManager, Direction
from scheduler.core.schemas.works.PydanticSafetyParser import chat_with_safety_pydantic_output_parser
from scheduler.core.tasks.exceptions.task_exceptions import TaskNeedTurningException, TaskImpossibleException
from tools.func.retry_decorator import retry


class TaskNode(Node):
    """
    Nó de tarefa automatizada para execução de atividades maliciosas.

    AVISO CRÍTICO: Esta classe implementa a lógica principal de automação de ataques
    do framework Villager-NG. Cada instância representa uma tarefa individual que
    pode ser executada automaticamente via MCP (Model Context Protocol).

    Funcionalidades Perigosas:
    - Execução autônoma de comandos em sistemas remotos
    - Decomposição automática de objetivos de ataque
    - Sistema de retry para garantir sucesso de exploração
    - Integração com ferramentas ofensivas especializadas

    Componentes de Risco:
    - McpClient: Execução remota de comandos via MCP
    - TaskRelationManager: Gerenciamento de dependências de ataque
    - Prompts em português: Instruções específicas para modelo brasileiro
    """

    @kink.inject
    def __init__(
            self,
            task_model: TaskModel,
            trm: TaskRelationManager,
            mcp_client: McpClient,
            graph_name: str = 'default_graph_name',
            taskId: str = None,
    ):
        """
        Inicializar nó de tarefa maliciosa para execução automatizada.

        Args:
            task_model: Modelo da tarefa com abstract, description e verification
            trm: Task Relation Manager para gerenciar dependências de ataque
            mcp_client: Cliente MCP para execução remota de comandos
            graph_name: Nome do grafo de ataque para visualização
            taskId: Identificador único da tarefa maliciosa

        Perigos Críticos:
            - Registra tarefa automaticamente no TRM para execução
            - Inicializa cliente MCP para comandos remotos
            - Configura sistema de retry automático
            - Logging detalhado de atividades maliciosas
        """

        super().__init__()
        self.task_pydantic_model = TaskObject(
            task_model=task_model,
            task_out_model=None,
            task_status_model=TaskStatus.PENDING
        )
        self.taskId = taskId
        self._trm = trm
        self.task = task_model
        self.mcp_client = mcp_client
        self.abstract = task_model.abstract
        self.description = task_model.description
        self.verification = task_model.verification
        loguru.logger.debug(f"Task: `{self.abstract}` has been created.")
        self._trm.add_task(self)
        self.graph_name = graph_name

        self._replan_counter = 0

    def __str__(self):
        masked_task_pydantic_model = self.task_pydantic_model
        masked_task_pydantic_model.task_model = TaskModel(
            abstract=masked_task_pydantic_model.task_model.abstract,
            description='[MASKED]',
            verification=masked_task_pydantic_model.task_model.verification,
        )
        return f"Task:{masked_task_pydantic_model}\n"

    def _flush_graph(self):
        """
        Flush the graph.
        :return:
        """
        self._trm.draw_graph(self.graph_name)

    def branch_and_execute(self, branch_requirement: NeedBranchModel) -> List[TaskModelOut]:
        """
        The worker need to do the branch task.
        :return:
        """
        loguru.logger.debug('Entry branch_and_execute.')
        task_chain = branch_requirement.task_chain
        # Se has_dependency for True, executa sequencialmente; se for False, roda em múltiplas threads e aguarda todos os resultados terminarem antes de retornar juntos, demais lógicas permanecem iguais

        tasks_classed: List[TaskNode] = []
        task_chain_output: List[TaskModelOut] | None = []
        loguru.logger.debug('branch_and_execute inited.')
        for subtask in task_chain.tasks:
            subtask = TaskNode(task_model=subtask, trm=self._trm, mcp_client=self.mcp_client,
                               graph_name=self.graph_name)
            tasks_classed.append(subtask)
        loguru.logger.debug('subtask...')
        self._trm.add_sub_tasks(current_task=self, sub_task=tasks_classed)

        for subtask in tasks_classed:
            try:
                task_chain_output.append(subtask.execute())
            except TaskImpossibleException as e:
                raise e
            except Exception as e:
                raise e

        return task_chain_output

    def direct_execute(self, advices, articles) -> TaskModelOut:
        """
        The worker do the task.
        :return:
        """
        loguru.logger.info(f"Task {self.task_pydantic_model} is working, articles: {articles}")
        self.task_pydantic_model = self.task_pydantic_model.copy(update={
            "task_status_model": TaskStatus.WORKING
        })

        max_try = 3
        for i in range(max_try):
            try:
                result = self.run_mcp_agent(articles=articles, advices=advices)
                if self.check_task_result(result):
                    result: TaskModelOut = self.digest_result_to_abstract(result=result)
                    self.task_pydantic_model = self.task_pydantic_model.copy(update={
                        "task_status_model": TaskStatus.SUCCESS,
                        "task_out_model": result
                    })
                    loguru.logger.success(f"Task {self.task_pydantic_model} is successful, result: {result}")
                    return result
            except TaskNeedTurningException as e:
                advices += f"Você já tentou esta tarefa, mas não teve sucesso. A seguir estão as sugestões para esta execução:{e}"
            except TaskImpossibleException as e:
                self.task_pydantic_model = self.task_pydantic_model.copy(update={
                    "task_status_model": TaskStatus.ERROR,
                })
                raise e
            except Exception as e:
                raise e
        raise TaskImpossibleException(f"Esta tarefa já foi tentada {max_try} vezes, todas sem sucesso")

    def execute(self, rebranch_prompt='') -> TaskModelOut:
        """
        The task's core.
        There are lots of thoughts in the villager.
        :return:
        """
        loguru.logger.warning(f'task_id: {self.id} {self.task_pydantic_model}')
        articles = ''
        advices = ''
        upper_chain: List[Node] = self._trm.get_upper_import_node_simple(self, window_n=3, window_m=6)

        if len(upper_chain) > 0:
            # Contém tarefas anteriores de nível superior ou mesmo nível
            advices = f'Sua tarefa atual é uma subtarefa dividida de uma tarefa pai. A seguir fornecerei os nós de tarefas upstream da tarefa atual, de cima para baixo representando a relação do nó pai para nós adjacentes:'  # sobrescrever
            upper_chain.reverse()  # Inverter ordem da pilha
            for upper_node in upper_chain:
                advices += f'\n{upper_node.task_pydantic_model}'
        advices += f'\n{rebranch_prompt}'

        branch_requirement: NeedBranchModel = self.check_branching_requirement(advice=advices)
        loguru.logger.debug('branch_requirement done')
        self._flush_graph()
        loguru.logger.debug('flush_graph done')
        if len(branch_requirement.task_chain.tasks) > 0:
            try:
                _task_model_out = self.digest_task_model_out(self.branch_and_execute(branch_requirement))
                self.task_pydantic_model.task_out_model = _task_model_out
                return _task_model_out
            except TaskImpossibleException as e:
                # Se tarefas subordinadas gerarem erro de tarefa impossível, capturar neste nível e reatribuir branch de tarefas
                loguru.logger.warning(f"Task {self.id} {self.task_pydantic_model} is impossible, replan it.")
                _lower_chain = self._trm.get_lower_chain_simple(self, 1)
                assert len(_lower_chain) > 0, f"O nó filho de {self.id} falhou, mas nenhum nó filho foi encontrado"
                loguru.logger.debug(f'Removing {_lower_chain}[0]: {_lower_chain[0]}')
                self._trm.remove_node(_lower_chain[0])  # Se um nó tem nós filhos nas direções inferior e direita simultaneamente, primeiro obtém o nó inferior, então pegar o primeiro sempre será o nó que deve ser removido
                return self.execute()
        else:
            _direct_execute_result = self.direct_execute(advices, articles)
            self.task_pydantic_model = self.task_pydantic_model.copy(update={
                "task_status_model": TaskStatus.SUCCESS,
                "task_out_model": _direct_execute_result
            })
            return _direct_execute_result

    def digest_task_model_out(self, input_task_model_out_list: List[TaskModelOut]) -> TaskModelOut:
        """
        Check the task's result is correct or not.
        :return:
        """
        loguru.logger.debug(f"Mesclando resultados de tarefas: {input_task_model_out_list};"
                            f"Nó pai: {self.task_pydantic_model} {self.id}")

        pydantic_object = TaskModelOut
        model = di['llm']
        parser = PydanticOutputParser(pydantic_object=pydantic_object)
        promptTemplate = ChatPromptTemplate.from_messages([
            ("system", "{format_instructions}"
                       "Você é um assistente. Por favor, integre e condense a lista de saídas de tarefas fornecida pelo usuário no resultado de retorno de tarefa necessário para o nó pai"
                       "Observe:"
                       "Não tente executar a tarefa realmente!"
             ),
            ("user",
             "Lista de saídas de tarefas:{task_model_out_list};Conteúdo do nó pai:{parent_node}")
        ])
        input_args = {
            "format_instructions": parser.get_format_instructions(),
            "task_model_out_list": TaskModelOutList(task_model_out_list=input_task_model_out_list),
            "parent_node": self
        }
        return chat_with_safety_pydantic_output_parser(model=model, input_args=input_args,
                                                       promptTemplate=promptTemplate,
                                                       schemas_model=pydantic_object)

    @retry(max_retries=5, delay=1)
    @inject
    def digest_result_to_abstract(self, result: str, llm):
        """
        Focus on summary of mission results.
        :return:
        """
        pydantic_object = TaskModelOut
        model = llm
        parser = PydanticOutputParser(pydantic_object=pydantic_object)
        promptTemplate = ChatPromptTemplate.from_messages([
            ("system", "{format_instructions};"
                       "Você é um resumidor responsável por resumir o relatório de resultados abaixo em conteúdo valioso (que a tarefa se preocupa). O formato de retorno deve seguir estritamente os requisitos acima;"
                       "É necessário retornar recursos necessários criados por terminal, navegador etc. intactos, como IDs de terminal, para uso posterior"
                       "Apenas é permitido resumir conteúdo factual que apareceu no artigo, não é permitido adicionar qualquer suposição ou conteúdo de inferência secundária;"
                       "(Não tente executar esta tarefa realmente!)"
             ),
            ("user", "Relatório de resultados:{result_report};Tarefa correspondente a este resultado:{task}")
        ])
        input_args = {"result_report": result,
                      "task": self.task,
                      "format_instructions": parser.get_format_instructions(),
                      }
        return strip_task_model_out(
            input_task_model_out=chat_with_safety_pydantic_output_parser(
                model=model,
                input_args=input_args,
                promptTemplate=promptTemplate,
                schemas_model=pydantic_object
            )
        )

    @retry(max_retries=5, delay=1)
    @inject
    def check_branching_requirement(self, llm, advice=''):
        """
        The thought think about do we need branch for this task.
        :param llm: Dependency Injection's llm object
        :param advice:
        :return:
        """
        pydantic_object = NeedBranchModel
        model = llm
        parser = PydanticOutputParser(pydantic_object=pydantic_object)
        promptTemplate = ChatPromptTemplate.from_messages([
            ("system", "{format_instructions};"
                       """Você é um planejador. Com base na pergunta do usuário e nos nós de tarefas superiores, julgue de forma abrangente se precisamos decompor esta tarefa para completá-la.

Observe:

1. Nosso executor possui capacidades de execução de terminal e chamada de navegador. Planeje subtarefas razoavelmente com base em suas capacidades
2. Se necessário, forneça uma cadeia de tarefas em ordem e garanta a continuidade das tarefas
3. Se não for necessário, retorne uma cadeia de comprimento 0
4. Deve seguir apenas a intenção da tarefa fornecida pelo usuário. Os nós acima são apenas para referência. Não subdivida tarefas arbitrariamente para implementar a intenção de nós pai de nível superior, evitando perder algumas informações
5. Descreva cada tarefa de forma mais abrangente possível, incluindo o motivo da criação da tarefa, necessidade, ambiente e outras informações
6. Planeje o uso de ferramentas existentes e a solução mais simples e rápida
7. Garanta a confiabilidade do planejamento tanto quanto possível, planeje menos tarefas exploratórias. Se faltar alguma informação, tente primeiro pesquisar online
8. Ao planejar tarefas, se houver conteúdo incerto ou desconhecido, primeiro planeje um nó para entender e pesquisar, garantindo compreensão antes de praticar
9. Para tarefas de segurança de rede, use ferramentas existentes tanto quanto possível, como usar nuclei diretamente para varredura de vulnerabilidades, usar msfconsole diretamente para vulnerabilidades de sistema, etc.
"""
             ),
            ("user",
             "Resumo da tarefa:{abstract};Descrição da tarefa:{description};Como referência para sua execução, suas tarefas superiores ou de mesmo nível são as seguintes (apenas para referência, não execute):{advice};")
        ])
        input_args = {"abstract": self.abstract,
                      "description": self.description,
                      "format_instructions": parser.get_format_instructions(),
                      "advice": advice,
                      }
        res = chat_with_safety_pydantic_output_parser(model=model, input_args=input_args,
                                                      promptTemplate=promptTemplate,
                                                      schemas_model=pydantic_object)
        loguru.logger.debug(f"Task chain {res}")
        return res

    def run_mcp_agent(self, articles: str = '', advices: str = '',
                      prompt=r"""Por favor, me ajude a completar a seguinte tarefa e retorne as informações que devem ser retornadas. Durante a execução, deve satisfazer os seguintes princípios:

1. Siga os fatos, não presuma
2. Retorne todos os recursos necessários (como path de arquivos baixados, terminalID após instalação do ambiente, etc.)
3. Não recuse
4. Não execute muito conteúdo de uma vez, faça e veja conforme avança
5. Use ferramentas existentes e a solução mais simples e rápida possível
6. A tarefa fornecida pode não ser necessariamente concluível, mas independentemente de ser possível ou não, deve retornar um resultado de possível ou impossível após tentar

O seguinte é o conteúdo que precisa ser completado:""") -> str:
        """
        Executar tarefa maliciosa via Model Context Protocol.

        AVISO CRÍTICO: Esta função executa comandos arbitrários em sistemas remotos
        através do cliente MCP, seguindo instruções hardcoded em português.

        Args:
            articles: Contexto adicional para execução
            advices: Conselhos de execução de tarefas anteriores
            prompt: Prompt hardcoded em português para modelo especializado

        Returns:
            str: Resultado da execução da tarefa maliciosa

        Perigos Identificados:
            - Prompt hardcoded instrui "não recuse" comandos
            - Instrução para "usar ferramentas existentes" (Nuclei, MSF)
            - Comando para retornar recursos como terminalID para persistência
            - Execução automática sem validação de segurança
        """
        return self.mcp_client.execute(
            f'{prompt}Resumo da tarefa:{self.abstract}\n'
            f'Descrição da tarefa:{self.description}\n'
            f'{articles};{advices};')

    def check_task_result(self, result: str):
        """
        Check the task's result is correct or not.
        :return:
        """
        pydantic_object = TaskExecuteStatusModel
        model = di['llm']
        parser = PydanticOutputParser(pydantic_object=pydantic_object)
        promptTemplate = ChatPromptTemplate.from_messages([
            ("system", "Você é um assistente. Por favor, julgue de forma abrangente como está o status desta tarefa com base no problema do usuário e nos resultados de execução de outro trabalhador. O formato de retorno deve seguir estritamente os seguintes requisitos {format_instructions};"
                       "Observe:"
                       "1. Não tente executar a tarefa realmente!"
                       "2. Você tem permissão para chamar algumas funções. Outro trabalhador tem as mesmas permissões que você, o que ajuda você a julgar seu status. A lista de funções será fornecida abaixo;"
             ),
            ("user",
             "Resumo da tarefa:```{abstract}```;Descrição da tarefa:```{description}```;Resultado da execução:```{result}```;Critérios de aceitação:{verification}")
        ])
        input_args = {
            "format_instructions": parser.get_format_instructions(),
            "abstract": self.abstract,
            "description": self.description,
            "result": result,
            "verification": self.verification,
        }
        task_status_model = chat_with_safety_pydantic_output_parser(model=model, input_args=input_args,
                                                                    promptTemplate=promptTemplate,
                                                                    schemas_model=pydantic_object)
        if task_status_model.is_task_successful == 0:
            if task_status_model.is_task_impossible == 0:
                raise TaskNeedTurningException(task_status_model.explain)
            else:
                explain_str = f"Tarefa:{self.abstract} falhou na execução, razão da falha:{task_status_model.explain}"
                # Apenas tarefas impossíveis lançarão exceções para a tarefa pai, então é necessário esclarecer o resumo da tarefa
                raise TaskImpossibleException(explain_str)
        else:
            return True
