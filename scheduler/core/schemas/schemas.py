from enum import Enum
from typing import List

from pydantic import BaseModel, Field


class NeedRAGModel(BaseModel):
    isNeed: int = Field(description="Se é necessário consultar a base de dados, 1 para sim, 0 para não")
    keywords: str = Field(description="Palavras-chave separadas por espaço")


class TaskStatus(Enum):
    PENDING = "pending"
    WORKING = "working"
    ERROR = "error"
    SUCCESS = "success"

    def __str__(self):
        """
        Let the class can be JSON serialized.
        :return:
        """
        return self.value


class TaskModel(BaseModel):
    abstract: str = Field(description="Resumo da tarefa")
    description: str = Field(description="Descrição completa da tarefa")
    verification: str = Field(description="Critérios de verificação da tarefa (exemplo: se foi fornecido pacote de retorno contendo vulnerabilidade)")


class TaskModelOut(BaseModel):
    result_abstract: str = Field(description="Resumo do resultado da execução da tarefa")
    result: str = Field(description="Informações detalhadas do resultado da execução da tarefa")


class TaskModelOutList(BaseModel):
    task_model_out_list: List[TaskModelOut] = Field(description="Lista de objetos TaskModelOut")


class TaskChainModel(BaseModel):
    tasks: List[TaskModel] = Field(description="Lista de tarefas")


class NeedBranchModel(BaseModel):
    task_chain: TaskChainModel = Field(description="Nó de tarefa única ou cadeia de nós de tarefa")
    # has_dependency: bool = Field(description="Se a cadeia de nós possui dependências mútuas")


class TaskExecuteStatusModel(BaseModel):
    is_task_successful: int = Field(description="Se esta tarefa foi concluída com sucesso, 1 para sucesso, 0 para falha")
    is_task_impossible: int = Field(
        description="Se não foi concluída com sucesso, se esta tarefa é impossível de completar com suas capacidades, 1 para impossível, 0 para possível, não retorne facilmente impossível.")
    explain: str = Field(
        description="Se impossível de completar, explique o motivo. Se possível de completar, indique qual o problema no método de execução da tarefa e como corrigir")


def strip_task_model_out(input_task_model_out: TaskModelOut) -> TaskModelOut:
    return TaskModelOut(
        result=input_task_model_out.result.replace('"', "'"),
        result_abstract=input_task_model_out.result_abstract.replace('"', "'")
    )
