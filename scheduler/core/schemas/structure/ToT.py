import json
import re
import uuid
from enum import Enum
from typing import Optional, Any

import yaml
from pydantic import BaseModel, Field

from scheduler.core.schemas.schemas import TaskModel, TaskModelOut, TaskStatus


class TaskObject(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_model: TaskModel
    task_out_model: Optional[TaskModelOut]
    task_status_model: TaskStatus

    class Config:
        use_enum_values = True  # Habilitar conversão automática de valores de enumeração

    def __str__(self, indent: int = 2) -> str:
        """Formatar modelo recursivamente para string em formato YAML"""

        def convert_value(value: Any) -> Any:
            """Converter recursivamente valores de campo para tipos compatíveis com YAML"""
            if isinstance(value, BaseModel):
                return value.dict()  # Converter modelo Pydantic para dicionário
            elif isinstance(value, Enum):
                return value.value  # Obter valor da enumeração
            elif isinstance(value, dict):
                return {k: convert_value(v) for k, v in value.items()}  # Processar dicionário recursivamente
            elif isinstance(value, list):
                return [convert_value(v) for v in value]  # Processar lista recursivamente
            return value

        # Converter dados do modelo completo
        data = {k: convert_value(v) for k, v in self.__dict__.items()}

        # Gerar string YAML, usando safe_dump para evitar riscos de segurança potenciais
        return yaml.safe_dump(
            data,
            indent=indent,
            allow_unicode=True,  # Suporte para caracteres Unicode
            default_flow_style=False  # Desabilitar formato compacto
        )
