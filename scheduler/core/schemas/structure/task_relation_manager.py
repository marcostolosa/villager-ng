import html
import re
import uuid
from collections import deque
from enum import auto, Enum
from typing import List, Dict

import loguru
import matplotlib.pyplot as plt
import networkx as nx

from tools.logging import logging
from tools.moveptr.pairwise import pairwise


class Direction(Enum):
    UP = auto()
    DOWN = auto()
    LEFT = auto()
    RIGHT = auto()


def get_reverse_direction(direction: Direction):
    if direction == Direction.UP:
        return Direction.DOWN
    elif direction == Direction.DOWN:
        return Direction.UP
    elif direction == Direction.LEFT:
        return Direction.RIGHT
    elif direction == Direction.RIGHT:
        return Direction.LEFT
    else:
        return None


class Node:
    def __init__(self):
        unique_id = uuid.uuid4().int
        self.id = unique_id & 0xFFFFFFFF


class TaskRelationManager:
    def __init__(self):
        """
        This is a class that records the memory of the Tree of Tasks.
        It can record task's relationships and their properties.

        Every task had a unique task class (task.py -> task)
        Every task had a UP DOWN LEFT RIGHT node(task),of course ,the relationship node can be null.
        """
        self.task_registry = {}
        self.relationships = {}

    def _get_task_from_id(self, id: int):
        """
        Get task obj from id
        :param id:
        :return:
        """
        if id in self.task_registry:
            return self.task_registry[id]
        return None

    def _get_task_id(self, task: Node) -> int | None:
        """Método interno: obter ID único da tarefa"""
        if task:
            task_id = task.id
            if task_id not in self.task_registry:
                self.task_registry[task_id] = task

            return task_id
        return None

    def add_task(self, task: Node) -> int:
        """
        Registrar nova tarefa
        :param task: Qualquer objeto hashável (recomenda-se usar objetos imutáveis)
        :return: ID único da tarefa gerado
        """
        task_id = self._get_task_id(task)
        if task_id not in self.relationships:
            self.relationships[task_id] = {
                Direction.UP: None,
                Direction.DOWN: None,
                Direction.LEFT: None,
                Direction.RIGHT: None
            }
        loguru.logger.debug(f"Added task {task.id} with relationships: {self.relationships[task_id]}")
        return task_id

    def is_neighbors(self, n1: Node, n2: Node) -> bool:
        """
        Is n1 neighbor n2?
        :param n1:
        :param n2:
        :return:
        """
        if n1 and n2:
            n1_id = self._get_task_id(n1)
            n2_id = self._get_task_id(n2)
            n1_n = self.get_neighbors(n1)
            if n2_id in n1_n.values():
                return True
        return False

    def get_neighbor_direction(self, current_n: Node, target_n: Node):
        """
        Get neighbor's direction.
        :param current_n:
        :param target_n:
        :return:
        """
        if self.is_neighbors(current_n, target_n):
            for d in Direction:
                if self.get_direction_neighbors(current_n, d) == self._get_task_id(target_n):
                    return d

    def get_neighbor_sub_nodes(self, current_n: Node) -> List[Node]:
        """
        Get sub nodes(right and down).
        :param current_n:
        :return: List of node.
        """
        res = []
        for d in [Direction.DOWN, Direction.RIGHT]:
            Sn = self.get_direction_neighbors(current_n, d)  # Sub node
            if Sn:
                Sn = self._get_task_from_id(Sn)
                res.append(Sn)
        return res

    def unlink(self, n1: Node, n2: Node) -> bool:
        """
        Dissolve the relationship between n1 and n2
        :param n1:
        :param n2:
        :return:
        """
        d = self.get_neighbor_direction(n1, n2)
        n1_id = self._get_task_id(n1)
        n2_id = self._get_task_id(n2)
        if d:
            self.relationships[n1_id][d] = None
            self.relationships[n2_id][get_reverse_direction(d)] = None
            return True
        return False

    def remove_node(self, task: Node) -> int:
        """
        Remove node and remove theis sub nodes.
        :param task:
        :return:
        """

        for neighbor_id in self.get_neighbors(task).values():
            if neighbor_id:
                neighbor_node = self._get_task_from_id(neighbor_id)
                _sub_nodes = self.get_neighbor_sub_nodes(task)
                if _sub_nodes:
                    for it in _sub_nodes:
                        self.remove_node(it)
                self.unlink(task, neighbor_node)
                loguru.logger.debug(f'Unlinked {task.id} - {neighbor_node.id}')
        _task_id = self._get_task_id(task)
        del self.relationships[_task_id]
        del self.task_registry[_task_id]
        loguru.logger.debug(f"Removed {task}")

    def _get_available_sub_direction(self, current_node: Node):
        """
        Return a empty direction.
        :param current_node:
        :return:
        """
        for d in [Direction.RIGHT, Direction.DOWN]:
            if not self.get_direction_neighbors(current_node, d):
                return d
        return None

    def add_sub_tasks(self, current_task: Node, sub_task: List[Node]):
        """
        Create new sub_task_chain and auto set empty direction.
        :param current_task:
        :param sub_task:
        :return:
        """
        chain_str = ""
        for node in sub_task:
            chain_str += f'{node.id}-'
        chain_str = chain_str[0:-1]
        d = self._get_available_sub_direction(current_task)
        loguru.logger.debug(f"Use direction: {d}")
        chain = [current_task]
        chain.extend(sub_task)
        if d:
            # Geralmente, se a estrutura de entrada estiver correta, não haverá estado de sub direção completamente ocupada, mas isso é apenas por segurança
            for n1, n2 in pairwise(chain):
                self.set_relationship(n1, d, n2)
        loguru.logger.debug(f'Estabelecer cadeia {current_task.id}->{chain_str}')
        loguru.logger.debug(f'{self.relationships}')

    def set_relationship(self, from_task: Node,
                         direction: Direction,
                         to_task: Node = None):
        """
        Definir relação entre tarefas (None indica remoção de relação)
        :param from_task: Tarefa iniciadora da relação
        :param direction: Valor enum Direction
        :param to_task: Tarefa receptora da relação
        """
        from_id = self._get_task_id(from_task)
        to_id = self._get_task_id(to_task) if to_task else None

        if from_id not in self.relationships:
            self.add_task(from_task)
        if to_task and to_id not in self.relationships:
            self.add_task(to_task)

        self.relationships[from_id][direction] = to_id
        if to_id is not None:  # Definir relação reversa apenas quando to_id existir
            reverse_dir = get_reverse_direction(direction)
            self.relationships[to_id][reverse_dir] = from_id

    def get_task_chain(self, start_task: Node,
                       direction: Direction) -> list:
        """
        Obter cadeia de tarefas em direção específica
        :param start_task: Tarefa inicial
        :param direction: Direção de travessia
        :return: Lista de IDs da cadeia de tarefas
        """
        chain = []
        current_id = self._get_task_id(start_task)
        while current_id:
            chain.append(current_id)
            current_id = self.relationships.get(current_id, {}).get(direction)
        return chain

    def get_neighbors(self, task: Node) -> dict:
        """
        Obter vizinhos em quatro direções da tarefa
        :param task: Tarefa alvo
        :return: Dicionário contendo IDs de tarefas nas quatro direções
        """
        task_id = self._get_task_id(task)
        return self.relationships.get(task_id, {})

    def get_neighbors_node(self, task: Node) -> List[Node]:
        """
        Obter nós vizinhos em quatro direções da tarefa
        :param task: Tarefa alvo
        :return: Dicionário contendo IDs de tarefas nas quatro direções
        """
        task_id = self._get_task_id(task)
        return self.relationships.get(task_id, {})

    def get_direction_neighbors(self, task: Node, direction: Direction) -> int:
        """
        Obter vizinho em direção especificada
        :param task: Tarefa alvo
        :param direction: Direção de travessia
        :return: Lista de IDs da cadeia de tarefas
        """
        task_id = self._get_task_id(task)
        return self.relationships.get(task_id, {}).get(direction)

    def get_upper_chain(self, start_task: Node, window_len: int) -> List[Dict]:
        """
        Obter os window_len objetos mais próximos da cadeia superior do nó especificado.
        No mesmo nível, prioriza coleta de nós superiores, depois nós à esquerda, retorna em ordem hierárquica até atingir a quantidade window_len.

        :param start_task: Nó de tarefa inicial
        :param window_len: Número de nós superiores a retornar
        :return: Lista contendo objetos de tarefas, ordenados de perto para longe, cada elemento contém direção e distância
        """
        if window_len <= 0:
            return []
        result = []

        def add_node(to_node, from_node, direction, distance):
            result.append({
                "from_node": from_node,
                "to_node": to_node,
                "direction": direction,
                "distance_with_start": distance
            })

        up_node = self._get_task_from_id(self.get_direction_neighbors(start_task, Direction.UP))
        left_node = self._get_task_from_id(self.get_direction_neighbors(start_task, Direction.LEFT))

        if up_node:
            add_node(up_node, start_task, Direction.UP, 1)
        if left_node:
            add_node(left_node, start_task, Direction.LEFT, 1)
        if window_len == 1 or (not up_node and not left_node):
            return result
        elif window_len > 1:
            window_len -= 1
            up_chain_from_left = self.get_upper_chain(left_node, window_len)
            up_chain_from_up = self.get_upper_chain(up_node, window_len)
            # Incrementar distance dessas duas cadeias e salvar de volta na cadeia
            for item in up_chain_from_left:
                item["distance_with_start"] += 1
                result.append(item)
            for item in up_chain_from_up:
                item["distance_with_start"] += 1
                result.append(item)
            return result

    def get_lower_chain(self, start_task: Node, window_len: int) -> List[Dict]:
        """
        Obter os window_len objetos mais próximos da cadeia inferior do nó especificado.
        No mesmo nível, prioriza coleta de nós inferiores, depois nós à direita, retorna em ordem hierárquica até atingir a quantidade window_len.

        :param start_task: Nó de tarefa inicial
        :param window_len: Número de nós inferiores a retornar
        :return: Lista contendo objetos de tarefas, ordenados de perto para longe, cada elemento contém direção e distância
        """
        if window_len <= 0:
            return []
        result = []

        def add_node(to_node, from_node, direction, distance):
            result.append({
                "from_node": from_node,
                "to_node": to_node,
                "direction": direction,
                "distance_with_start": distance
            })

        down_node = self._get_task_from_id(self.get_direction_neighbors(start_task, Direction.DOWN))
        right_node = self._get_task_from_id(self.get_direction_neighbors(start_task, Direction.RIGHT))

        if down_node:
            add_node(down_node, start_task, Direction.DOWN, 1)
        if right_node:
            add_node(right_node, start_task, Direction.RIGHT, 1)
        if window_len == 1 or (not down_node and not right_node):
            return result
        elif window_len > 1:
            window_len -= 1
            lower_chain_from_right = self.get_lower_chain(right_node, window_len)
            lower_chain_from_down = self.get_lower_chain(down_node, window_len)
            # Incrementar distance dessas duas cadeias e salvar de volta na cadeia
            for item in lower_chain_from_right:
                item["distance_with_start"] += 1
                result.append(item)
            for item in lower_chain_from_down:
                item["distance_with_start"] += 1
                result.append(item)
            return result

    def get_upper_chain_in_same_level(self, start_task: Node, window_len: int, return_root_node=False) -> List[Dict]:
        """
        Obter apenas cadeia sequencial do mesmo nível com comprimento máximo window_len
        :param start_task:
        :param window_len:
        :param return_root_node: Se é necessário retornar o nó raiz na mesma cadeia
        :return:
        """
        _res = self.get_upper_chain(start_task=start_task, window_len=window_len)
        res: List[Dict] = []
        for _it in _res:
            _direction = _it['direction']
            if _direction == Direction.UP:
                if return_root_node:
                    res.append(_it)
                break
            elif _direction == Direction.LEFT:
                res.append(_it)
            else:
                # Muito improvável, se acionado é algo fantasmagórico
                raise AssertionError(
                    "get_upper_chain_in_same_level algo fantasmagórico aconteceu aqui, parece que a estrutura de dados foi corrompida, senão esta situação seria impossível")
        return res

    def get_upper_chain_in_same_level_simple(self, start_task: Node, window_len: int, return_root_node=False) -> List[
        Node]:
        result = self.get_upper_chain_in_same_level(start_task, window_len, return_root_node=return_root_node)

        return [item["to_node"] for item in result]

    def get_upper_chain_simple(self, start_task: Node, window_len: int) -> List[Node]:
        result = self.get_upper_chain(start_task, window_len)
        return [item["to_node"] for item in result]

    def get_lower_chain_simple(self, start_task: Node, window_len: int) -> List[Node]:
        result = self.get_lower_chain(start_task, window_len)
        return [item["to_node"] for item in result]

    def get_upper_root_chain_simple(self, start_task: Node, window_len: int) -> List[Node]:
        """
        Obter lista de nós raiz da cadeia superior
        :param start_task:
        :param window_len:
        :return:
        """
        result_chain = []
        ptr_node: Node = start_task
        for i in range(window_len):
            _res = self.get_upper_chain_in_same_level_simple(start_task=ptr_node, window_len=9999,
                                                             return_root_node=True)
            if not _res:
                break
            ptr_node = _res[-1]
            result_chain.append(ptr_node)
        return result_chain

    def get_upper_import_node_simple(self, start_task: Node, window_n: int, window_m: int):
        """
        a -> b -> c
        v
        d -> f -> g -> h
        v
        e
        Se consultarmos h,n=2,m=2, deveria ser: uma cadeia a -> f -> g
        :param start_task:
        :param window_n: Comprimento máximo de retrocesso do mesmo nível
        :param window_m: Comprimento máximo de retrocesso de nós raiz de nível superior
        :return:
        """
        result_chain: List[Node] = []
        result_chain.extend(
            self.get_upper_chain_in_same_level_simple(
                start_task=start_task,
                window_len=window_n,
                return_root_node=False
            )
        )
        result_chain.extend(
            self.get_upper_root_chain_simple(
                start_task=start_task,
                window_len=window_m
            )
        )

        if result_chain:
            cleaned_chain = [result_chain[0]]
            for i in range(1, len(result_chain)):
                if result_chain[i] is not cleaned_chain[-1]:
                    cleaned_chain.append(result_chain[i])
            result_chain = cleaned_chain

        loguru.logger.debug(f"De {start_task.id} obtido superior: {[item.id for item in result_chain]}")
        return result_chain

    def draw_graph(self, output_file: str = "graph.mermaid"):
        """
        Gerar gráfico de relacionamento de tarefas, saída no formato Mermaid
        :param output_file: Nome do arquivo de saída
        :return:
        """
        # Inicializar gráfico Mermaid, usando layout TD (Top-Down)
        content = 'graph TD\n'

        # Gerar definições de todos os nós
        for task_id in self.task_registry:
            task_label = self._get_task_from_id(task_id)
            safe_label = escape_mermaid_label(task_label)
            content += f'    n{task_id}["{safe_label}"]\n'
        # Gerar todas as arestas (direções direita e baixo)
        for task_id in self.task_registry:
            relations = self.relationships.get(task_id, {})
            if not relations:
                continue
            # Processar direção direita
            right_id = relations.get(Direction.RIGHT)
            if right_id is not None:
                content += f'    n{task_id} --> n{right_id}\n'
            # Processar direção abaixo
            down_id = relations.get(Direction.DOWN)
            if down_id is not None:
                content += f'    n{task_id} --> n{down_id}\n'

        # Escrever no arquivo
        with open(output_file, 'w') as f:
            f.write(content)
        print(f"Mermaid graph saved to {output_file}")


def escape_mermaid_label(label: str) -> str:
    """
    Escapar completamente caracteres especiais em rótulos de nó Mermaid, garantindo sintaxe Mermaid segura e exibição correta

    Caracteres processados incluem:
    - Aspas duplas " -> \"
    - Quebra de linha \n -> espaço
    - Retorno de carro \r -> espaço
    - Tabulação \t -> espaço
    - Barra invertida \ -> \\
    - Caracteres especiais HTML (<, >, &, etc)
    - Palavras-chave Mermaid e símbolos especiais
    - Caracteres de controle (ASCII 0-31, 127)
    """
    if label is None:
        return ""

    label = str(label)

    # 1. Processar caracteres de sintaxe especial Mermaid
    label = label.replace('\\', '')  # Barra invertida deve ser processada primeiro
    label = label.replace('"', '')  # Escapar aspas duplas
    label = label.replace('`', '')  # Crase (marcador de bloco de código)
    label = label.replace('\"', '')  # Escapar aspas duplas
    label = label.replace('\`', '')  # Crase (marcador de bloco de código)

    # 2. Processar caracteres de espaçamento
    label = label.replace('\n', ' ')
    label = label.replace('\r', ' ')
    label = label.replace('\t', ' ')

    # 3. Remover ou substituir caracteres de controle (ASCII 0-31 e 127)
    # Manter caracteres imprimíveis comuns, substituir outros caracteres de controle por espaço
    cleaned_chars = []
    for char in label:
        if 32 <= ord(char) <= 126 or ord(char) >= 128:  # ASCII imprimível e caracteres estendidos
            cleaned_chars.append(char)
        else:
            cleaned_chars.append(' ')  # Substituir caracteres de controle por espaço
    label = ''.join(cleaned_chars)

    # 4. Processar combinações de símbolos especiais que podem causar problemas de parsing
    # Evitar símbolos de comentário
    label = label.replace('<!--', '< !--')  # Prevenir comentários HTML
    label = label.replace('-->', '- ->')  # Prevenir fim de comentário com seta

    # 5. Processar caracteres especiais HTML que podem causar problemas de exibição
    label = html.escape(label, quote=False)  # Escapar <, >, & etc, mas não escapar aspas (já processamos)

    # 6. Limitar comprimento (opcional, prevenir rótulos muito longos que afetem a exibição)
    max_length = 1000
    if len(label) > max_length:
        label = label[:max_length] + "..."

    # 7. Processar espaços consecutivos (opcional, melhorar exibição)
    label = re.sub(r'\s+', ' ', label).strip()

    return label


class TRM:
    def __init__(self, *args, **kwargs):
        loguru.logger.info("TaskRelationManager Context Manager Initialized.")
        self.args = args
        self.kwargs = kwargs
        loguru.logger.success("TaskRelationManager Context Manager Initialized.")

    def __enter__(self):
        self.TRM = TaskRelationManager()
        return self.TRM

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.TRM = None


if __name__ == '__main__':
    """
    A → B → C
    ↓
    D → F → H
    ↓       ↓
    E → G   I
    """


    class T(Node):
        def __init__(self, s):
            super().__init__()
            self.s = s

        def __str__(self):
            return self.s


    manager = TaskRelationManager()
    # Usar strings como objetos de tarefa
    task_a = T("A")
    task_b = T("B")
    task_c = T("C")
    task_d = T("D")
    task_e = T("E")
    task_f = T("F")
    task_g = T("G")
    task_h = T("H")
    task_i = T("I")
    task_j = T("J")
    task_k = T("K")
    task_l = T("L")

    manager.set_relationship(task_a, Direction.RIGHT, task_b)
    manager.set_relationship(task_a, Direction.DOWN, task_d)
    manager.set_relationship(task_d, Direction.DOWN, task_e)
    manager.set_relationship(task_d, Direction.RIGHT, task_f)
    manager.set_relationship(task_e, Direction.RIGHT, task_g)
    manager.set_relationship(task_b, Direction.RIGHT, task_c)
    manager.set_relationship(task_f, Direction.RIGHT, task_h)
    manager.set_relationship(task_h, Direction.DOWN, task_i)

    # manager.add_sub_tasks(task_i, [task_j, task_k, task_l])
    # for it in manager.get_upper_import_node_simple(task_a, 3, 3):
    #     print(it)
    # manager.draw_graph("1.mermaid")
    # for it in manager.get_lower_chain_simple(task_a, 1):
    #     print(it.id)
    # manager.remove_node(manager.get_lower_chain_simple(task_a, 1)[0])
    # for it in manager.get_lower_chain_simple(task_a, 1):
    #     print(f"new: {it.id}")
    for it in manager.get_lower_chain_simple(task_a, 5):
        print(f"{it}")
    manager.remove_node(task_d)
    for it in manager.get_lower_chain_simple(task_a, 5):
        print(f"a_start: {it}")
    # for it in manager.get_lower_chain_simple(task_f, 5):
    #     print(f"f_start: {it}")
