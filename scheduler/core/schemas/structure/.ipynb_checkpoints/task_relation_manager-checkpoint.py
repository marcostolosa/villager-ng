import uuid
from collections import deque
from enum import auto, Enum
from typing import List, Dict

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


class node:
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

    def _get_task_id(self, task: node) -> int:
        """内部方法：获取任务的唯一ID"""
        if task:
            task_id = task.id
            if task_id not in self.task_registry:
                self.task_registry[task_id] = task

            return task_id

    def add_task(self, task: node) -> int:
        """
        注册新任务
        :param task: 任何可哈希的对象（建议使用不可变对象）
        :return: 生成的唯一任务ID
        """
        task_id = self._get_task_id(task)
        if task_id not in self.relationships:
            self.relationships[task_id] = {
                Direction.UP: None,
                Direction.DOWN: None,
                Direction.LEFT: None,
                Direction.RIGHT: None
            }
        return task_id

    def is_neighbors(self, n1: node, n2: node) -> bool:
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

    def get_neighbor_direction(self, current_n: node, target_n: node):
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

    def get_neighbor_sub_nodes(self, current_n: node) -> List[node]:
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

    def unlink(self, n1: node, n2: node) -> bool:
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

    def remove_node(self, task: node) -> int:
        """
        Remove node and remove theis sub nodes.
        :param task:
        :return:
        """

        for Sn in self.get_neighbor_sub_nodes(task):
            if self.get_neighbor_sub_nodes(Sn):
                self.remove_node(Sn)
            self.unlink(task, Sn)

    def _get_available_sub_direction(self, current_node: node):
        """
        Return a empty direction.
        :param current_node:
        :return:
        """
        for d in [Direction.RIGHT, Direction.DOWN]:
            if not self.get_direction_neighbors(current_node, d):
                return d

    def add_sub_tasks(self, current_task: node, sub_task: List[node]):
        """
        Create new sub_task_chain and auto set empty direction.
        :param current_task:
        :param sub_task:
        :return:
        """
        d = self._get_available_sub_direction(current_task)
        chain = [current_task]
        chain.extend(sub_task)
        if d:
            # 一般来说输入的结构正确不会有sub direction完全占满的状态，但这个仅为了保险
            for n1, n2 in pairwise(chain):
                self.set_relationship(n1, d, n2)

    def set_relationship(self, from_task: node,
                         direction: Direction,
                         to_task: node = None):
        """
        设置任务间关系（None表示解除关系）
        :param from_task: 关系发起方任务
        :param direction: Direction枚举值
        :param to_task: 关系接收方任务
        """
        from_id = self._get_task_id(from_task)
        to_id = self._get_task_id(to_task) if to_task else None

        if from_id not in self.relationships:
            self.add_task(from_task)
        if to_task and to_id not in self.relationships:
            self.add_task(to_task)

        self.relationships[from_id][direction] = to_id
        self.relationships[to_id][get_reverse_direction(direction)] = from_id

    def get_task_chain(self, start_task: node,
                       direction: Direction) -> list:
        """
        获取特定方向的任务链
        :param start_task: 起始任务
        :param direction: 遍历方向
        :return: 任务ID链表
        """
        chain = []
        current_id = self._get_task_id(start_task)
        while current_id:
            chain.append(current_id)
            current_id = self.relationships.get(current_id, {}).get(direction)
        return chain

    def get_neighbors(self, task: node) -> dict:
        """
        获取任务的四向邻居
        :param task: 目标任务
        :return: 包含四个方向任务ID的字典
        """
        task_id = self._get_task_id(task)
        return self.relationships.get(task_id, {})

    def get_direction_neighbors(self, task: node, direction: Direction) -> int:
        """
        获取指定方向的邻居
        :param task: 目标任务
        :param direction: 遍历方向
        :return: 任务ID链表
        """
        task_id = self._get_task_id(task)
        return self.relationships.get(task_id, {}).get(direction)

    def get_upper_chain(self, start_task: node, window_len: int) -> List[Dict]:
        """
        获取指定节点的上级链路的最近window_len个对象。
        同一层级优先收集上级节点，其次左节点，按层级顺序返回，直到达到window_len的数量。

        :param start_task: 起始任务节点
        :param window_len: 需要返回的上级节点数量
        :return: 包含任务对象的列表，按从近到远顺序排列，每个元素包含方向和距离
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
        if window_len == 1:
            return result
        elif window_len > 1:
            window_len -= 1
            up_chain_from_left = self.get_upper_chain(left_node, window_len)
            up_chain_from_up = self.get_upper_chain(up_node, window_len)
            # 把这两个链里面的distance ++并保存回链
            for item in up_chain_from_left:
                item["distance_with_start"] += 1
                result.append(item)
            for item in up_chain_from_up:
                item["distance_with_start"] += 1
                result.append(item)
            return result

