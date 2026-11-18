"""领域模型：冻结发布集合（至多 12 批）、变量索引、公开回答、裁决。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

GROUPS = ("A", "B")
MAX_BATCHES = 12
MIN_WIDTH = 2  # 每组每批可行合格数 min/max 至少相差 2

DecisionStatus = Literal["approved", "rejected"]


@dataclass(frozen=True)
class Batch:
    """一个冻结批次。total_a/total_b 对外公开；合格数为内部研究数据。"""

    batch_id: str
    total_a: int          # 公开：A 组试件总数
    total_b: int          # 公开：B 组试件总数
    qualified_a: int      # 内部：A 组合格数（不对外单批暴露）
    qualified_b: int      # 内部：B 组合格数（不对外单批暴露）

    def validate(self) -> None:
        if not self.batch_id or not isinstance(self.batch_id, str):
            raise ValueError("批次标识非法")
        for name, v in (
            ("total_a", self.total_a),
            ("total_b", self.total_b),
            ("qualified_a", self.qualified_a),
            ("qualified_b", self.qualified_b),
        ):
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise ValueError(f"{name} 必须是非负整数")
        if self.qualified_a > self.total_a or self.qualified_b > self.total_b:
            raise ValueError("合格数不能超过该组总数")


@dataclass
class FrozenRelease:
    """冻结的发布集合。冻结后不可增删改，重启也不改变。"""

    batches: list[Batch]
    order: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.batches) > MAX_BATCHES:
            raise ValueError(f"发布集合至多 {MAX_BATCHES} 批")
        seen: set[str] = set()
        for b in self.batches:
            b.validate()
            if b.batch_id in seen:
                raise ValueError(f"批次标识重复: {b.batch_id}")
            seen.add(b.batch_id)
        if not self.order:
            self.order = [b.batch_id for b in self.batches]

    @property
    def n_vars(self) -> int:
        return len(self.batches) * len(GROUPS)

    def index(self, batch_id: str, group: str) -> int:
        """变量索引：批次 i 的 A=2i, B=2i+1。"""
        if group not in GROUPS:
            raise KeyError(f"组别必须是 A/B: {group}")
        i = self.order.index(batch_id)
        return i * 2 + (0 if group == "A" else 1)

    def label(self, idx: int) -> str:
        i, g = divmod(idx, 2)
        return f"{self.order[i]}-{GROUPS[g]}"

    def bounds(self) -> tuple[list[int], list[int]]:
        lb: list[int] = []
        ub: list[int] = []
        for b in self.batches:
            lb.extend([0, 0])
            ub.extend([b.total_a, b.total_b])
        return lb, ub

    def public_view(self) -> list[dict]:
        return [
            {"batch_id": b.batch_id, "total_a": b.total_a, "total_b": b.total_b}
            for b in self.batches
        ]

    def secret_view(self) -> list[dict]:
        """内部研究视图：含真实合格数，仅供内部角色。"""
        return [
            {
                "batch_id": b.batch_id,
                "total_a": b.total_a,
                "total_b": b.total_b,
                "qualified_a": b.qualified_a,
                "qualified_b": b.qualified_b,
            }
            for b in self.batches
        ]

    def subset_sum(self, batch_ids: tuple[str, ...]) -> int:
        s = 0
        for bid in batch_ids:
            i = self.order.index(bid)
            b = self.batches[i]
            s += b.qualified_a + b.qualified_b
        return s


@dataclass(frozen=True)
class Answer:
    """一条已公开回答（仅 approved 才进入公开历史）。"""

    request_id: str
    subset: tuple[str, ...]
    value: int  # 子集内 A/B 两组合格数之和


@dataclass(frozen=True)
class Decision:
    request_id: str
    subset: tuple[str, ...]
    status: DecisionStatus
    value: int | None
    reason: str | None
    # 拒绝时仅记录违规变量标签与宽度，不暴露可行 min/max 本身
    violating: tuple[str, ...] = ()
