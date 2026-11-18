"""隐私网关核心服务。

职责
----
1. 持有一个**冻结**的至多 12 批发布集合（冻结后不可变更、重启不变）。
2. 对外只公开每批 A/B 总数；合格数属于内部研究数据。
3. 受理"任意批子集的两组合格数之和"申请；裁决依据是**全部已公开回答
   与本次候选回答构成的联合整数系统**，不是逐条或两两检查。
4. 联合求解每个变量（每批每组）的最小/最大可行整数，任一宽度 < 2 即拒绝。
5. 并发申请按同一公开历史串行裁决；request_id 幂等，重试不重复发布；
   裁决与回答均为仅追加事件，中断恢复不遗漏。
"""

from __future__ import annotations

import threading
from pathlib import Path

from .models import (
    MAX_BATCHES,
    MIN_WIDTH,
    Answer,
    Batch,
    Decision,
    FrozenRelease,
)
from .solver import Constraint, Solver, SolverBudgetError
from .store import EventStore


def compute_group_widths(release: FrozenRelease, answers: list[Answer]) -> list[dict]:
    """对给定公开历史，计算联合整数可行域下每个“批×组”的 min/max/宽度。

    与裁决同口径：批次级 z 变量降维 + 单调映射回 A/B。
    系统不可行时返回空列表。
    """
    n = len(release.batches)
    constraints = [
        Constraint.subset_sum(
            tuple(release.order.index(b) for b in a.subset), a.value
        )
        for a in answers
    ]
    solver = Solver(
        n=n,
        lb=[0] * n,
        ub=[b.total_a + b.total_b for b in release.batches],
        constraints=constraints,
    )
    if not solver.feasible():
        return []
    z_ranges = solver.all_ranges()
    out: list[dict] = []
    for i, b in enumerate(release.batches):
        z_min, z_max, _ = z_ranges[i]
        ta, tb = b.total_a, b.total_b
        a_min, a_max = max(0, z_min - tb), min(ta, z_max)
        b_min, b_max = max(0, z_min - ta), min(tb, z_max)
        out.append({"variable": f"{b.batch_id}-A", "min": a_min, "max": a_max,
                    "width": a_max - a_min})
        out.append({"variable": f"{b.batch_id}-B", "min": b_min, "max": b_max,
                    "width": b_max - b_min})
    return out


class GatewayError(ValueError):
    """请求层面的可预期错误（参数、状态机）。"""


class Gateway:
    def __init__(self, store_path: str | Path):
        self.store = EventStore(store_path)
        self._lock = threading.RLock()
        self.release: FrozenRelease | None = None
        self.decisions: list[Decision] = []
        self.answers: list[Answer] = []
        self._by_id: dict[str, Decision] = {}
        self._reload()

    # ------------------------------------------------------------------ 恢复
    def _reload(self) -> None:
        release, decisions, answers = self.store.replay()
        self.release = release
        self.decisions = decisions
        self.answers = answers
        self._by_id = {d.request_id: d for d in decisions}

    # ------------------------------------------------------------- 冻结发布集
    def freeze(self, batches: list[Batch]) -> FrozenRelease:
        with self._lock:
            if self.release is not None:
                raise GatewayError("发布集合已冻结，不可更改或重新冻结")
            if not batches:
                raise GatewayError("发布集合不能为空")
            if len(batches) > MAX_BATCHES:
                raise GatewayError(f"发布集合至多 {MAX_BATCHES} 批，收到 {len(batches)} 批")
            release = FrozenRelease(batches=list(batches))
            self.store.append(
                {"type": "frozen", "batches": [b.__dict__ for b in release.batches]}
            )
            self.release = release
            return release

    @property
    def frozen(self) -> bool:
        return self.release is not None

    # ------------------------------------------------------------- 公开视图
    def public_batches(self) -> list[dict]:
        """对外：仅各批 A/B 总数。"""
        with self._lock:
            if self.release is None:
                return []
            return self.release.public_view()

    def secret_batches(self) -> list[dict]:
        """内部研究视图：含真实合格数。路由层限制仅内部角色可访问。"""
        with self._lock:
            if self.release is None:
                return []
            return self.release.secret_view()

    def public_history(self) -> list[dict]:
        with self._lock:
            return [
                {"request_id": a.request_id, "subset": list(a.subset), "value": a.value}
                for a in self.answers
            ]

    def list_decisions(self) -> list[dict]:
        with self._lock:
            return [self._decision_dict(d) for d in self.decisions]

    # ------------------------------------------------------------- 申请裁决
    def request_aggregation(self, request_id: str, subset: list[str] | tuple[str, ...]) -> dict:
        if not isinstance(request_id, str) or not request_id.strip():
            raise GatewayError("request_id 不能为空")
        subset_tuple = tuple(subset)
        with self._lock:
            # 状态机：必须先冻结
            if self.release is None:
                raise GatewayError("发布集合尚未冻结，暂不受理汇总申请")
            release = self.release

            # 幂等：同一 request_id 永远返回同一裁决，重试不重复发布
            if request_id in self._by_id:
                prior = self._by_id[request_id]
                if tuple(prior.subset) != subset_tuple:
                    raise GatewayError(
                        "request_id 已存在但子集不一致，拒绝复用（请更换 request_id）"
                    )
                return self._decision_dict(prior)

            self._validate_subset(release, subset_tuple)

            candidate_value = release.subset_sum(subset_tuple)
            decision = self._adjudicate(release, request_id, subset_tuple, candidate_value)

            # 裁决（含拒绝）落事件日志；已公开回答天然包含在 approved 事件中
            self.store.append(
                {
                    "type": "decision",
                    "request_id": decision.request_id,
                    "subset": list(decision.subset),
                    "status": decision.status,
                    "value": decision.value,
                    "reason": decision.reason,
                    "violating": list(decision.violating),
                }
            )
            self.decisions.append(decision)
            self._by_id[decision.request_id] = decision
            if decision.status == "approved":
                self.answers.append(Answer(decision.request_id, decision.subset, decision.value))
            return self._decision_dict(decision)

    def _validate_subset(self, release: FrozenRelease, subset: tuple[str, ...]) -> None:
        if not subset:
            raise GatewayError("子集不能为空（不受理空集申请）")
        if len(set(subset)) != len(subset):
            raise GatewayError("子集内批次不能重复")
        unknown = [b for b in subset if b not in release.order]
        if unknown:
            raise GatewayError(f"子集包含未冻结批次: {unknown}")

    def _adjudicate(
        self,
        release: FrozenRelease,
        request_id: str,
        subset: tuple[str, ...],
        candidate_value: int,
    ) -> Decision:
        """基于**联合公开历史 + 候选回答**的整数可行域做隐私裁决。

        结构降维（对本系统精确成立）：每条公开回答都是整批两组合计，
        即只约束批次级变量 ``z_i = a_i + b_i``（``0 <= z_i <= total_a+total_b``）。
        先在至多 12 个 z 变量上联合求解每批 z 的整数最小/最大值，
        再由 z 极值单调推出该批 A、B 各自的最小/最大可行合格数：

            a ∈ [max(0, z-tb), min(ta, z)]，L/U 关于 z 单调，
            故 a_min=L(z_min), a_max=U(z_max)；B 组对称。
        """
        n = len(release.batches)
        z_lb = [0] * n
        z_ub = [b.total_a + b.total_b for b in release.batches]
        constraints: list[Constraint] = []

        # 全部已公开回答（不是只取与本次相关的几条，也不是两两配对）
        for ans in self.answers:
            idxs = tuple(release.order.index(b) for b in ans.subset)
            constraints.append(Constraint.subset_sum(idxs, ans.value))

        # 本次候选若发布将增加的等式
        cand_idxs = tuple(release.order.index(b) for b in subset)
        constraints.append(Constraint.subset_sum(cand_idxs, candidate_value))

        solver = Solver(n=n, lb=z_lb, ub=z_ub, constraints=constraints)
        try:
            if not solver.feasible():
                return Decision(
                    request_id, subset, "rejected", None,
                    "联合系统无整数可行解，保守拒绝", (),
                )
            z_ranges = solver.all_ranges()  # 每批 (z_min, z_max, width)
        except SolverBudgetError as exc:
            # 无法在预算内证明安全 -> 绝不放行
            return Decision(
                request_id, subset, "rejected", None,
                f"联合可行性裁决计算预算耗尽，保守拒绝（{exc}）", (),
            )

        violating: list[str] = []
        for i, b in enumerate(release.batches):
            z_min, z_max, _ = z_ranges[i]
            ta, tb = b.total_a, b.total_b
            a_min = max(0, z_min - tb)
            a_max = min(ta, z_max)
            b_min = max(0, z_min - ta)
            b_max = min(tb, z_max)
            if a_max - a_min < MIN_WIDTH:
                violating.append(f"{b.batch_id}-A")
            if b_max - b_min < MIN_WIDTH:
                violating.append(f"{b.batch_id}-B")

        if violating:
            return Decision(
                request_id, subset, "rejected", None,
                f"联合公开后存在可行合格数宽度小于 {MIN_WIDTH} 的批×组，拒绝发布",
                tuple(violating),
            )

        return Decision(request_id, subset, "approved", candidate_value, None, ())

    def _decision_dict(self, d: Decision) -> dict:
        return {
            "request_id": d.request_id,
            "subset": list(d.subset),
            "status": d.status,
            "value": d.value,
            "reason": d.reason,
            "violating": list(d.violating),
        }

    # ------------------------------------------------------------- 诊断/测试
    def joint_widths(self) -> list[dict]:
        """诊断接口：仅基于当前已公开回答的联合可行域宽度（路由层内部可见）。"""
        with self._lock:
            if self.release is None:
                return []
            return compute_group_widths(self.release, self.answers)
