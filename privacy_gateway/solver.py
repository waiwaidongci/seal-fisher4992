"""有界整数线性约束的可行性与逐变量最小/最大值求解器。

背景：对外汇总系统的隐私裁决是一组整数变量（每批 A/B 合格数）上的
"子集求和"等式约束。仅依赖标准库，无需 SciPy/LP 求解器。

支持的约束形式::

    sum(c_i * x_i) == b        x_i 为整数, lb_i <= x_i <= ub_i

提供：
  * ``feasible``       —— 约束系统是否存在整数可行解；
  * ``variable_range`` —— 给定系统下某变量的整数最小值/最大值；
  * ``all_ranges``     —— 全部变量的 (min, max) 与宽度。

实现方式：区间界传播（含非负/非正系数行的裁剪）+ 分支定界。
变量规模至多 24（12 批 × A/B 两组），搜索深度浅、裁剪充分，
配合显式节点预算保守失败（不产生"无法证明安全却放行"的情况）。
"""

from __future__ import annotations

from dataclasses import dataclass, field


class SolverBudgetError(RuntimeError):
    """节点预算耗尽，无法在预算内完成证明。调用方必须保守拒绝。"""


@dataclass(frozen=True)
class Constraint:
    coeffs: tuple[tuple[int, float], ...]  # (变量索引, 系数)，系数非 0
    rhs: float

    @classmethod
    def subset_sum(cls, indices: tuple[int, ...], rhs: float) -> "Constraint":
        return cls(tuple((i, 1.0) for i in indices), float(rhs))


@dataclass
class Solver:
    n: int
    lb: list[int]
    ub: list[int]
    constraints: list[Constraint] = field(default_factory=list)
    node_budget: int = 200_000

    def _propagate(self, lb: list[int], ub: list[int]) -> bool:
        """界传播：利用每行系数和的最小/最大可能值收紧变量界。

        返回 False 表示已可判定不可行。原地修改 lb/ub。
        每轮按当前界重新计算行和；界一旦变化就标记并重扫，保证单调收敛。
        """
        changed = True
        while changed:
            changed = False
            for con in self.constraints:
                lo_sum = 0.0
                hi_sum = 0.0
                for idx, c in con.coeffs:
                    if c >= 0:
                        lo_sum += c * lb[idx]
                        hi_sum += c * ub[idx]
                    else:
                        lo_sum += c * ub[idx]
                        hi_sum += c * lb[idx]
                # 可行要求 lo_sum <= rhs <= hi_sum
                if lo_sum > con.rhs + 1e-9 or hi_sum < con.rhs - 1e-9:
                    return False
                # 逐变量收紧：把其余变量推向极值后，该变量必须承担的剩余量
                for idx, c in con.coeffs:
                    if c > 0:
                        others_lo = lo_sum - c * lb[idx]
                        others_hi = hi_sum - c * ub[idx]
                        # c*x >= rhs - others_hi ; c*x <= rhs - others_lo
                        new_lb = max(lb[idx], _ceil((con.rhs - others_hi) / c))
                        new_ub = min(ub[idx], _floor((con.rhs - others_lo) / c))
                    else:  # c < 0
                        others_lo = lo_sum - c * ub[idx]
                        others_hi = hi_sum - c * lb[idx]
                        # c 为负，不等式方向反转
                        new_lb = max(lb[idx], _ceil((con.rhs - others_lo) / c))
                        new_ub = min(ub[idx], _floor((con.rhs - others_hi) / c))
                    if new_lb > new_ub:
                        return False
                    if new_lb != lb[idx] or new_ub != ub[idx]:
                        lb[idx], ub[idx] = new_lb, new_ub
                        changed = True
        return True

    def feasible(self) -> bool:
        """完整系统是否存在整数可行解。预算耗尽按 SolverBudgetError 抛出。"""
        lb, ub = list(self.lb), list(self.ub)
        if not self._propagate(lb, ub):
            return False
        if all(lb[i] == ub[i] for i in range(self.n)):
            return self._check_full(lb)
        return self._search_feasible(lb, ub)

    def _check_full(self, vals: list[int]) -> bool:
        for con in self.constraints:
            s = sum(c * vals[i] for i, c in con.coeffs)
            if abs(s - con.rhs) > 1e-9:
                return False
        return True

    def _search_feasible(self, lb: list[int], ub: list[int]) -> bool:
        calls = 0

        def dfs(lb0: list[int], ub0: list[int]) -> bool:
            nonlocal calls
            calls += 1
            if calls > self.node_budget:
                raise SolverBudgetError("可行性搜索超过节点预算")
            lb, ub = list(lb0), list(ub0)
            if not self._propagate(lb, ub):
                return False
            if all(lb[i] == ub[i] for i in range(self.n)):
                return self._check_full(lb)
            # 选择域最宽的变量分支，尽快制造强传播
            j = max(
                (i for i in range(self.n) if ub[i] > lb[i]),
                key=lambda i: ub[i] - lb[i],
            )
            mid = (lb[j] + ub[j]) // 2
            for lo, hi in ((lb[j], mid), (mid + 1, ub[j])):
                nlb, nub = list(lb), list(ub)
                nlb[j], nub[j] = lo, hi
                if dfs(nlb, nub):
                    return True
            return False

        return dfs(lb, ub)

    def optimize(self, target: int, maximize: bool = False) -> int:
        """在可行系统下求 target 变量的最小（或最大）整数值。"""
        # 先确保整体可行，避免对不可行系统调用
        if not self.feasible():
            raise ValueError("约束系统不可行，无法优化")
        best: int | None = None
        calls = 0

        def dfs(lb0: list[int], ub0: list[int]) -> None:
            nonlocal best, calls
            calls += 1
            if calls > self.node_budget:
                raise SolverBudgetError("界值搜索超过节点预算")
            lb, ub = list(lb0), list(ub0)
            if not self._propagate(lb, ub):
                return
            # 定界剪枝
            if best is not None:
                if not maximize and lb[target] >= best:
                    return
                if maximize and ub[target] <= best:
                    return
            if all(lb[i] == ub[i] for i in range(self.n)):
                if self._check_full(lb):
                    v = lb[target]
                    best = v if best is None else (max(best, v) if maximize else min(best, v))
                return
            # 优先对目标变量分支，并先探索更可能取得更优值的一侧
            free = [i for i in range(self.n) if ub[i] > lb[i]]
            if target in free:
                j = target
            else:
                j = max(free, key=lambda i: ub[i] - lb[i])
            mid = (lb[j] + ub[j]) // 2
            sides = [(lb[j], mid), (mid + 1, ub[j])]
            if maximize:
                sides.reverse()
            for lo, hi in sides:
                nlb, nub = list(lb), list(ub)
                nlb[j], nub[j] = lo, hi
                dfs(nlb, nub)

        dfs(list(self.lb), list(self.ub))
        if best is None:
            raise SolverBudgetError("未取得界值（系统可能不可行）")
        return best

    def variable_range(self, target: int) -> tuple[int, int]:
        vmin = self.optimize(target, maximize=False)
        vmax = self.optimize(target, maximize=True)
        return vmin, vmax

    def all_ranges(self) -> list[tuple[int, int, int]]:
        """返回每个变量的 (min, max, 宽度=max-min)。"""
        out: list[tuple[int, int, int]] = []
        for i in range(self.n):
            vmin, vmax = self.variable_range(i)
            out.append((vmin, vmax, vmax - vmin))
        return out


def _floor(x: float) -> int:
    """对（接近整数的）浮点值做安全 floor。"""
    import math

    r = math.floor(x + 1e-9)
    # 修正浮点误差：若 x 实为整数略被表示成 k-1e-12
    if abs(x - (r + 1)) < 1e-7:
        return r + 1
    return r


def _ceil(x: float) -> int:
    import math

    return -_floor(-x)
