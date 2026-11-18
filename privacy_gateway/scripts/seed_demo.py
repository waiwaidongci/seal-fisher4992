"""生成 12 批冻结发布集的演示数据（固定 seed=42，可复现）。

用法::

    python -m privacy_gateway.scripts.seed_demo [事件日志路径]

若目标事件日志已存在事件则拒绝覆盖，保护已有公开历史。
真实合格数仅写入事件日志（内部研究数据），公开接口只暴露总数。
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

from ..gateway import Gateway
from ..models import MAX_BATCHES, Batch


def build_demo_batches(seed: int = 42, n: int = MAX_BATCHES) -> list[Batch]:
    rng = random.Random(seed)
    batches: list[Batch] = []
    for i in range(n):
        total_a = rng.randint(40, 90)
        total_b = rng.randint(40, 90)
        qa = rng.randint(0, total_a)
        qb = rng.randint(0, total_b)
        batches.append(
            Batch(
                batch_id=f"B{i + 1:02d}",
                total_a=total_a,
                total_b=total_b,
                qualified_a=qa,
                qualified_b=qb,
            )
        )
    return batches


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        store_path = Path(argv[1])
    else:
        from ..server import DEFAULT_STORE

        store_path = Path(DEFAULT_STORE)
    gw = Gateway(store_path)
    if gw.frozen:
        print(f"[拒绝] {store_path} 已存在冻结发布集，seed 不覆盖历史。")
        return 1
    batches = build_demo_batches()
    gw.freeze(batches)
    print(f"[完成] 已冻结 {len(batches)} 批 -> {store_path}")
    print("公开视图（仅总数）:")
    for row in gw.public_batches():
        print("  ", row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
