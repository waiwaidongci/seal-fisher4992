"""仅追加事件日志（JSONL）与崩溃恢复重放。

每条事件占一行，写入时 flush + fsync，保证中断后：
  * 完整行不会丢；
  * 最后一条不完整的部分行在重放时被安全截除；
  * 已公开回答与拒绝裁决都不遗漏（裁决本身也是事件）。
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .models import Answer, Batch, Decision, FrozenRelease


class EventStore:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # 新建文件时确保存在，便于 fsync
        self.path.touch(exist_ok=True)

    def append(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
        data = line.encode("utf-8")
        with self._lock:
            # 单次 write 尽量原子落盘；随后 fsync，崩溃只可能丢最后一行整体
            with self.path.open("ab") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())

    def replay(self) -> tuple[FrozenRelease | None, list[Decision], list[Answer]]:
        """重放全部事件，重建冻结集合、裁决流与公开回答历史。"""
        decisions: list[Decision] = []
        answers: list[Answer] = []
        release: FrozenRelease | None = None

        raw = self.path.read_bytes()
        lines = raw.split(b"\n")
        # 末尾 split 必产生一个空串元素；若最后一个非空元素不是完整 JSON 行，截除
        clean: list[bytes] = []
        for ln in lines:
            if not ln.strip():
                continue
            try:
                obj = json.loads(ln.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                # 崩溃造成的部分行：截除并停止（其后不可能有完整事件）
                break
            clean.append(ln)
            if obj["type"] == "frozen":
                release = FrozenRelease(
                    batches=[Batch(**b) for b in obj["batches"]],
                    order=[b["batch_id"] for b in obj["batches"]],
                )
            elif obj["type"] == "decision":
                d = Decision(
                    request_id=obj["request_id"],
                    subset=tuple(obj["subset"]),
                    status=obj["status"],
                    value=obj.get("value"),
                    reason=obj.get("reason"),
                    violating=tuple(obj.get("violating", ())),
                )
                decisions.append(d)
                if d.status == "approved":
                    assert d.value is not None
                    answers.append(Answer(d.request_id, d.subset, d.value))
            # 未知类型事件忽略前向兼容
        if len(clean) != sum(1 for ln in lines if ln.strip() and _is_json(ln)):
            # 存在被截除的部分行：重写干净日志，避免下次重复告警
            with self.path.open("wb") as f:
                f.write(b"\n".join(clean) + (b"\n" if clean else b""))
                f.flush()
                os.fsync(f.fileno())
        return release, decisions, answers


def _is_json(ln: bytes) -> bool:
    try:
        json.loads(ln.decode("utf-8"))
        return True
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
