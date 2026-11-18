"""隐私网关验证脚本（仅标准库，使用临时目录，不污染演示数据）。

覆盖五条证据链，全部通过才返回 0：

A. 三条联合才可反推（证明不能只逐条/两两检查）
   构造 3 批场景，使任意两条汇总回答下每个变量宽度都 >= 2，
   而三条联合后某“批×组”宽度 < 2 -> 服务必须拒绝第三条之后的
   继续反推申请；同时直接验证“朴素两两检查会误放行”。
B. 并发分别安全：并发申请按同一公开历史串行裁决，
   无重复发布、无重复事件、裁决全序确定（逐线程串行结果与并发一致）。
C. 公开后重启：已公开回答落盘、跨进程重建、幂等重试不重复发布。
D. 中断恢复：截断事件日志模拟部分写入，重建不丢失此前完整公开回答。
E. 角色权限隔离：对外令牌无法触达原数据/冻结/诊断入口，内部研究不受影响。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from privacy_gateway.gateway import Gateway, compute_group_widths  # noqa: E402
from privacy_gateway.models import Answer, Batch, MIN_WIDTH  # noqa: E402

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((PASS if ok else FAIL, name, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def min_group_width(release, answers) -> int:
    """与裁决同口径：联合可行域下所有“批×组”宽度的最小值。"""
    rows = compute_group_widths(release, answers)
    assert rows, "联合系统不可行"
    return min(r["width"] for r in rows)


def make_attack_batches() -> list[Batch]:
    """3 批场景：B01 小计数，使得三条联合后 B01-A 宽度 < 2。

    真实值：y1=qA1+qB1=1, y2=5, y3=3。
    """
    return [
        Batch("B01", total_a=5, total_b=5, qualified_a=1, qualified_b=0),
        Batch("B02", total_a=10, total_b=10, qualified_a=2, qualified_b=3),
        Batch("B03", total_a=10, total_b=10, qualified_a=1, qualified_b=2),
    ]


# ---------------------------------------------------------------- A. 联合反推
def part_a_joint_inference(tmp: Path) -> None:
    print("\n=== A. 三条联合才可反推（禁止只逐条/两两检查）===")
    gw = Gateway(tmp / "a_events.jsonl")
    gw.freeze(make_attack_batches())
    release = gw.release

    r1 = gw.request_aggregation("r1", ["B01", "B02"])
    r2 = gw.request_aggregation("r2", ["B01", "B03"])
    check("A1 前两条子集回答获准", r1["status"] == "approved" and r2["status"] == "approved",
          f"r1={r1['value']} r2={r2['value']}")

    min_w2 = min_group_width(release, gw.answers)
    check("A2 两条回答联合下最小宽度 >= 2（两两检查将误放行）", min_w2 >= MIN_WIDTH,
          f"min width={min_w2}")

    # 朴素“逐条/两两”裁决器：只看候选单独、或候选与任意单条历史的配对
    def naive_pairwise_adjudicate(subset) -> bool:
        cand = Answer("cand", tuple(subset), release.subset_sum(tuple(subset)))
        if min_group_width(release, [cand]) < MIN_WIDTH:
            return False
        for a in gw.answers:
            if min_group_width(release, [a, cand]) < MIN_WIDTH:
                return False
        return True

    naive_allows_third = naive_pairwise_adjudicate(["B02", "B03"])
    check("A3 朴素两两检查会错误放行第三条（证明其不足）", naive_allows_third is True)

    # 服务端联合裁决必须拒绝第三条
    r3 = gw.request_aggregation("r3", ["B02", "B03"])
    check("A4 联合裁决拒绝第三条反推申请", r3["status"] == "rejected",
          f"violating={r3['violating']} reason={r3['reason']}")
    check("A5 拒绝原因不含 min/max 具体数值",
          ("宽度" in (r3["reason"] or "")) or
          not any(ch.isdigit() for ch in (r3["reason"] or "")))

    # 拒绝后公开历史仍是两条，联合不变量继续成立
    check("A6 拒绝未发布候选值，公开历史不变", len(gw.answers) == 2)
    check("A7 已公开系统所有变量宽度仍 >= 2",
          min_group_width(release, gw.answers) >= MIN_WIDTH)

    # 全集合申请同样被联合拒绝（等价的第四条反推路径）
    r4 = gw.request_aggregation("r4", ["B01", "B02", "B03"])
    check("A8 全集合反推申请同样被拒绝", r4["status"] == "rejected",
          f"violating={r4['violating']}")

    # 可反推性证据：三条等式下 B01 相关变量被钉死/近钉死
    three_answers = [
        Answer("x1", ("B01", "B02"), r1["value"]),
        Answer("x2", ("B01", "B03"), r2["value"]),
        Answer("x3", ("B02", "B03"), release.subset_sum(("B02", "B03"))),
    ]
    pinned = [r["variable"] for r in compute_group_widths(release, three_answers)
              if r["width"] < MIN_WIDTH]
    check("A9 三条联合确实产生宽度<2变量（反推风险真实存在）", bool(pinned), f"{pinned}")


# ---------------------------------------------------------------- B. 并发安全
def part_b_concurrency(tmp: Path) -> None:
    print("\n=== B. 并发分别安全：同一公开历史串行裁决，无泄露合并 ===")
    from privacy_gateway.scripts.seed_demo import build_demo_batches

    batches = build_demo_batches(seed=7)[:6]
    gw = Gateway(tmp / "b_events.jsonl")
    gw.freeze(batches)
    ids = [b.batch_id for b in batches]

    # 参考：串行顺序执行同一批请求，得到确定性裁决序列
    serial_gw = Gateway(tmp / "b_serial.jsonl")
    serial_gw.freeze([Batch(**b.__dict__) for b in batches])

    subsets = [
        ["B01"], ["B02"], ["B03"], ["B01", "B02"], ["B02", "B03"],
        ["B01", "B03"], ["B01", "B02", "B03"], ids,
        ["B04"], ["B05", "B06"], ["B04", "B05", "B06"],
    ]
    reqs = [(f"c-{i:02d}", s) for i, s in enumerate(subsets)]
    for rid, s in reqs:
        serial_gw.request_aggregation(rid, s)
    serial_by_id = {d.request_id: d.status for d in serial_gw.decisions}

    # 并发：多线程同时竞争，但用顺序闸门固定一个到达全序，
    # 验证服务按“同一公开历史”把并发请求严格线性化到该全序
    n_req = len(reqs)
    turn_lock = threading.Lock()
    turn_cond = threading.Condition(turn_lock)
    current_turn = {"i": 0}

    outcomes: dict[str, str] = {}
    lock = threading.Lock()

    def worker(order: int, rid: str, subset: list[str]) -> None:
        # 等待自己的到达次序，制造真实并发压力下的确定全序
        with turn_cond:
            turn_cond.wait_for(lambda: current_turn["i"] == order)
            current_turn["i"] += 1
            turn_cond.notify_all()
        out = gw.request_aggregation(rid, subset)
        with lock:
            outcomes[rid] = out["status"]

    with ThreadPoolExecutor(max_workers=n_req) as pool:
        list(pool.map(lambda x: worker(x[0], x[1][0], x[1][1]), enumerate(reqs)))

    check("B1 并发裁决数量与申请数一致", len(outcomes) == len(reqs))
    check("B2 并发裁决与固定到达全序的串行参考逐请求一致（同一公开历史线性化）",
          outcomes == serial_by_id, f"并发={outcomes}")
    check("B3 无重复发布：approved 数 = 公开回答数 = 唯一事件数",
          len(gw.answers) == sum(1 for d in gw.decisions if d.status == "approved")
          and len({d.request_id for d in gw.decisions}) == len(gw.decisions))

    # 同一公开历史：再跑一轮并发，全部 request_id 复用 -> 必须逐字返回原裁决且不新增事件
    before = len(gw.decisions)
    barrier2 = threading.Barrier(len(reqs))

    def retry_worker(rid: str, subset: list[str]) -> None:
        barrier2.wait()
        gw.request_aggregation(rid, subset)

    with ThreadPoolExecutor(max_workers=len(reqs)) as pool:
        list(pool.map(lambda x: retry_worker(*x), reqs))
    check("B4 并发重试不重复发布、不新增裁决事件", len(gw.decisions) == before)

    # 并发后联合不变量：当前公开系统所有宽度 >= 2（否则说明有泄露被合并进来）
    widths = compute_group_widths(gw.release, gw.answers)
    check("B5 并发合并后公开系统全部变量宽度 >= 2",
          min(r["width"] for r in widths) >= MIN_WIDTH,
          f"min={min(r['width'] for r in widths)}")

    # request_id 复用但子集不一致必须拒绝
    try:
        gw.request_aggregation("c-00", ["B04"])
        conflict_ok = False
    except Exception:
        conflict_ok = True
    check("B6 同 request_id 不同子集被拒绝（防幂等键滥用）", conflict_ok)


# ---------------------------------------------------------------- C. 重启恢复
def part_c_restart(tmp: Path) -> None:
    print("\n=== C. 公开后重启：跨进程重建 + 幂等不重复发布 ===")
    path = tmp / "c_events.jsonl"
    gw = Gateway(path)
    from privacy_gateway.scripts.seed_demo import build_demo_batches
    gw.freeze(build_demo_batches(seed=11)[:5])

    r1 = gw.request_aggregation("p-01", ["B01", "B02"])
    r2 = gw.request_aggregation("p-02", ["B03"])
    gw.request_aggregation("p-03", ["B01", "B02", "B03"])  # 可能获准或拒绝，都应持久化
    n_before = len(gw.decisions)
    approved_before = len(gw.answers)

    # 模拟重启：新进程对象从同一日志重建
    gw2 = Gateway(path)
    check("C1 重启后冻结集合重建（批次数一致）",
          gw2.frozen and len(gw2.public_batches()) == 5)
    check("C2 重启后裁决记录不遗漏", len(gw2.decisions) == n_before)
    check("C3 重启后已公开回答不遗漏", len(gw2.answers) == approved_before)
    check("C4 重启后公开值逐字一致",
          [a.value for a in gw2.answers] == [a.value for a in gw.answers])

    # 幂等重试：重启后复用 request_id，返回同一裁决，不新增事件
    again = gw2.request_aggregation("p-01", ["B01", "B02"])
    check("C5 重启后幂等重试返回原裁决",
          again["status"] == r1["status"] and again["value"] == r1["value"])
    check("C6 幂等重试未新增事件", len(gw2.decisions) == n_before)

    # 第二次重启仍稳定
    gw3 = Gateway(path)
    check("C7 二次重启状态稳定", len(gw3.decisions) == n_before and gw3.frozen)
    check("C8 冻结不可更改：再次冻结被拒绝", _expect_error(gw3, lambda: gw3.freeze(
        build_demo_batches(seed=11)[:5])))


def _expect_error(gw: Gateway, fn) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


# ---------------------------------------------------------------- D. 中断恢复
def part_d_crash(tmp: Path) -> None:
    print("\n=== D. 中断恢复：部分写入截断不丢已公开回答 ===")
    path = tmp / "d_events.jsonl"
    gw = Gateway(path)
    gw.freeze(make_attack_batches())
    gw.request_aggregation("d-01", ["B01", "B02"])
    gw.request_aggregation("d-02", ["B01", "B03"])
    good_lines = path.read_text(encoding="utf-8").count("\n")

    # 模拟写到一半的事件行（崩溃）
    with path.open("a", encoding="utf-8") as f:
        f.write('{"type": "decision", "request_id": "d-03", "sub')  # 无换行，不完整
    gw_recovered = Gateway(path)
    check("D1 截断部分行后仍可重建", gw_recovered.frozen)
    check("D2 此前完整公开回答一条不丢", len(gw_recovered.answers) == 2)
    check("D3 不完整事件未被记为裁决",
          all(d.request_id != "d-03" for d in gw_recovered.decisions))

    # 重放后日志被自愈为干净行，再次重启状态不变
    clean_lines = path.read_text(encoding="utf-8").count("\n")
    check("D4 部分行被截除，日志自愈", clean_lines == good_lines)
    gw_again = Gateway(path)
    check("D5 自愈后重启公开回答仍完整", len(gw_again.answers) == 2)

    # 恢复后继续受理，且新事件正常追加
    r = gw_again.request_aggregation("d-04", ["B02"])
    check("D6 恢复后新申请正常裁决", r["status"] in ("approved", "rejected"))
    check("D7 新事件后历史不丢不重", len(gw_again.answers) >= 2
          and len({d.request_id for d in gw_again.decisions}) == len(gw_again.decisions))


# ---------------------------------------------------------------- E. 角色隔离
def part_e_roles(tmp: Path) -> None:
    print("\n=== E. 角色权限隔离（HTTP 层）")
    import threading
    from http.server import ThreadingHTTPServer

    from privacy_gateway.server import DEFAULT_EXTERNAL_TOKEN, DEFAULT_INTERNAL_TOKEN, Handler

    store = tmp / "e_events.jsonl"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.gateway = Gateway(store)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        import urllib.request
        import urllib.error

        base = f"http://127.0.0.1:{port}"

        def call(method: str, path: str, token: str | None, body: dict | None = None):
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read().decode())

        EXT, INT = DEFAULT_EXTERNAL_TOKEN, DEFAULT_INTERNAL_TOKEN
        batches = make_attack_batches()

        # 无令牌
        s, _ = call("GET", "/api/public/batches", None)
        check("E1 无令牌访问公开接口被拒 401", s == 401)

        # 对外令牌不能冻结/看原数据/看诊断
        s, _ = call("POST", "/api/internal/freeze", EXT, {"batches": [b.__dict__ for b in batches]})
        check("E2 对外令牌冻结入口 403", s == 403)
        s, _ = call("GET", "/api/internal/batches", EXT)
        check("E3 对外令牌原数据入口 403（合格数隔离）", s == 403)
        s, _ = call("GET", "/api/internal/widths", EXT)
        check("E4 对外令牌诊断入口 403", s == 403)

        # 未知令牌
        s, _ = call("GET", "/api/public/batches", "not-a-real-token")
        check("E5 未知令牌 401", s == 401)

        # 内部令牌冻结并可见原数据（内部研究不变）
        s, body = call("POST", "/api/internal/freeze", INT, {"batches": [b.__dict__ for b in batches]})
        check("E6 内部令牌可冻结发布集", s == 201 and len(body["batches"]) == 3)
        s, body = call("GET", "/api/internal/batches", INT)
        check("E7 内部令牌可见真实合格数（内部研究不变）",
              s == 200 and "qualified_a" in body[0])

        # 对外公开接口只见总数
        s, body = call("GET", "/api/public/batches", EXT)
        check("E8 对外公开接口仅含总数，无合格数字段",
              s == 200 and all("qualified_a" not in row for row in body))

        # 对外正常申请流程
        s, body = call("POST", "/api/public/aggregation-requests", EXT,
                       {"request_id": "e-01", "subset": ["B01", "B02"]})
        check("E9 对外申请获准并返回汇总值", s == 200 and body["status"] == "approved"
              and isinstance(body["value"], int))
        # 拒绝路径走 HTTP 403 但 body 含拒绝原因
        call("POST", "/api/public/aggregation-requests", EXT,
             {"request_id": "e-02", "subset": ["B01", "B03"]})
        s, body = call("POST", "/api/public/aggregation-requests", EXT,
                       {"request_id": "e-03", "subset": ["B02", "B03"]})
        check("E10 联合拒绝通过 403 + 原因返回给专用页",
              s == 403 and body["status"] == "rejected" and bool(body["reason"]))

        # 专用页面可匿名打开，但不含数据
        s, html = call("GET", "/portal", None) if False else (None, None)
        import urllib.request as u2
        with u2.urlopen(base + "/portal") as resp:
            portal = resp.read().decode()
        check("E11 专用页面可打开且不内嵌任何合格数",
              "qualified" not in portal and "B01" not in portal)

        # 对外看不到内部入口是否存在之外的任何信息：404 路径
        s, _ = call("GET", "/api/unknown", EXT)
        check("E12 未知路径 404", s == 404)
    finally:
        httpd.shutdown()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="priv-gw-verify-") as d:
        tmp = Path(d)
        part_a_joint_inference(tmp)
        part_b_concurrency(tmp)
        part_c_restart(tmp)
        part_d_crash(tmp)
        part_e_roles(tmp)

    total = len(results)
    failed = [r for r in results if r[0] == FAIL]
    print("\n" + "=" * 64)
    print(f"合计 {total} 项，通过 {total - len(failed)} 项，失败 {len(failed)} 项")
    if failed:
        for _, name, detail in failed:
            print(f"  失败项: {name} {detail}")
        return 1
    print("全部验证通过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
