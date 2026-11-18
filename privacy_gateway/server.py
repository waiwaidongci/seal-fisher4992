"""隐私网关 HTTP 服务（仅标准库）。

角色权限隔离
------------
* ``EXTERNAL_TOKEN``（对外角色）：只能访问公开信息与汇总申请，
  以及专用页面 /portal；任何内部/原数据入口一律 403/404。
* ``INTERNAL_TOKEN``（内部研究角色）：可访问内部冻结、原数据（真实合格数）、
  联合宽度诊断；内部研究流程不受影响。

并发：ThreadingHTTPServer + 串行裁决锁（Gateway 内部 RLock），
保证并发申请按同一公开历史逐条裁决，裁决结果全序确定。
"""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .gateway import Gateway, GatewayError
from .models import Batch

DEFAULT_STORE = str(Path(__file__).resolve().parent.parent / "gateway_data" / "events.jsonl")
DEFAULT_EXTERNAL_TOKEN = "external-demo-token"
DEFAULT_INTERNAL_TOKEN = "internal-demo-token"
PORTAL_HTML = Path(__file__).resolve().parent / "pages" / "portal.html"


def build_gateway() -> Gateway:
    store_path = os.environ.get("GATEWAY_STORE", DEFAULT_STORE)
    return Gateway(store_path)


class Handler(BaseHTTPRequestHandler):
    server_version = "PrivacyGateway/1.0"

    # ------------------------------------------------------------ 基础工具
    def _send_json(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, status: int, content: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            raise GatewayError("请求体不能为空")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayError(f"JSON 解析失败: {exc}") from exc
        if not isinstance(data, dict):
            raise GatewayError("请求体必须是 JSON 对象")
        return data

    def _role(self) -> str | None:
        """从 Bearer 令牌解析角色；无令牌/未知令牌返回 None。"""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[len("Bearer ") :].strip()
        ext = os.environ.get("EXTERNAL_TOKEN", DEFAULT_EXTERNAL_TOKEN)
        internal = os.environ.get("INTERNAL_TOKEN", DEFAULT_INTERNAL_TOKEN)
        if token == internal:
            return "internal"
        if token == ext:
            return "external"
        return None

    def log_message(self, fmt: str, *args) -> None:  # 安静日志
        return

    # ------------------------------------------------------------ 路由
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        gw: Gateway = self.server.gateway  # type: ignore[attr-defined]
        try:
            if path == "/health":
                self._send_json(HTTPStatus.OK, {"status": "ok", "frozen": gw.frozen})
                return
            if path == "/portal":
                # 专用页面本身不含任何数据；数据仍按令牌接口拉取
                self._send_file(
                    HTTPStatus.OK, PORTAL_HTML.read_bytes(), "text/html; charset=utf-8"
                )
                return
            if path == "/api/public/batches":
                if self._role() not in ("external", "internal"):
                    self._deny()
                    return
                self._send_json(HTTPStatus.OK, gw.public_batches())
                return
            if path == "/api/public/history":
                if self._role() not in ("external", "internal"):
                    self._deny()
                    return
                self._send_json(HTTPStatus.OK, gw.public_history())
                return
            if path == "/api/public/decisions":
                if self._role() not in ("external", "internal"):
                    self._deny()
                    return
                self._send_json(HTTPStatus.OK, gw.list_decisions())
                return
            if path == "/api/internal/batches":
                if self._role() != "internal":
                    self._deny()
                    return
                self._send_json(HTTPStatus.OK, gw.secret_batches())
                return
            if path == "/api/internal/widths":
                if self._role() != "internal":
                    self._deny()
                    return
                self._send_json(HTTPStatus.OK, gw.joint_widths())
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found", "path": path})
        except Exception as exc:  # pragma: no cover - 兜底
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal", "detail": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        gw: Gateway = self.server.gateway  # type: ignore[attr-defined]
        try:
            if path == "/api/public/aggregation-requests":
                role = self._role()
                if role not in ("external", "internal"):
                    self._deny()
                    return
                data = self._read_json()
                request_id = data.get("request_id")
                subset = data.get("subset")
                if not isinstance(subset, list) or not all(isinstance(x, str) for x in subset):
                    raise GatewayError("subset 必须是字符串数组（批次标识列表）")
                result = gw.request_aggregation(str(request_id), subset)
                status = HTTPStatus.OK if result["status"] == "approved" else HTTPStatus.FORBIDDEN
                self._send_json(status, result)
                return
            if path == "/api/internal/freeze":
                if self._role() != "internal":
                    self._deny()
                    return
                data = self._read_json()
                raw_batches = data.get("batches")
                if not isinstance(raw_batches, list) or not raw_batches:
                    raise GatewayError("batches 必须是非空数组")
                batches = [Batch(**b) for b in raw_batches]
                gw.freeze(batches)
                self._send_json(HTTPStatus.CREATED, {"frozen": True, "batches": gw.public_batches()})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found", "path": path})
        except GatewayError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bad_request", "detail": str(exc)})
        except TypeError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bad_request", "detail": f"字段非法: {exc}"})
        except Exception as exc:  # pragma: no cover - 兜底
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal", "detail": str(exc)})

    def _deny(self) -> None:
        if self._role() is None:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "unauthorized", "detail": "缺少有效 Bearer 令牌"},
            )
        else:
            # 对外角色触碰内部/原数据入口：明确权限隔离，不泄露入口是否存在
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden", "detail": "对外角色无权访问该资源（原数据入口已隔离）"},
            )


def serve(host: str = "127.0.0.1", port: int = 18080) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.gateway = build_gateway()  # type: ignore[attr-defined]
    print(f"隐私网关监听 http://{host}:{port}  专用页面 /portal")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    serve(
        host=os.environ.get("GATEWAY_HOST", "127.0.0.1"),
        port=int(os.environ.get("GATEWAY_PORT", "18080")),
    )
