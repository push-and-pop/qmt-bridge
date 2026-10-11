"""局域网发现信标 ── 让主力机无需预先知道 IP 就能找到这台 QMT Bridge。

miniQMT 只能跑在 Windows 上，主力机（Mac/Linux）要连过来得先知道这台 Windows 的
局域网 IP。手填 IP 在 DHCP 下很脆：路由器重启、租约过期，IP 就变了。信标解决这个：
服务端在一个 UDP 端口上监听探测包，收到就把自己的 HTTP 端口、版本、是否开了交易
等信息单播回去，客户端广播一次就能收齐全网所有 Bridge 的应答。

**纯标准库**，且刻意不 import xtquant / fastapi —— 信标要能在任意平台（含 CI 的
Linux）被导入和单元测试，不依赖只有 Windows 才装得上的交易端。真正的 xtquant 由
HTTP 服务那一侧持有，信标只负责"我在这里、HTTP 在哪个端口"。

协议（UDP，JSON 单行）：
    探测 →  {"magic": "qmt-bridge-discover", "v": 1, "nonce": "<可选>"}
    应答 ←  {"magic": "qmt-bridge", "v": 1, "http_port": 8000, "trading": true,
            "account": true, "version": "2.8.1", "name": "<主机名>", "nonce": "<回显>"}
应答里带回探测包的 ``nonce``，客户端据此丢弃过期/串扰的应答。
"""

from __future__ import annotations

import json
import logging
import socket
import threading

logger = logging.getLogger("qmt_bridge")

# 发现协议常量。客户端（xtrader 侧）必须用同一组值，改这里要同步改对端。
MAGIC_PROBE = "qmt-bridge-discover"
MAGIC_REPLY = "qmt-bridge"
PROTOCOL_VERSION = 1
DEFAULT_DISCOVERY_PORT = 8001
# 单个数据报上限。探测/应答都是几十字节的小 JSON，1500 足够且挡住异常大包。
_MAX_DATAGRAM = 1500


class BridgeBeacon:
    """在 UDP 端口上应答局域网发现探测的后台线程。

    不持有 xtquant，也不触碰 HTTP 服务；只把构造时给定的静态信息（HTTP 端口、是否
    开了交易、账户是否就绪）在收到合法探测时回出去。``start`` 幂等，``stop`` 可重入。
    """

    def __init__(
        self,
        *,
        http_port: int,
        discovery_port: int = DEFAULT_DISCOVERY_PORT,
        trading: bool = False,
        account_present: bool = False,
        version: str = "",
        name: str | None = None,
        bind_host: str = "0.0.0.0",
    ) -> None:
        self.http_port = int(http_port)
        self.discovery_port = int(discovery_port)
        self.trading = bool(trading)
        self.account_present = bool(account_present)
        self.version = str(version)
        self.name = name or socket.gethostname()
        self.bind_host = bind_host
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def _reply_payload(self, nonce: object) -> bytes:
        body = {
            "magic": MAGIC_REPLY,
            "v": PROTOCOL_VERSION,
            "http_port": self.http_port,
            "trading": self.trading,
            "account": self.account_present,
            "version": self.version,
            "name": self.name,
        }
        if isinstance(nonce, str) and nonce:
            body["nonce"] = nonce
        return json.dumps(body, ensure_ascii=False).encode("utf-8")

    def _is_probe(self, data: bytes) -> tuple[bool, object]:
        """判定一个数据报是不是合法探测，顺带取出要回显的 nonce。"""
        try:
            message = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, None
        if not isinstance(message, dict) or message.get("magic") != MAGIC_PROBE:
            return False, None
        return True, message.get("nonce")

    def _serve(self) -> None:
        sock = self._sock
        assert sock is not None
        while self._running:
            try:
                data, addr = sock.recvfrom(_MAX_DATAGRAM)
            except TimeoutError:
                continue
            except OSError:
                # 套接字在 stop() 里被关掉时 recvfrom 会抛错，正常退出循环。
                break
            ok, nonce = self._is_probe(data)
            if not ok:
                continue
            try:
                sock.sendto(self._reply_payload(nonce), addr)
            except OSError:
                logger.debug("discovery beacon failed to reply to %s", addr)

    def start(self) -> BridgeBeacon:
        """绑定 UDP 端口并起后台线程。重复调用不叠加线程。"""
        if self._running:
            return self
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 0.5s 超时让 recvfrom 周期性回到循环检查 _running，从而能被 stop() 打断。
        sock.settimeout(0.5)
        sock.bind((self.bind_host, self.discovery_port))
        self._sock = sock
        self._running = True
        self._thread = threading.Thread(
            target=self._serve, name="qmt-bridge-discovery", daemon=True
        )
        self._thread.start()
        logger.info(
            "Discovery beacon listening on udp/%s (http_port=%s)",
            self.bound_port,
            self.http_port,
        )
        return self

    @property
    def bound_port(self) -> int:
        """实际绑定的 UDP 端口。``discovery_port=0`` 时由内核分配，测试据此取真实端口。"""
        if self._sock is not None:
            return int(self._sock.getsockname()[1])
        return self.discovery_port

    def stop(self) -> None:
        """停止线程并关闭套接字。可安全重复调用。"""
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


__all__ = [
    "DEFAULT_DISCOVERY_PORT",
    "MAGIC_PROBE",
    "MAGIC_REPLY",
    "PROTOCOL_VERSION",
    "BridgeBeacon",
]
