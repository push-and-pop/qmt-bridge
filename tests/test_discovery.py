"""局域网发现信标的单元测试（纯标准库，不依赖 xtquant/fastapi）。"""

from __future__ import annotations

import json
import socket

from qmt_bridge.server.discovery import (
    MAGIC_PROBE,
    MAGIC_REPLY,
    PROTOCOL_VERSION,
    BridgeBeacon,
)


def _probe(port: int, payload: bytes, timeout: float = 2.0) -> dict:
    """向本机信标发一个探测包，返回解析后的应答。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, ("127.0.0.1", port))
        data, _ = sock.recvfrom(1500)
        return json.loads(data.decode("utf-8"))
    finally:
        sock.close()


def test_beacon_replies_to_a_valid_probe_with_its_service_info() -> None:
    beacon = BridgeBeacon(
        http_port=8000,
        discovery_port=0,  # 让内核分配空闲端口，避免测试间端口冲突
        trading=True,
        account_present=True,
        version="9.9.9",
        name="winbox",
    ).start()
    try:
        probe = json.dumps(
            {"magic": MAGIC_PROBE, "v": PROTOCOL_VERSION, "nonce": "abc123"}
        ).encode()
        reply = _probe(beacon.bound_port, probe)
    finally:
        beacon.stop()

    assert reply["magic"] == MAGIC_REPLY
    assert reply["http_port"] == 8000
    assert reply["trading"] is True
    assert reply["account"] is True
    assert reply["version"] == "9.9.9"
    assert reply["name"] == "winbox"
    assert reply["nonce"] == "abc123"  # nonce 必须原样回显


def test_beacon_ignores_non_probe_datagrams() -> None:
    beacon = BridgeBeacon(http_port=8000, discovery_port=0).start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.6)
        try:
            # 乱码和 magic 不对的 JSON 都不应收到应答。
            sock.sendto(b"\xff\x00not-json", ("127.0.0.1", beacon.bound_port))
            sock.sendto(
                json.dumps({"magic": "something-else"}).encode(),
                ("127.0.0.1", beacon.bound_port),
            )
            got_reply = True
            try:
                sock.recvfrom(1500)
            except TimeoutError:
                got_reply = False
            assert got_reply is False
        finally:
            sock.close()
    finally:
        beacon.stop()


def test_beacon_start_is_idempotent_and_stop_is_reentrant() -> None:
    beacon = BridgeBeacon(http_port=8000, discovery_port=0).start()
    port = beacon.bound_port
    beacon.start()  # 不应另起线程或换端口
    assert beacon.bound_port == port
    beacon.stop()
    beacon.stop()  # 重复 stop 不抛
