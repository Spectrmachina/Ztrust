"""Payout backends.

``RpcBackend`` speaks the zcashd-compatible JSON-RPC wallet API, which is also
the compatibility target of Zallet, the Rust wallet that replaces zcashd:
https://github.com/zcash/wallet

Payments use ``z_sendmany`` from a shielded account, so the payout amount,
recipient and memo are encrypted on-chain.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

from ztrust.bounty.zcash import MAX_MEMO_BYTES, ZATS_PER_ZEC


@dataclass
class PayoutResult:
    txid: str
    operation_id: str | None
    backend: str


class PayoutError(RuntimeError):
    pass


class ZcashBackend(Protocol):
    name: str

    def send(self, to_address: str, amount_zats: int, memo: str) -> PayoutResult: ...


class MockBackend:
    """Deterministic fake payments for development and tests. Never moves real funds."""

    name = "mock"

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, to_address: str, amount_zats: int, memo: str) -> PayoutResult:
        txid = hashlib.sha256(f"{to_address}:{amount_zats}:{memo}:{len(self.sent)}".encode()).hexdigest()
        self.sent.append({"to": to_address, "amount_zats": amount_zats, "memo": memo, "txid": txid})
        return PayoutResult(txid=txid, operation_id=None, backend=self.name)


class RpcBackend:
    """zcashd / Zallet JSON-RPC client."""

    name = "rpc"

    def __init__(
        self,
        url: str,
        from_address: str,
        user: str | None = None,
        password: str | None = None,
        privacy_policy: str = "FullPrivacy",
        minconf: int = 1,
        timeout: float = 30.0,
        poll_seconds: float = 120.0,
    ) -> None:
        self.url = url
        self.from_address = from_address
        self.privacy_policy = privacy_policy
        self.minconf = minconf
        self.timeout = timeout
        self.poll_seconds = poll_seconds
        self._auth = (
            "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() if user is not None else None
        )

    def call(self, method: str, params: list[Any]) -> Any:
        body = json.dumps({"jsonrpc": "1.0", "id": "ztrust", "method": method, "params": params}).encode()
        headers = {"Content-Type": "application/json"}
        if self._auth:
            headers["Authorization"] = self._auth
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.load(resp)
        except OSError as exc:
            raise PayoutError(f"RPC {method} failed: {exc}") from exc
        if payload.get("error"):
            raise PayoutError(f"RPC {method} error: {payload['error']}")
        return payload.get("result")

    def send(self, to_address: str, amount_zats: int, memo: str) -> PayoutResult:
        memo_bytes = memo.encode("utf-8")[:MAX_MEMO_BYTES]
        amount = Decimal(amount_zats) / ZATS_PER_ZEC
        recipient = {"address": to_address, "amount": float(amount), "memo": memo_bytes.hex()}
        # z_sendmany "fromaddress" [{address, amount, memo}] minconf fee privacyPolicy
        # fee=None lets the wallet apply the ZIP-317 conventional fee.
        opid = self.call("z_sendmany", [self.from_address, [recipient], self.minconf, None, self.privacy_policy])
        deadline = time.monotonic() + self.poll_seconds
        while time.monotonic() < deadline:
            statuses = self.call("z_getoperationstatus", [[opid]]) or []
            if statuses:
                op = statuses[0]
                if op.get("status") == "success":
                    return PayoutResult(txid=op["result"]["txid"], operation_id=opid, backend=self.name)
                if op.get("status") in ("failed", "cancelled"):
                    raise PayoutError(f"payment {opid} {op.get('status')}: {op.get('error')}")
            time.sleep(2)
        raise PayoutError(f"payment {opid} still pending after {self.poll_seconds:.0f}s")


def backend_from_env() -> ZcashBackend:
    kind = os.environ.get("ZTRUST_ZCASH_BACKEND", "mock").lower()
    if kind == "mock":
        return MockBackend()
    if kind == "rpc":
        try:
            return RpcBackend(
                url=os.environ["ZTRUST_ZCASH_RPC_URL"],
                from_address=os.environ["ZTRUST_ZCASH_FROM_ADDRESS"],
                user=os.environ.get("ZTRUST_ZCASH_RPC_USER"),
                password=os.environ.get("ZTRUST_ZCASH_RPC_PASSWORD"),
                privacy_policy=os.environ.get("ZTRUST_ZCASH_PRIVACY_POLICY", "FullPrivacy"),
            )
        except KeyError as exc:
            raise RuntimeError(f"missing environment variable {exc} for the rpc backend") from exc
    raise RuntimeError(f"unknown ZTRUST_ZCASH_BACKEND: {kind}")
