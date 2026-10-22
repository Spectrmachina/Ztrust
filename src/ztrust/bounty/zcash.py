"""Zcash primitives used by ZTrust — pure Python, no node required.

* amount handling in zatoshis (1 ZEC = 10^8 zat)
* address classification + checksum validation
  - transparent (Base58Check)              t1… / t3… / tm… / t2…
  - Sapling (Bech32)                        zs1… / ztestsapling1…
  - Unified addresses, ZIP-316 (Bech32m)    u1… / utest1…
  - TEX addresses, ZIP-320 (Bech32m)        tex1… / textest1…
* ZIP-321 payment request URIs (``zcash:<addr>?amount=…&memo=…``)

References:
  https://zips.z.cash/zip-0316  https://zips.z.cash/zip-0320  https://zips.z.cash/zip-0321
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from urllib.parse import parse_qsl, quote, unquote

ZATS_PER_ZEC = 100_000_000
MAX_MONEY_ZATS = 21_000_000 * ZATS_PER_ZEC
MAX_MEMO_BYTES = 512

# --------------------------------------------------------------------------- amounts


def zec_to_zats(value: str | int | Decimal) -> int:
    try:
        amount = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"invalid ZEC amount: {value!r}") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError(f"invalid ZEC amount: {value!r}")
    zats = amount * ZATS_PER_ZEC
    if zats != zats.to_integral_value():
        raise ValueError("ZEC amounts support at most 8 decimal places")
    if zats > MAX_MONEY_ZATS:
        raise ValueError("amount exceeds the total ZEC supply")
    return int(zats)


def format_zec(zats: int) -> str:
    """Format zatoshis as a minimal decimal ZEC string (``150000000`` → ``"1.5"``)."""
    if zats < 0:
        raise ValueError("negative amount")
    whole, frac = divmod(zats, ZATS_PER_ZEC)
    return f"{whole}.{frac:08d}".rstrip("0").rstrip(".")


# --------------------------------------------------------------------------- bech32 / bech32m

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def _polymod(values: list[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= _GEN[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_decode(text: str) -> tuple[str, list[int], str] | None:
    """Decode without the BIP-173 90-char limit (unified addresses are longer)."""
    if text.lower() != text and text.upper() != text:
        return None
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        return None
    hrp, data = text[:pos], [_CHARSET.find(c) for c in text[pos + 1 :]]
    if -1 in data or any(ord(c) < 33 or ord(c) > 126 for c in hrp):
        return None
    const = _polymod(_hrp_expand(hrp) + data)
    variant = {BECH32_CONST: "bech32", BECH32M_CONST: "bech32m"}.get(const)
    if variant is None:
        return None
    return hrp, data[:-6], variant


def bech32_encode(hrp: str, data: list[int], variant: str = "bech32") -> str:
    const = BECH32M_CONST if variant == "bech32m" else BECH32_CONST
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0] * 6) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc, bits, out = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out


# --------------------------------------------------------------------------- base58check

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TRANSPARENT_PREFIXES = {
    b"\x1c\xb8": ("transparent-p2pkh", "main"),  # t1
    b"\x1c\xbd": ("transparent-p2sh", "main"),  # t3
    b"\x1d\x25": ("transparent-p2pkh", "test"),  # tm
    b"\x1c\xba": ("transparent-p2sh", "test"),  # t2
}


def _double_sha(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def b58check_encode(payload: bytes) -> str:
    raw = payload + _double_sha(payload)[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + out


def b58check_decode(text: str) -> bytes | None:
    n = 0
    for ch in text:
        idx = _B58.find(ch)
        if idx < 0:
            return None
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    raw = b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    return payload if _double_sha(payload)[:4] == checksum else None


# --------------------------------------------------------------------------- classification

SHIELDED_HRPS = {
    "zs": ("sapling", "main", "bech32"),
    "ztestsapling": ("sapling", "test", "bech32"),
    "u": ("unified", "main", "bech32m"),
    "utest": ("unified", "test", "bech32m"),
    "tex": ("tex", "main", "bech32m"),
    "textest": ("tex", "test", "bech32m"),
}
VIEWING_KEY_HRPS = {
    "uview": ("unified-fvk", "main", "bech32m"),
    "uviewtest": ("unified-fvk", "test", "bech32m"),
    "zxviews": ("sapling-efvk", "main", "bech32"),
    "zxviewtestsapling": ("sapling-efvk", "test", "bech32"),
}


@dataclass(frozen=True)
class AddressInfo:
    kind: str  # sapling | unified | tex | transparent-p2pkh | transparent-p2sh | unknown
    network: str | None  # main | test
    valid: bool

    @property
    def shielded(self) -> bool:
        # ZIP-316 requires every Unified Address to contain at least one shielded receiver.
        return self.valid and self.kind in ("sapling", "unified")


def classify_address(address: str) -> AddressInfo:
    address = address.strip()
    if address[:1] == "t" and not address.lower().startswith("tex"):
        payload = b58check_decode(address)
        if payload and len(payload) == 22 and payload[:2] in TRANSPARENT_PREFIXES:
            kind, network = TRANSPARENT_PREFIXES[payload[:2]]
            return AddressInfo(kind, network, True)
        return AddressInfo("transparent", None, False)
    decoded = bech32_decode(address)
    if decoded:
        hrp, _data, variant = decoded
        if hrp in SHIELDED_HRPS:
            kind, network, expected = SHIELDED_HRPS[hrp]
            return AddressInfo(kind, network, variant == expected)
    return AddressInfo("unknown", None, False)


def is_viewing_key(value: str) -> bool:
    decoded = bech32_decode(value.strip())
    if not decoded:
        return False
    hrp, _data, variant = decoded
    return hrp in VIEWING_KEY_HRPS and VIEWING_KEY_HRPS[hrp][2] == variant


# --------------------------------------------------------------------------- ZIP-321


def encode_memo(memo: str | bytes) -> str:
    raw = memo.encode("utf-8") if isinstance(memo, str) else memo
    if len(raw) > MAX_MEMO_BYTES:
        raise ValueError(f"memo is {len(raw)} bytes; Zcash memos are limited to {MAX_MEMO_BYTES}")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_memo(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def build_payment_uri(
    address: str,
    amount_zats: int | None = None,
    memo: str | bytes | None = None,
    message: str | None = None,
    label: str | None = None,
) -> str:
    """Build a single-recipient ZIP-321 payment request URI."""
    info = classify_address(address)
    if not info.valid:
        raise ValueError(f"not a valid Zcash address: {address}")
    params: list[tuple[str, str]] = []
    if amount_zats is not None:
        if not 0 <= amount_zats <= MAX_MONEY_ZATS:
            raise ValueError("amount out of range")
        params.append(("amount", format_zec(amount_zats)))
    if memo is not None:
        if not info.shielded:
            raise ValueError("ZIP-321 forbids memos for transparent / TEX recipients")
        params.append(("memo", encode_memo(memo)))
    if label:
        params.append(("label", quote(label, safe="")))
    if message:
        params.append(("message", quote(message, safe="")))
    query = "&".join(f"{k}={v}" for k, v in params)
    return f"zcash:{address}" + (f"?{query}" if query else "")


def parse_payment_uri(uri: str) -> dict[str, object]:
    """Parse a single-recipient ZIP-321 URI (indexed multi-payment params are not supported)."""
    if not uri.startswith("zcash:"):
        raise ValueError("not a zcash: URI")
    body = uri[len("zcash:") :]
    address, _, query = body.partition("?")
    result: dict[str, object] = {"address": unquote(address)}
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key == "amount":
            result["amount_zats"] = zec_to_zats(value)
        elif key == "memo":
            result["memo"] = decode_memo(value)
        elif key in ("message", "label"):
            result[key] = value
        elif key.startswith("req-"):
            raise ValueError(f"unsupported required parameter: {key}")
    return result
