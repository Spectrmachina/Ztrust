import pytest
from conftest import make_sapling_address, make_unified_address

from ztrust.bounty.zcash import (
    b58check_encode,
    build_payment_uri,
    classify_address,
    format_zec,
    parse_payment_uri,
    zec_to_zats,
)


def test_amount_conversion():
    assert zec_to_zats("1.5") == 150_000_000
    assert zec_to_zats("0.00000001") == 1
    assert format_zec(150_000_000) == "1.5"
    assert format_zec(1) == "0.00000001"
    assert format_zec(500_000_000) == "5"
    with pytest.raises(ValueError):
        zec_to_zats("0.000000001")
    with pytest.raises(ValueError):
        zec_to_zats("-1")
    with pytest.raises(ValueError):
        zec_to_zats("21000001")


def test_sapling_and_unified_classification():
    sapling = make_sapling_address()
    info = classify_address(sapling)
    assert info.valid and info.kind == "sapling" and info.network == "main" and info.shielded

    ua = make_unified_address(network="test")
    info = classify_address(ua)
    assert info.valid and info.kind == "unified" and info.network == "test"


def test_corrupted_address_is_invalid():
    sapling = make_sapling_address()
    flipped = sapling[:-1] + ("q" if sapling[-1] != "q" else "p")
    assert not classify_address(flipped).valid


def test_transparent_address():
    addr = b58check_encode(b"\x1c\xb8" + bytes(range(20)))
    assert addr.startswith("t1")
    info = classify_address(addr)
    assert info.valid and info.kind == "transparent-p2pkh" and not info.shielded


def test_zip321_roundtrip():
    addr = make_unified_address()
    uri = build_payment_uri(addr, amount_zats=12_345_678, memo="ztrust:fund:prg_1", message="Thanks for securing OSS")
    assert uri.startswith(f"zcash:{addr}?amount=0.12345678&memo=")
    parsed = parse_payment_uri(uri)
    assert parsed["address"] == addr
    assert parsed["amount_zats"] == 12_345_678
    assert parsed["memo"] == b"ztrust:fund:prg_1"
    assert parsed["message"] == "Thanks for securing OSS"


def test_zip321_rejects_memo_to_transparent():
    addr = b58check_encode(b"\x1c\xb8" + bytes(20))
    with pytest.raises(ValueError):
        build_payment_uri(addr, memo="hi")


def test_memo_size_limit():
    with pytest.raises(ValueError):
        build_payment_uri(make_sapling_address(), memo="x" * 513)
