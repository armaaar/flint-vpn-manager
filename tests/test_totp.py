"""Tests for vpn.totp (RFC 6238 test vectors)."""

import base64

import pytest

from vpn.totp import parse_totp, seconds_left, totp_code

# RFC 6238 Appendix B secrets (ASCII), 8 digits
_SHA1 = base64.b32encode(b"12345678901234567890").decode()
_SHA256 = base64.b32encode(b"12345678901234567890123456789012").decode()
_SHA512 = base64.b32encode(b"1234567890" * 6 + b"1234").decode()


@pytest.mark.parametrize("t,secret,alg,expected", [
    (59, _SHA1, "SHA1", "94287082"),
    (1111111109, _SHA1, "SHA1", "07081804"),
    (1234567890, _SHA1, "SHA1", "89005924"),
    (20000000000, _SHA1, "SHA1", "65353130"),
    (59, _SHA256, "SHA256", "46119246"),
    (1234567890, _SHA256, "SHA256", "91819424"),
    (59, _SHA512, "SHA512", "90693936"),
    (1234567890, _SHA512, "SHA512", "93441116"),
])
def test_rfc6238_vectors(t, secret, alg, expected):
    cfg = {"secret": secret, "digits": 8, "period": 30, "algorithm": alg}
    assert totp_code(cfg, at=t) == expected


def test_parse_bare_secret_normalises():
    cfg = parse_totp(" jbsw y3dp-ehpk 3pxp ")
    assert cfg == {"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30, "algorithm": "SHA1"}
    assert len(totp_code(cfg)) == 6


def test_parse_otpauth_uri():
    cfg = parse_totp("otpauth://totp/Corp:alice?secret=JBSWY3DPEHPK3PXP&issuer=Corp&digits=8&period=60&algorithm=SHA256")
    assert cfg["secret"] == "JBSWY3DPEHPK3PXP"
    assert (cfg["digits"], cfg["period"], cfg["algorithm"]) == (8, 60, "SHA256")
    assert cfg["label"] == "Corp:alice"


@pytest.mark.parametrize("bad", ["", "not base32!", "ABC", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
                                 "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"])
def test_rejects_invalid(bad):
    with pytest.raises(ValueError):
        parse_totp(bad)


def test_seconds_left():
    assert seconds_left({"period": 30}, at=59) == 1
    assert seconds_left({"period": 30}, at=60) == 30
