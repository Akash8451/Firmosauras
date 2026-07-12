"""Unit tests for CPE parsing/building and family scoping (Task 9 support)."""
from __future__ import annotations

from services.cve_matching import config, cpe as cpe_mod


def test_parse_cpe_23_formatted_string():
    parts = cpe_mod.parse_cpe("cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*")
    assert parts is not None
    assert parts.part == "a"
    assert parts.vendor == "busybox"
    assert parts.product == "busybox"
    assert parts.version == "1.31.1"


def test_parse_cpe_22_uri_fallback():
    parts = cpe_mod.parse_cpe("cpe:/a:openssl:openssl:1.0.2")
    assert parts is not None
    assert parts.vendor == "openssl"
    assert parts.product == "openssl"
    assert parts.version == "1.0.2"


def test_parse_cpe_rejects_garbage():
    assert cpe_mod.parse_cpe("not-a-cpe") is None
    assert cpe_mod.parse_cpe("") is None


def test_build_cpe_wildcards_missing_fields():
    assert (
        cpe_mod.build_cpe("busybox", "busybox", "1.31.1")
        == "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*"
    )
    assert cpe_mod.build_cpe("", "busybox", "") == "cpe:2.3:a:*:busybox:*:*:*:*:*:*:*:*"


def test_family_for_in_scope_products():
    assert config.family_for("busybox", "busybox") == "busybox"
    assert config.family_for("openssl", "openssl") == "openssl"
    assert config.family_for("haxx", "libcurl") == "libcurl"
    assert config.family_for("linux", "linux_kernel") == "linux_kernel"


def test_family_for_out_of_scope_returns_none():
    assert config.family_for("microsoft", "windows_10") is None
    assert config.family_for("adobe", "acrobat") is None
    assert config.family_for(None, None) is None


def test_in_scope_cpes_filters_and_dedupes():
    cpes = [
        "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*",  # dup
        "cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*",  # out of scope
    ]
    scoped = cpe_mod.in_scope_cpes(cpes)
    assert scoped == ["cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*"]


def test_thresholds_default_and_per_family_override():
    assert config.thresholds_for(None) is config.DEFAULT_THRESHOLDS
    custom = config.ThresholdConfig(high_confidence=0.95, possible=0.75, low_confidence=0.55)
    config.set_family_thresholds("busybox", custom)
    try:
        assert config.thresholds_for("busybox") is custom
        assert config.thresholds_for("openssl") is config.DEFAULT_THRESHOLDS
    finally:
        config.FAMILY_THRESHOLDS.clear()


def test_threshold_config_rejects_inverted_bounds():
    import pytest

    with pytest.raises(ValueError):
        config.ThresholdConfig(high_confidence=0.5, possible=0.7, low_confidence=0.9)
