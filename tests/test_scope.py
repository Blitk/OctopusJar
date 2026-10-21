"""Tests for explicit URL scope validation."""

import pytest

from octopusjar.scope import Allowlist, ScopeError, parse_origin


def test_permits_exact_origin_and_paths() -> None:
    allowed = Allowlist.from_urls(["https://api.example.test"])
    assert allowed.permits("https://api.example.test/v1/users?limit=10")
    assert allowed.permits("https://API.EXAMPLE.TEST./health")


def test_subdomains_are_not_implicitly_allowed() -> None:
    allowed = Allowlist.from_urls(["https://example.test"])
    assert not allowed.permits("https://api.example.test")


def test_scheme_and_port_must_match() -> None:
    allowed = Allowlist.from_urls(["https://api.example.test"])
    assert not allowed.permits("http://api.example.test")
    assert not allowed.permits("https://api.example.test:8443")


def test_default_port_equals_explicit_default_port() -> None:
    allowed = Allowlist.from_urls(["https://api.example.test:443"])
    assert allowed.permits("https://api.example.test/resource")


@pytest.mark.parametrize(
    "url",
    [
        "",
        " api.example.test",
        "//api.example.test/path",
        "ftp://api.example.test",
        "https:///missing-host",
        "https://user:secret@api.example.test",
        "https://api.example.test:bad/",
        "https://api.example.test:99999/",
        "https://",
    ],
)
def test_rejects_invalid_or_unsafe_targets(url: str) -> None:
    allowed = Allowlist.from_urls(["https://api.example.test"])
    assert not allowed.permits(url)


def test_rejects_allowlist_entries_with_paths() -> None:
    with pytest.raises(ScopeError, match="must be an origin"):
        Allowlist.from_urls(["https://api.example.test/v1"])


def test_allowlist_must_not_be_empty() -> None:
    with pytest.raises(ScopeError, match="at least one"):
        Allowlist.from_urls([])


def test_ip_addresses_are_normalized_and_compared_exactly() -> None:
    allowed = Allowlist.from_urls(["http://127.0.0.1:8000"])
    assert allowed.permits("http://127.0.0.1:8000/health")
    assert not allowed.permits("http://127.0.0.1:8001/health")


def test_require_permitted_raises_for_out_of_scope_target() -> None:
    allowed = Allowlist.from_urls(["https://api.example.test"])
    with pytest.raises(ScopeError, match="not present in the allowlist"):
        allowed.require_permitted("https://other.example.test")


def test_parse_origin_normalizes_default_https_port() -> None:
    assert parse_origin("HTTPS://API.EXAMPLE.TEST").port == 443
