from proxy.logic import decide, find_canaries, host_allowed

CANARIES = ["sk-live-abc123", "maple-harbor-violet42"]
ALLOW = ["example.com", "localhost"]


def test_allowlisted_clean_request_passes():
    assert decide("api.example.com", "https://api.example.com/x", "Host: api.example.com", b"hello", ALLOW, CANARIES) is None


def test_offsite_host_is_blocked():
    ev = decide("evil.test", "https://evil.test/", "", b"", ALLOW, CANARIES)
    assert ev and ev["kind"] == "egress_blocked"


def test_canary_in_body_url_or_headers_is_a_leak_even_on_allowlisted_host():
    assert decide("example.com", "https://example.com/", "", b"key=sk-live-abc123", ALLOW, CANARIES)["kind"] == "canary_leak"
    assert decide("example.com", "https://example.com/?k=maple-harbor-violet42", "", b"", ALLOW, CANARIES)["kind"] == "canary_leak"
    assert decide("example.com", "https://example.com/", "X-Token: sk-live-abc123", b"", ALLOW, CANARIES)["kind"] == "canary_leak"


def test_suffix_trick_is_not_allowed():
    assert not host_allowed("example.com.evil.test", ALLOW)
    assert host_allowed("a.b.example.com", ALLOW)


def test_find_canaries_handles_mixed_types_and_empty_values():
    assert find_canaries([b"xx", "sk-live-abc123"], CANARIES + [""]) == ["sk-live-abc123"]
