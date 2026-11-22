"""The proxy's CA: its PRIVATE key stays with the proxy; the sandbox only ever gets the public certificate.
Trusting this CA is what lets the proxy read HTTPS to scan it for canaries (docs/THREAT_MODEL.md). No Docker needed."""
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from airlock.sandbox.ca import PUBLIC_NAME, ensure_proxy_ca


@pytest.fixture
def state(tmp_path):
    return tmp_path / "state"


def test_public_dir_holds_only_a_ca_certificate_and_no_private_key(state):
    pub = ensure_proxy_ca(state)
    public_dir = state / "mitm-ca" / "public"
    assert sorted(p.name for p in public_dir.iterdir()) == [PUBLIC_NAME] and pub == public_dir / PUBLIC_NAME
    text = pub.read_text()
    assert "PRIVATE KEY" not in text and text.count("BEGIN CERTIFICATE") == 1
    cert = x509.load_pem_x509_certificate(pub.read_bytes())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True and cert.subject == cert.issuer                      # a self-signed CA
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True


def test_private_key_exists_only_in_the_private_dir_and_is_not_readable_by_others(state):
    ensure_proxy_ca(state)
    root = state / "mitm-ca"
    holders = [p for p in root.rglob("*") if p.is_file() and "PRIVATE KEY" in p.read_text()]
    assert [p.parent.name for p in holders] == ["private"]
    key_file = root / "private" / "mitmproxy-ca.pem"
    assert holders == [key_file]
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600 and stat.S_IMODE((root / "private").stat().st_mode) == 0o700
    # the combined file mitmproxy reads holds the SAME certificate the sandbox is given
    pem = key_file.read_bytes()
    assert serialization.load_pem_private_key(pem, password=None) is not None
    assert x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()) == \
        x509.load_pem_x509_certificate((root / "public" / PUBLIC_NAME).read_bytes()).fingerprint(hashes.SHA256())


def test_running_it_again_keeps_the_same_ca_so_a_running_sandbox_stays_valid(state):
    first = ensure_proxy_ca(state).read_bytes()
    assert ensure_proxy_ca(state).read_bytes() == first


def test_a_damaged_or_missing_half_is_regenerated_not_trusted(state):
    ensure_proxy_ca(state)
    (state / "mitm-ca" / "private" / "mitmproxy-ca.pem").write_text("garbage")
    again = ensure_proxy_ca(state)
    assert "PRIVATE KEY" in (state / "mitm-ca" / "private" / "mitmproxy-ca.pem").read_text()
    x509.load_pem_x509_certificate(again.read_bytes())
    (state / "mitm-ca" / "public" / PUBLIC_NAME).unlink()
    assert ensure_proxy_ca(state).exists()


def test_the_ca_is_not_valid_for_anything_but_signing_site_certificates_and_is_not_a_leaf(state):
    cert = x509.load_pem_x509_certificate(ensure_proxy_ca(state).read_bytes())
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0   # may sign leaf certs only
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days >= 365
