"""The egress proxy's CA, so tools inside the sandbox can verify HTTPS through it. Layer 5 (containment).

Why it exists: the proxy reads HTTPS requests (to apply the allowlist and the canary scan) by terminating TLS and re-signing
with its own CA. A client only accepts that if it trusts the CA. We therefore give the sandbox the CA *certificate* (public) and
nothing else. The CA *private key* is generated on the host and mounted only into the proxy container.
Invariants: the key is never in a directory the sandbox mounts; the public file holds one certificate and no key; the key file
is 0600 in a 0700 directory; an existing, readable pair is kept (so a running sandbox stays valid), a damaged one is replaced.
Layout under <state>/mitm-ca/:  private/mitmproxy-ca.pem (key + cert, the file mitmproxy reads)   public/airlock-proxy-ca.crt
"""
from __future__ import annotations

import datetime
import os
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PUBLIC_NAME = "airlock-proxy-ca.crt"
PRIVATE_NAME = "mitmproxy-ca.pem"
VALID_DAYS = 3650


def _usable(private_pem: Path, public_crt: Path) -> bool:
    try:
        key_and_cert = private_pem.read_bytes()
        serialization.load_pem_private_key(key_and_cert, password=None)
        a = x509.load_pem_x509_certificate(key_and_cert)
        b = x509.load_pem_x509_certificate(public_crt.read_bytes())
        now = datetime.datetime.now(datetime.timezone.utc)
        return a.fingerprint(hashes.SHA256()) == b.fingerprint(hashes.SHA256()) and a.not_valid_after_utc > now + datetime.timedelta(days=30)
    except (OSError, ValueError):
        return False


def ensure_proxy_ca(state_dir: Path) -> Path:
    """Create the CA if there is no usable one. Returns the path of the PUBLIC certificate."""
    root = Path(state_dir) / "mitm-ca"
    private_dir, public_dir = root / "private", root / "public"
    private_pem, public_crt = private_dir / PRIVATE_NAME, public_dir / PUBLIC_NAME
    if _usable(private_pem, public_crt):
        return public_crt
    shutil.rmtree(root, ignore_errors=True)
    private_dir.mkdir(parents=True)
    public_dir.mkdir(parents=True)
    os.chmod(private_dir, 0o700)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Airlock (demo)"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "Airlock sandbox proxy CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())

    fd = os.open(private_pem, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # never briefly world-readable
    with os.fdopen(fd, "wb") as f:
        f.write(key_pem + cert_pem)
    public_crt.write_bytes(cert_pem)
    os.chmod(public_dir, 0o755)
    os.chmod(public_crt, 0o644)
    return public_crt
