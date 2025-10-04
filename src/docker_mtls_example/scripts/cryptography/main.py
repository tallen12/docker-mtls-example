from datetime import timedelta
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.base import CertificateSigningRequest
from cyclopts import App

from docker_mtls_example.scripts.cryptography.ca import make_self_signed_root_ca
from docker_mtls_example.scripts.cryptography.csr import cert_from_csr, make_csr
from docker_mtls_example.scripts.cryptography.models import SubjectX509
from docker_mtls_example.scripts.types import TimePeriod


def generate_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """
    Generates an RSA private key with the specified key size.

    Args:
        key_size (int, optional): The size of the RSA key in bits. Defaults to 4096.

    Returns:
        rsa.RSAPrivateKey: An RSA private key.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )


def save_certs(
    key_path: Path, key: rsa.RSAPrivateKey, cert_path: Path, cert: x509.Certificate | CertificateSigningRequest
):
    """
    Save the RSA private key and certificate to the specified paths.

    Args:
        key_path (Path): The path where the RSA private key will be saved.
        key (rsa.RSAPrivateKey): The RSA private key to save.
        cert_path (Path): The path where the certificate will be saved.
        cert (x509.Certificate | CertificateSigningRequest): The certificate or CSR to save.

    Returns:
        None
    """
    #  Write cert and private key, since this is a toy app no need to encrypt the private key
    with open(cert_path, "wb") as cf:
        cf.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as cf:
        cf.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


app = App()


@app.command(name="generate-root-ca")
def generate_root_ca(
    subject: SubjectX509,
    valid_for: TimePeriod = timedelta(days=365),
    certs_path=Path("./certs/"),
):
    """
    Generates a self-signed root CA certificate and saves it to the specified path.

    Args:
        subject (SubjectX509): The subject information for the CA certificate.
        valid_for (TimePeriod, optional): The validity period of the CA certificate. Defaults to 365 days.
        certs_path (Path, optional): The directory where the CA certificate and key will be saved. Defaults to "./certs/".

    Returns:
        None
    """
    key = generate_rsa_key()
    cert = make_self_signed_root_ca(subject=subject, private_key=key, valid_for=valid_for)
    certs_path.mkdir(parents=True, exist_ok=True)
    cert_path = certs_path / "root-ca.cert"
    key_path = certs_path / "root-private-key.pem"
    save_certs(key_path=key_path, key=key, cert_path=cert_path, cert=cert)


@app.command(name="generate-intermediate-ca")
def generate_intermediate_ca(
    subject: SubjectX509,
    valid_for: TimePeriod = timedelta(days=365),
    certs_path=Path("./certs/"),
):
    """
    Generates an intermediate CA certificate and private key.

    Args:
        subject (SubjectX509): The subject information for the certificate.
        valid_for (TimePeriod, optional): The validity period of the certificate. Defaults to timedelta(days=365).
        certs_path (Path, optional): The path where the certificates will be saved. Defaults to Path("./certs/").

    Returns:
        None
    """
    key = generate_rsa_key()
    cert = make_self_signed_root_ca(subject=subject, private_key=key, valid_for=valid_for)
    certs_path.mkdir(parents=True, exist_ok=True)
    cert_path = certs_path / "intermediate-ca.cert"
    key_path = certs_path / "intermediate-private-key.pem"
    save_certs(key_path=key_path, key=key, cert_path=cert_path, cert=cert)


@app.command(name="generate-csr")
def generate_csr(domain: str, subject: SubjectX509, csrs_path=Path("./csr/"), certs_path=Path("./certs")):
    """
    Generates a Certificate Signing Request (CSR) for the given domain and subject.

    Args:
        domain (str): The domain name to be included in the CSR.
        subject (SubjectX509): The subject information to be included in the CSR.
        csrs_path (Path, optional): The path where the CSR file will be saved. Defaults to Path("./csr/").
        certs_path (Path, optional): The path where the intermediate CA certificate and key are located. Defaults to Path("./certs").

    Returns:
        None
    """
    if domain not in subject.alternate_names:
        raise ValueError("Domain not in subject alternate names.")
    key = generate_rsa_key()
    cert = make_csr(subject=subject, private_key=key)
    csrs_path.mkdir(parents=True, exist_ok=True)
    certs_path.mkdir(parents=True, exist_ok=True)
    csr_path = csrs_path / f"{domain}.csr"
    key_path = certs_path / f"{domain}-key.pem"
    save_certs(key_path=key_path, key=key, cert_path=csr_path, cert=cert)


@app.command(name="process-csrs")
def process_csrs(
    intermediate_ca_path: Path,
    intermediate_ca_key_path: Path,
    csrs_path=Path("./csr/"),
    certs_path=Path("./certs"),
    valid_for: TimePeriod = timedelta(days=365),
) -> None:
    """
    Process all Certificate Signing Requests (CSRs) found in csrs_path and place the resulting certificates in certs_path.

    Args:
        intermediate_ca_path (Path): Path to the intermediate CA certificate.
        intermediate_ca_key_path (Path): Path to the intermediate CA private key.
        csrs_path (Path, optional): Path to the directory containing CSRs. Defaults to Path("./csr/").
        certs_path (Path, optional): Path to the directory where certificates will be saved. Defaults to Path("./certs").
        valid_for (TimePeriod, optional): Duration for which the certificate is valid. Defaults to timedelta(days=365).

    Returns:
        None
    """
    csrs_path.mkdir(parents=True, exist_ok=True)
    certs_path.mkdir(parents=True, exist_ok=True)
    with open(intermediate_ca_path, "rb") as ca_file:
        ca_cert = x509.load_pem_x509_certificate(ca_file.read())
    with open(intermediate_ca_key_path, "rb") as ca_key_file:
        # This will always be a RSA key
        ca_key = cast(rsa.RSAPrivateKey, serialization.load_pem_private_key(ca_key_file.read(), password=None))

    for file in csrs_path.glob("*.csr"):
        print(f"Signing cert for {file}")

        with open(file, "rb") as cf:
            csr = x509.load_pem_x509_csr(cf.read())
            cert = cert_from_csr(csr, ca_key=ca_key, ca_cert=ca_cert, valid_for=valid_for)
        cert_path = certs_path / f"{file.stem}.cert"
        with open(cert_path, "wb") as cf:
            cf.write(cert.public_bytes(serialization.Encoding.PEM))
