import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.base import Certificate

from docker_mtls_example.scripts.cryptography.models import SubjectX509


def ca_builder(
    subject: x509.Name,
    issuer: x509.Name,
    private_key: rsa.RSAPrivateKey,
    not_valid_before: datetime.datetime,
    not_valid_after: datetime.datetime,
    path_length: int | None = None,
) -> x509.CertificateBuilder:
    """
    Creates a Certificate Authority (CA) certificate builder.

    Args:
        subject (x509.Name): The subject name of the CA certificate.
        issuer (x509.Name): The issuer name of the CA certificate, which is typically the same as the subject.
        private_key (rsa.RSAPrivateKey): The private key used to sign the CA certificate.
        not_valid_before (datetime.datetime): The date and time before which the CA certificate is not valid.
        not_valid_after (datetime.datetime): The date and time after which the CA certificate is not valid.
        path_length (int | None, optional): The maximum number of intermediate certificates that can be issued below this CA. Defaults to None.

    Returns:
        x509.CertificateBuilder: A CertificateBuilder object representing the CA certificate.
    """
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .serial_number(x509.random_serial_number())
        .public_key(private_key.public_key())
        .not_valid_before(
            not_valid_before,
        )
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )


def make_self_signed_root_ca(
    subject: SubjectX509, private_key: rsa.RSAPrivateKey, valid_for: datetime.timedelta
) -> x509.Certificate:
    """
    Generates a self-signed root CA certificate.

    Args:
        subject (SubjectX509): The subject of the certificate.
        private_key (rsa.RSAPrivateKey): The private key for the certificate.
        valid_for (datetime.timedelta): The duration for which the certificate is valid.

    Returns:
        x509.Certificate: The self-signed root CA certificate.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    subject_name = issuer_name = subject.to_x509_name_cryptography()
    builder: x509.CertificateBuilder = ca_builder(
        subject=subject_name,
        issuer=issuer_name,
        private_key=private_key,
        not_valid_before=now,
        not_valid_after=now + valid_for,
    )
    return builder.sign(private_key, hashes.SHA256())


def make_intermediate_ca(
    subject: SubjectX509,
    private_key: rsa.RSAPrivateKey,
    root_cert: x509.Certificate,
    root_key: rsa.RSAPrivateKey,
    valid_for: datetime.timedelta,
) -> Certificate:
    """
    Generates an intermediate CA certificate.

    Args:
        subject (SubjectX509): The subject of the intermediate CA.
        private_key (rsa.RSAPrivateKey): The private key for the intermediate CA.
        root_cert (x509.Certificate): The self-signed root CA certificate.
        root_key (rsa.RSAPrivateKey): The private key for the self-signed root CA.
        valid_for (datetime.timedelta): The validity period of the intermediate CA.

    Returns:
        Certificate: The generated intermediate CA certificate.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    subject_name = subject.to_x509_name_cryptography()
    issuer_name = root_cert.subject
    builder: x509.CertificateBuilder = ca_builder(
        subject=subject_name,
        issuer=issuer_name,
        private_key=private_key,
        not_valid_before=now,
        not_valid_after=now + valid_for,
        path_length=0,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        ),
        critical=False,
    )
    return builder.sign(root_key, hashes.SHA256())
