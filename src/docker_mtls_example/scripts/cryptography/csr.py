import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.base import Certificate, CertificateSigningRequest

from docker_mtls_example.scripts.cryptography.models import SubjectX509


def make_csr(
    subject: SubjectX509,
    private_key: rsa.RSAPrivateKey,
) -> CertificateSigningRequest:
    """
    Generates a Certificate Signing Request (CSR) for the given subject and private key.

    Args:
        subject (SubjectX509): The subject information for the CSR.
        private_key (rsa.RSAPrivateKey): The private key to use for signing the CSR.

    Returns:
        CertificateSigningRequest: The generated CSR.
    """
    subject_name = subject.to_x509_name_cryptography()
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject_name)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in subject.alternate_names]),
            critical=False,
        )
    )
    return builder.sign(private_key, hashes.SHA256())


def cert_from_csr(
    csr: x509.CertificateSigningRequest,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    valid_for: datetime.timedelta,
) -> Certificate:
    """
    Generate a certificate from a CSR using the provided CA key and certificate.

    Args:
        csr (CertificateSigningRequest): The CSR to sign.
        ca_key (RSAPrivateKey): The private key of the CA used to sign the certificate.
        ca_cert (Certificate): The CA certificate used to sign the certificate.
        valid_for (timedelta): The duration for which the certificate should be valid.

    Returns:
        Certificate: The signed certificate.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + valid_for)
        .add_extension(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.ExtendedKeyUsageOID.SERVER_AUTH,
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
    )

    return builder.sign(ca_key, hashes.SHA256())
