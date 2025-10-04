import datetime

from cryptography.x509 import DNSName
from cryptography.x509.verification import PolicyBuilder, Store

from docker_mtls_example.scripts.cryptography.ca import make_intermediate_ca, make_self_signed_root_ca
from docker_mtls_example.scripts.cryptography.csr import cert_from_csr, make_csr
from docker_mtls_example.scripts.cryptography.main import generate_rsa_key
from docker_mtls_example.scripts.cryptography.models import SubjectX509


def main() -> None:
    root_key = generate_rsa_key()
    intermediate_key = generate_rsa_key()
    server_key = generate_rsa_key()

    root_subject = SubjectX509(common_name="Root CA")
    intermediate_subject = SubjectX509(common_name="Intermediate CA")
    server_subject = SubjectX509(common_name="Server", alternate_names=["server.docker"])

    root_ca = make_self_signed_root_ca(root_subject, root_key, datetime.timedelta(days=365))
    intermediate_ca = make_intermediate_ca(
        intermediate_subject, intermediate_key, root_ca, root_key, datetime.timedelta(days=365)
    )
    csr = make_csr(server_subject, server_key)

    server_cert = cert_from_csr(csr, intermediate_key, intermediate_ca, valid_for=datetime.timedelta(days=365))

    store = Store([root_ca])
    builder = PolicyBuilder().store(store)

    verifier = builder.build_server_verifier(DNSName("server.docker"))

    print(verifier.verify(server_cert, [intermediate_ca]))
