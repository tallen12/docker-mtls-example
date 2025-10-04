from dataclasses import dataclass, field

from attr import dataclass
from cryptography import x509
from cryptography.x509.oid import NameOID


@dataclass
class SubjectX509:
    """
    Represents a subject in an X.509 certificate.

    Attributes:
        common_name (str): The common name of the subject.
        organization_name (str): The organization name of the subject.
        organizational_unit_name (str): The organizational unit name of the subject.
        locality_name (str): The locality name of the subject.
        state_or_province_name (str): The state or province name of the subject.
        country_name (str): The country name of the subject.
    """

    country_name: str | None = None
    state_or_province_name: str | None = None
    locality_name: str | None = None
    organization_name: str | None = None
    email_address: str | None = None
    common_name: str | None = None
    alternate_names: list[str] = field(default_factory=list)

    def to_x509_name_cryptography(self):
        """
        Converts the SubjectX509 dataclass object to a cryptography.x509.Name object.

        Returns:
            x509.Name: The X.509 name representation of the subject.
        """
        name_attributes = (
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name) if self.country_name else None,
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province_name)
            if self.state_or_province_name
            else None,
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality_name) if self.locality_name else None,
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name) if self.organization_name else None,
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email_address) if self.email_address else None,
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name) if self.common_name else None,
        )
        return x509.Name([name for name in name_attributes if name])
