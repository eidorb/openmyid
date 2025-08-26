"""
So many clients...
- httpx.Client: HTTP client
- HttpClient: HTTP client with MyID-specific headers
- meatie_httpx.Client: Meatie base client (using httpx)
- Client: MyID client

Run doctests:
    uv run python -m doctest --verbose --option ELLIPSIS myid.py
"""

import base64
import random
import time
from dataclasses import dataclass
from typing import Annotated, Optional
from uuid import uuid4

import httpx
import jwt
import meatie_httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from meatie import api_ref, body, endpoint
from pydantic import BaseModel

# Static headers required by every request.
static_headers = {
    "X-AuditCallingAppName": "myID",
    "X-AuditCallingAppVersion": "3.1.0.2",
    # not strictly required
    # "User-Agent": "myID/0 CFNetwork/1220.1 Darwin/20.3.0",
}

base_url = "https://mygovid.gov.au/api/v1"


def add_request_id(request):
    """Adds unique request ID header to request."""
    request.headers["X-AuditRequestId"] = random.randbytes(16).hex()


def add_session_id(request):
    """Adds unique session ID header to request."""
    request.headers["X-AuditSessionId"] = random.randbytes(16).hex()


class TermsAndConditions(BaseModel):
    url: str
    version: str


class ProofOfIdentityProcess(BaseModel):
    status: str
    strength: str
    acceptedTermsAndConditionsVersion: str
    processId: str
    links: list[dict]


class EmailVerificationTask(BaseModel):
    id: int
    status: str
    eta: int
    remainingRetryCount: int
    processId: str
    links: list[dict]


class CertificateSigningTask(BaseModel):
    id: int
    status: str
    eta: int
    links: list[dict]


class EmailVerificationResult(BaseModel):
    verificationCodeResult: str
    poiAssuranceToken: str
    processId: str
    links: list[dict]


@dataclass
class EmailVerificationBody:
    emailAddress: str
    verificationCode: str


@dataclass
class CertificateSigningRequest:
    p10: str


class CertificateResponse(BaseModel):
    id: int
    p7: str
    p10: str
    credentialToken: str
    links: list[dict[str, str]]

    def decode_certificate_chain(self) -> list[x509.Certificate]:
        """Returns certificate chain contained in `p7` field.

        >>> certificate_response = CertificateResponse(id=0, p7="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", p10="...", credentialToken="...", links=[{"...": "..."}])
        >>> certificates = certificate_response.decode_certificate_chain()
        >>> certificates
        [<Certificate(subject=<Name(C=AU,O=mygovid.gov.au,CN=poi id,2.5.4.46=6a4aba42-b897-4478-b983-678f2bad1821)>, ...)>, <Certificate(subject=<Name(C=AU,O=Australian Taxation Office,OU=Certification Authority,CN=ATO Sub Certification Authority)>, ...)>, <Certificate(subject=<Name(C=AU,O=Australian Taxation Office,OU=Certification Authority,CN=ATO Root Certification Authority)>, ...)>]
        """
        return pkcs7.load_der_pkcs7_certificates(base64.standard_b64decode(self.p7))


class UnauthenticatedClient(meatie_httpx.Client):
    """myID client for unauthenticated endpoints."""

    def __init__(self):
        """Initiates HTTP client with static and dynamic headers."""
        super().__init__(
            httpx.Client(
                headers=static_headers,
                event_hooks={"request": [add_request_id, add_session_id]},
                base_url=base_url,
            )
        )

    @endpoint(
        "/termsAndConditions",
        # Unpack nested response.
        body(json=lambda response: response.json()["termsAndConditions"]),
    )
    def get_terms_and_conditions(self) -> TermsAndConditions:
        """Returns terms and conditions unpacked from response body."""

    @endpoint("/poi", method="POST")
    def initiate_proof_of_identity_process(
        self,
        # Transform version into JSON body.
        version: Annotated[
            str, api_ref("body", fmt=lambda version: {"acceptedVersion": version})
        ],
    ) -> ProofOfIdentityProcess:
        """Returns proof of identity process details.

        `version` specifies accepted terms and conditions version.

        Reference `processId` field in subsequent steps.
        """

    @endpoint("/poi/{process_id}/documents/emails", method="POST")
    def initiate_email_verification_task(
        self,
        process_id: str,
        # Transform email into JSON body.
        email: Annotated[
            str, api_ref("body", fmt=lambda email: {"emailAddress": email})
        ],
    ) -> EmailVerificationTask:
        """Returns email verification task details for `email`.

        Reference `id` field in subsequent steps.
        """

    @endpoint(
        "/poi/{process_id}/tasks/{task_id}/emailVerificationResponse",
        method="POST",
    )
    def complete_email_verification_task(
        self, process_id: str, task_id: int, body: EmailVerificationBody
    ) -> EmailVerificationResult:
        """Submits verification code and returns email verification result details.

        Verification is successful if `verificationCodeResult` field is `"Verified"`.
        """


class AssuranceClient(meatie_httpx.Client):
    """myID client for proof of identity assurance endpoints.

    Authenticated with token in `EmailVerificationResult`'s `poiAssuranceToken` field.
    """

    def __init__(self, token: str):
        """Initiates HTTP client with JWT bearer token."""
        super().__init__(
            httpx.Client(
                headers=static_headers
                | {
                    "Authorization": f"Bearer {token}",
                    # session id matches jwt's id
                    "X-AuditSessionId": (
                        jwt.decode(token, options={"verify_signature": False})["jti"]
                    ),
                },
                # Automatically follow /credentials/tasks/{task_id} redirect.
                follow_redirects=True,
                event_hooks={"request": [add_request_id]},
                base_url=base_url,
            )
        )

    @endpoint("/credentials/x509s", method="POST")
    def initiate_certificate_signing_task(
        self, body: CertificateSigningRequest
    ) -> CertificateSigningTask:
        """Submits certificate signing request.

        Returns certificate signing task details (reference `id` field in subsequent
        steps.)
        """

    @endpoint("/credentials/tasks/{task_id}")
    def get_signed_certificate(self, task_id: int) -> CertificateResponse:
        """Returns signed certificate response.

        follow_redirects=True allows redirect to /credentials/x509s/issueStatements/...
        """


class Identity:
    """Represents an identity at the core of a Digital ID.

    Creating an `Identity` generates a private key:

    >>> id = Identity()
    >>> id.key
    <cryptography.hazmat...rsa.RSAPrivateKey object at 0x...>

    Export the private key to a file (encrypted with a password):

    >>> with open("identity.pem", "wb") as file:
    ...     file.write(id.export_key(b"secret password"))
    1766

    Instantiate an identity from an exported key:

    >>> with open("identity.pem", "rb") as file:
    ...     id_2 = Identity.from_exported_key(file.read(), b"secret password")
    >>> assert id.key.public_key() == id_2.key.public_key()
    """

    def __init__(self, key: Optional[RSAPrivateKey] = None):
        """Generates or sets identity's private key."""
        if key is None:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.key
        else:
            self.key = key

    def export_key(self, password: bytes) -> bytes:
        """Returns identity's PEM-encoded private key, encrypted using password."""
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )

    @staticmethod
    def from_exported_key(encrypted: bytes, password: bytes) -> "Identity":
        """Returns identity instantiated from exported key encrypted using password."""
        key = serialization.load_pem_private_key(encrypted, password)
        assert isinstance(key, RSAPrivateKey)
        return Identity(key)

    def create_csr(self) -> CertificateSigningRequest:
        """Returns certificate signing request signed by identity's key.

        >>> id = Identity()
        >>> id.create_csr()
        CertificateSigningRequest(p10='MIIC...')
        """
        # http://pki.ato.gov.au/policy/myGovID%20Certificate%20Policy%20-%20User.pdf
        # 3.2.1 Method to prove possession of private key
        csr = (
            x509.CertificateSigningRequestBuilder()
            # 7.1.4 Name forms
            # The Subject Name component is based on the Subscriber’s POI ID and generated UUID and
            # defined as {CN = <POI ID>, dnQualifier = <UUID>, O = mygovid.gov.au, C = AU}.
            .subject_name(
                x509.Name(
                    [
                        # It appears myID devs took "CN = <POI ID>" too literally...
                        x509.NameAttribute(NameOID.COMMON_NAME, "poi id"),
                        x509.NameAttribute(NameOID.DN_QUALIFIER, str(uuid4())),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mygovid.gov.au"),
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
                    ]
                )
            )
            .add_extension(
                # https://oidref.com/1.2.36.1.333.1 says this OID should identify ABN.
                extval=x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.2.36.1.333.1"), b"\x16\x0emygovid.gov.au"
                ),
                critical=False,
            )
            .sign(self.key, hashes.SHA512())
        )
        return CertificateSigningRequest(
            p10=base64.standard_b64encode(
                csr.public_bytes(serialization.Encoding.DER)
            ).decode()
        )

    def create_authorization_grant(
        self, email: str, certificate: x509.Certificate
    ) -> str:
        """Returns authorization grant as JWT assertion signed with identity's key.

        Requires identity's `email` and `certificate` issued to identity.

        See RFC 7523: https://www.rfc-editor.org/rfc/rfc7523#section-2.1

        >>> identity = Identity()
        >>> certificate_response = CertificateResponse(id=0, p7="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", p10="...", credentialToken="...", links=[{"...": "..."}])
        >>> certificate = certificate_response.decode_certificate_chain()[0]
        >>> identity.create_authorization_grant("user@domain.com", certificate)
        'eyJhb...'
        """
        return jwt.encode(
            payload={
                "jti": str(uuid4()),
                "sub": email,
                "nbf": int(time.time()),
                "exp": int(time.time()) + 3600,
                "iss": f"https://ausidapp.gov.au/{certificate.serial_number}",
                "aud": "https://myGovId.gov.au/connect/token",
            },
            key=self.key,
            algorithm="RS256",
            headers={
                # kid is certificate's SHA1 fingerprint, UPPERCASE
                "kid": certificate.fingerprint(hashes.SHA1()).hex().upper(),
                # b64 encoded DER certificate
                "x5c": [
                    base64.standard_b64encode(
                        certificate.public_bytes(serialization.Encoding.DER)
                    ).decode()
                ],
            },
        )

    def create_client_authentication(self, certificate: x509.Certificate) -> str:
        """Returns JWT assertion for client authentication signed with identity's key.

        Requires `certificate` issued to identity.

        See RFC 7523: https://www.rfc-editor.org/rfc/rfc7523#section-2.2

        >>> identity = Identity()
        >>> certificate_response = CertificateResponse(id=0, p7="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", p10="...", credentialToken="...", links=[{"...": "..."}])
        >>> certificate = certificate_response.decode_certificate_chain()[0]
        >>> identity.create_client_authentication(certificate)
        'eyJhb...'
        """
        return jwt.encode(
            payload={
                "jti": str(uuid4()),
                "sub": f"https://ausidapp.gov.au/{certificate.serial_number}",
                "nbf": int(time.time()),
                "exp": int(time.time()) + 3600,
                "iss": f"https://ausidapp.gov.au/{certificate.serial_number}",
                "aud": "https://myGovId.gov.au/connect/token",
            },
            key=self.key,
            algorithm="RS256",
            headers={
                # kid is certificate's SHA1 fingerprint, UPPERCASE
                "kid": certificate.fingerprint(hashes.SHA1()).hex().upper(),
                # b64 encoded DER certificate
                "x5c": [
                    base64.standard_b64encode(
                        certificate.public_bytes(serialization.Encoding.DER)
                    ).decode()
                ],
            },
        )
