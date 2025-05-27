"""
So many clients...
- httpx.Client: HTTP client
- HttpClient: HTTP client with MyID-specific headers
- meatie_httpx.Client: Meatie base client (using httpx)
- Client: MyID client
"""

import random
from dataclasses import dataclass
from typing import Annotated

import httpx
import meatie_httpx
from meatie import api_ref, body, endpoint, private
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


class Certificate(BaseModel):
    id: int
    p7: str
    p10: str
    credentialToken: str
    links: list[dict[str, str]]


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

    @endpoint("/credentials/x509s", private)
    def post_certificate_signing_request(self, body: CertificateSigningRequest) -> Task:
        """Submit PKCS#10 formatted certificate signing request."""


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


if __name__ == "__main__":
    with Client() as myid_client:
        print(
            myid_client.post_proof_of_identity(
                ProofOfIdentityRequest(myid_client.get_terms_and_conditions().version)
            )
        )
