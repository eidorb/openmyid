"""
      ███████    ███████████  ██████████ ██████   █████    ██████   ██████ █████ █████ █████ ██████████
    ███░░░░░███ ░░███░░░░░███░░███░░░░░█░░██████ ░░███    ░░██████ ██████ ░░███ ░░███ ░░███ ░░███░░░░███
   ███     ░░███ ░███    ░███ ░███  █ ░  ░███░███ ░███     ░███░█████░███  ░░███ ███   ░███  ░███   ░░███
  ░███      ░███ ░██████████  ░██████    ░███░░███░███     ░███░░███ ░███   ░░█████    ░███  ░███    ░███
  ░███      ░███ ░███░░░░░░   ░███░░█    ░███ ░░██████     ░███ ░░░  ░███    ░░███     ░███  ░███    ░███
  ░░███     ███  ░███         ░███ ░   █ ░███  ░░█████     ░███      ░███     ░███     ░███  ░███    ███
   ░░░███████░   █████        ██████████ █████  ░░█████    █████     █████    █████    █████ ██████████
     ░░░░░░░    ░░░░░        ░░░░░░░░░░ ░░░░░    ░░░░░    ░░░░░     ░░░░░    ░░░░░    ░░░░░ ░░░░░░░░░░
-
A Textual app. Made up of various Screens, most of which are used in creating a new
identity.
"""

import asyncio
import logging

from rich_pixels import HalfcellRenderer, Pixels
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Header,
    Input,
    Link,
    Select,
    Static,
)

from myid import (
    AssuranceClient,
    CertificateResponse,
    CredentialClient,
    DateOfBirth,
    EmailVerificationBody,
    Identity,
    PersonalDetailsBody,
    TermsAndConditions,
    UnauthenticatedClient,
)

logging.basicConfig(level=logging.INFO)


class TermsOfUseScreen(Screen[bool]):
    """
    ▗▄▄▄▖▗▄▄▄▖▗▄▄▖ ▗▖  ▗▖ ▗▄▄▖     ▗▄▖ ▗▄▄▄▖    ▗▖ ▗▖ ▗▄▄▖▗▄▄▄▖
      █  ▐▌   ▐▌ ▐▌▐▛▚▞▜▌▐▌       ▐▌ ▐▌▐▌       ▐▌ ▐▌▐▌   ▐▌
      █  ▐▛▀▀▘▐▛▀▚▖▐▌  ▐▌ ▝▀▚▖    ▐▌ ▐▌▐▛▀▀▘    ▐▌ ▐▌ ▝▀▚▖▐▛▀▀▘
      █  ▐▙▄▄▖▐▌ ▐▌▐▌  ▐▌▗▄▄▞▘    ▝▚▄▞▘▐▌       ▝▚▄▞▘▗▄▄▞▘▐▙▄▄▖
    """

    TITLE = "New Identity Wizard"
    CSS = """
    Vertical {
        margin: 0 4;
    }
    Link {
        margin: 1 0;
    }
    Checkbox {
        margin: 1 0;
    }
    """

    def __init__(self, terms_and_conditions: TermsAndConditions):
        super().__init__()
        self.terms_and_conditions = terms_and_conditions

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(TermsOfUseScreen.__doc__)
        with Vertical():
            yield Static("Familiarise yourself with myID's terms of use:")
            yield Link(self.terms_and_conditions.url)
            yield Checkbox("I understand and accept the terms of use")
            with Horizontal():
                yield Button("Cancel", action="app.pop_screen")
                self.next_button = Button("Next >", "primary", disabled=True, id="next")
                yield self.next_button

    def on_checkbox_changed(self, event: Checkbox.Changed):
        """Enables next button if checkbox checked."""
        self.next_button.disabled = not event.checkbox.value

    def on_button_pressed(self, event: Button.Pressed):
        """Accepts terms and conditions."""
        if event.button.id == "next":
            self.dismiss(True)


class EmailAddressScreen(Screen[str]):
    """
    ▗▄▄▄▖▗▖  ▗▖ ▗▄▖ ▗▄▄▄▖▗▖        ▗▄▖ ▗▄▄▄ ▗▄▄▄ ▗▄▄▖ ▗▄▄▄▖ ▗▄▄▖ ▗▄▄▖
    ▐▌   ▐▛▚▞▜▌▐▌ ▐▌  █  ▐▌       ▐▌ ▐▌▐▌  █▐▌  █▐▌ ▐▌▐▌   ▐▌   ▐▌
    ▐▛▀▀▘▐▌  ▐▌▐▛▀▜▌  █  ▐▌       ▐▛▀▜▌▐▌  █▐▌  █▐▛▀▚▖▐▛▀▀▘ ▝▀▚▖ ▝▀▚▖
    ▐▙▄▄▖▐▌  ▐▌▐▌ ▐▌▗▄█▄▖▐▙▄▄▖    ▐▌ ▐▌▐▙▄▄▀▐▙▄▄▀▐▌ ▐▌▐▙▄▄▖▗▄▄▞▘▗▄▄▞▘
    """

    TITLE = "New Identity Wizard"
    CSS = """
    Vertical {
        margin: 0 4;
    }
    Input {
        width: 50;
        margin: 1 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(EmailAddressScreen.__doc__)
        with Vertical():
            yield Static(
                "Choose an email address to associate with your myID identity:"
            )
            self.input = Input(placeholder="Email address")
            yield self.input
            with Horizontal():
                yield Button("Cancel", action="app.pop_screen")
                self.next_button = Button("Next >", "primary", disabled=True, id="next")
                yield self.next_button

    def on_input_changed(self, event: Input.Changed):
        """Enables next button when input not empty."""
        self.next_button.disabled = not event.input.value

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss(self.input.value)


class EmailVerificationScreen(Screen[str]):
    """
    ▗▄▄▄▖▗▖  ▗▖ ▗▄▖ ▗▄▄▄▖▗▖       ▗▖  ▗▖▗▄▄▄▖▗▄▄▖ ▗▄▄▄▖▗▄▄▄▖▗▄▄▄▖ ▗▄▄▖ ▗▄▖▗▄▄▄▖▗▄▄▄▖ ▗▄▖ ▗▖  ▗▖
    ▐▌   ▐▛▚▞▜▌▐▌ ▐▌  █  ▐▌       ▐▌  ▐▌▐▌   ▐▌ ▐▌  █  ▐▌     █  ▐▌   ▐▌ ▐▌ █    █  ▐▌ ▐▌▐▛▚▖▐▌
    ▐▛▀▀▘▐▌  ▐▌▐▛▀▜▌  █  ▐▌       ▐▌  ▐▌▐▛▀▀▘▐▛▀▚▖  █  ▐▛▀▀▘  █  ▐▌   ▐▛▀▜▌ █    █  ▐▌ ▐▌▐▌ ▝▜▌
    ▐▙▄▄▖▐▌  ▐▌▐▌ ▐▌▗▄█▄▖▐▙▄▄▖     ▝▚▞▘ ▐▙▄▄▖▐▌ ▐▌▗▄█▄▖▐▌   ▗▄█▄▖▝▚▄▄▖▐▌ ▐▌ █  ▗▄█▄▖▝▚▄▞▘▐▌  ▐▌
    """

    TITLE = "New Identity Wizard"
    CSS = """
    Vertical {
        margin: 0 4;
    }
    Input {
        width: 50;
        margin: 1 0;
    }
    """

    def __init__(self, email: str):
        super().__init__()
        self.email = email

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(EmailVerificationScreen.__doc__)
        with Vertical():
            yield Static(f"Enter the code sent to {self.email}:")
            self.input = Input(placeholder="Verification code", type="integer")
            yield self.input
            with Horizontal():
                yield Button("Cancel", action="app.pop_screen")
                self.next_button = Button("Next >", "primary", disabled=True, id="next")
                yield self.next_button

    def on_input_changed(self, event: Input.Changed):
        """Enables next button when input not empty."""
        self.next_button.disabled = not event.input.value

    def on_button_pressed(self, event: Button.Pressed):
        """Returns verification code to caller."""
        self.dismiss(self.input.value)


class PasswordScreen(Screen[str]):
    """
    ▗▄▄▖  ▗▄▖  ▗▄▄▖ ▗▄▄▖▗▖ ▗▖ ▗▄▖ ▗▄▄▖ ▗▄▄▄
    ▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌  █
    ▐▛▀▘ ▐▛▀▜▌ ▝▀▚▖ ▝▀▚▖▐▌ ▐▌▐▌ ▐▌▐▛▀▚▖▐▌  █
    ▐▌   ▐▌ ▐▌▗▄▄▞▘▗▄▄▞▘▐▙█▟▌▝▚▄▞▘▐▌ ▐▌▐▙▄▄▀
    """

    TITLE = "New Identity Wizard"
    CSS = """
    Vertical {
        margin: 0 4;
    }
    Input {
        width: 50;
        margin: 1 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(PasswordScreen.__doc__)
        with Vertical():
            yield Static("Choose a password to protect your identity on this device:")
            self.password_input = Input(placeholder="Password", password=True)
            self.confirm_password_input = Input(
                placeholder="Confirm password", password=True
            )
            yield self.password_input
            yield self.confirm_password_input
            with Horizontal():
                yield Button("Cancel", action="app.pop_screen")
                self.finish_button = Button(
                    "Finish", "primary", disabled=True, id="finish"
                )
                yield self.finish_button

    def on_input_changed(self, event: Input.Changed):
        """Disables next button if password empty or don't match."""
        self.next_button.disabled = (
            not event.input.value
            or self.password_input.value != self.confirm_password_input.value
        )

    def on_button_pressed(self, event: Button.Pressed):
        """Returns password to caller."""
        self.dismiss(self.password_input.value)


class PersonalDetailsScreen(Screen[Optional[PersonalDetailsBody]]):
    """
    ▗▄▄▖ ▗▄▄▄▖▗▄▄▖  ▗▄▄▖ ▗▄▖ ▗▖  ▗▖ ▗▄▖ ▗▖       ▗▄▄▄ ▗▄▄▄▖▗▄▄▄▖▗▄▖ ▗▄▄▄▖▗▖    ▗▄▄▖
    ▐▌ ▐▌▐▌   ▐▌ ▐▌▐▌   ▐▌ ▐▌▐▛▚▖▐▌▐▌ ▐▌▐▌       ▐▌  █▐▌     █ ▐▌ ▐▌  █  ▐▌   ▐▌
    ▐▛▀▘ ▐▛▀▀▘▐▛▀▚▖ ▝▀▚▖▐▌ ▐▌▐▌ ▝▜▌▐▛▀▜▌▐▌       ▐▌  █▐▛▀▀▘  █ ▐▛▀▜▌  █  ▐▌    ▝▀▚▖
    ▐▌   ▐▙▄▄▖▐▌ ▐▌▗▄▄▞▘▝▚▄▞▘▐▌  ▐▌▐▌ ▐▌▐▙▄▄▖    ▐▙▄▄▀▐▙▄▄▖  █ ▐▌ ▐▌▗▄█▄▖▐▙▄▄▖▗▄▄▞▘
    """

    TITLE = "New Identity Wizard"
    CSS = """
    Vertical {
        margin: 0 4;
    }
    Horizontal {
        height: auto;
    }
    Input {
        width: 50;
        margin: 1 0;
    }
    .dob {
        width: 11;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(PersonalDetailsScreen.__doc__)
        with Vertical():
            yield Static("Enter you personal details:")
            self.given_name = Input(placeholder="Given name(s)")
            yield self.given_name
            self.family_name = Input(placeholder="Family name")
            yield self.family_name
            yield Static("Date of birth:")
            with Horizontal():
                self.dob_year = Input(
                    placeholder="YYYY", type="integer", max_length=4, classes="dob"
                )
                yield self.dob_year
                self.dob_month = Input(
                    placeholder="MM", type="integer", max_length=2, classes="dob"
                )
                yield self.dob_month
                self.dob_day = Input(
                    placeholder="DD", type="integer", max_length=2, classes="dob"
                )
                yield self.dob_day
            with Horizontal():
                yield Button("Cancel")
                self.next_button = Button(
                    "Next >", "primary", name="next", disabled=True
                )
                yield self.next_button

    def on_input_changed(self, event: Input.Changed):
        """Disables next button if any input empty."""
        self.next_button.disabled = any(
            (
                not self.given_name.value,
                not self.family_name.value,
                not self.dob_year.value,
                not self.dob_month.value,
                not self.dob_day,
            )
        )

    def on_input_submitted(self, event: Input.Submitted):
        self.next_button.press()

    def on_button_pressed(self, event: Button.Pressed):
        """Returns personal details to caller."""
        if event.button.name == "next":
            personal_details_body = PersonalDetailsBody(
                givenName=self.given_name.value,
                familyName=self.family_name.value,
                dateOfBirth=DateOfBirth(
                    int(self.dob_year.value),
                    int(self.dob_month.value),
                    int(self.dob_day.value),
                ),
            )
            self.dismiss(personal_details_body)
        else:
            self.dismiss()


class CompleteScreen(Screen[None]):
    """
     ▗▄▄▖ ▗▄▖ ▗▖  ▗▖▗▄▄▖ ▗▖   ▗▄▄▄▖▗▄▄▄▖▗▄▄▄▖
    ▐▌   ▐▌ ▐▌▐▛▚▞▜▌▐▌ ▐▌▐▌   ▐▌     █  ▐▌
    ▐▌   ▐▌ ▐▌▐▌  ▐▌▐▛▀▘ ▐▌   ▐▛▀▀▘  █  ▐▛▀▀▘
    ▝▚▄▄▖▝▚▄▞▘▐▌  ▐▌▐▌   ▐▙▄▄▖▐▙▄▄▖  █  ▐▙▄▄▖
    """

    TITLE = "New Identity Wizard"
    CSS = """
    Vertical {
        margin: 0 4;
    }
    Button {
        margin: 1 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(CompleteScreen.__doc__)
        with Vertical():
            yield Static("Your new myID identity was created and stored successfully.")
            yield Button("Finish", "primary")

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss()


class InitialScreen(Screen):
    """Sign in or create a new identity."""

    CSS = """
    #ascii-art {
        width: auto;
    }
    #wizard {
        width: 46;
        height: 29;
        padding: 0 1;
    }
    Select {
        width: 50;
        margin: 1 0;
    }
    Input {
        width: 50;
        margin: 1 0;
    }
    Button {
        width: 25;
        margin: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(__doc__.split("-")[0], id="ascii-art")
        with Horizontal():
            yield Static(
                Pixels.from_image_path(
                    "wizard.png", renderer=HalfcellRenderer(default_color="#E0E0E0")
                ),
                id="wizard",
            )
            with Vertical():
                emails = [row[0] for row in []]
                yield Select(emails, prompt="Select identity")
                yield Input(placeholder="Password", password=True)
                yield Button("Sign In", "primary")
                yield Static()
                yield Button(
                    "Create New Identity",
                    "success",
                    action="screen.create_new_identity",
                )
                yield Button("Quit", variant="error", action="app.quit")

    @work
    async def action_create_new_identity(self):
        async with UnauthenticatedClient() as client:
            terms_and_conditions = await client.get_terms_and_conditions()
            assert await self.app.push_screen_wait(
                TermsOfUseScreen(terms_and_conditions)
            )
            proof_of_identity_process = await client.initiate_proof_of_identity_process(
                terms_and_conditions.version
            )
            email = await self.app.push_screen_wait(EmailAddressScreen())
            email_verification_task = await client.initiate_email_verification_task(
                proof_of_identity_process.processId, email
            )
            verification_code = await self.app.push_screen_wait(
                EmailVerificationScreen(email)
            )
            email_verification_result = await client.complete_email_verification_task(
                proof_of_identity_process.processId,
                email_verification_task.id,
                EmailVerificationBody(email, verification_code),
            )
            # TODO: Spawn separate worker for certificate signing.
            identity = Identity()
            certificate_worker = self.request_certificate(
                identity, email_verification_result.poiAssuranceToken
            )
            password = await self.app.push_screen_wait(PasswordScreen())
            # TODO: await separate worker result, insert key and certificate into database
            await certificate_worker.wait()
            self.app.push_screen(CompleteScreen())

    @work
    async def request_certificate(
        self, identity: Identity, assurance_token: str
    ) -> CertificateResponse:
        """Returns signed certificate response for identity."""
        async with AssuranceClient(assurance_token) as client:
            certificate_signing_task = await client.initiate_certificate_signing_task(
                identity.create_csr()
            )
            await asyncio.sleep(certificate_signing_task.eta * 1.5)
            return await client.get_signed_certificate(certificate_signing_task.id)


class OpenMyid98(App):
    """A myID Textual app."""

    def __init__(self, database: str):
        super().__init__()
        self.database = database

    def on_mount(self):
        self.theme = "textual-light"
        # self.push_screen(InitialScreen())
        self.push_screen(CompleteScreen())


if __name__ == "__main__":
    app = OpenMyid98(database="openmyid.db")
    app.run()
