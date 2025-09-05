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

Copyright (C) 2025  Brodie Blackburn

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import sqlite3
from typing import Optional

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
    CredentialClient,
    DateOfBirth,
    EmailVerificationBody,
    Identity,
    PersonalDetailsBody,
    TermsAndConditions,
    UnauthenticatedClient,
)


class IdentityStore:
    """Manage myID digital identity persistence."""

    def __init__(self, database: str):
        """Opens connection to database.

        Creates table `identity` if it doesn't already exist.

        `identity` maps email address to Identity (PKCS#12 serialized export).
        """
        self.connection = sqlite3.connect(database, autocommit=True)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS identity (
                email TEXT PRIMARY KEY,
                p12 BLOB NOT NULL
            )
            """
        )

    def get_emails(self) -> list[str]:
        """Returns identity email addresses."""
        return [
            row[0]
            for row in self.connection.execute(
                """
                SELECT email FROM identity
                """
            )
        ]

    def get_identity(self, email: str, password: str) -> Identity:
        """Returns deserialized Identity."""
        row = self.connection.execute(
            """
            SELECT p12 FROM identity
            WHERE email = ?
            """,
            (email,),
        ).fetchone()
        p12 = row[0]
        return Identity.from_export(p12, password.encode())

    def insert(self, identity: Identity, password: str):
        """Inserts serialized identity into database."""
        email = identity.email
        p12 = identity.export(password.encode())
        self.connection.execute(
            """
            INSERT INTO identity (email, p12)
            VALUES (?, ?)
            """,
            (email, p12),
        )


class TermsOfUseScreen(Screen[Optional[bool]]):
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
                yield Button("Cancel")
                self.next_button = Button(
                    "Next >", "primary", name="next", disabled=True
                )
                yield self.next_button

    def on_checkbox_changed(self, event: Checkbox.Changed):
        """Enables next button if checkbox checked."""
        self.next_button.disabled = not event.checkbox.value

    def on_button_pressed(self, event: Button.Pressed):
        """Returns True to caller."""
        if event.button.name == "next":
            self.dismiss(True)
        else:
            self.dismiss()


class EmailAddressScreen(Screen[Optional[str]]):
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
                yield Button("Cancel")
                self.next_button = Button(
                    "Next >", "primary", name="next", disabled=True
                )
                yield self.next_button

    def on_input_changed(self, event: Input.Changed):
        """Enables next button when input not empty."""
        self.next_button.disabled = not event.input.value

    def on_input_submitted(self, event: Input.Submitted):
        self.next_button.press()

    def on_button_pressed(self, event: Button.Pressed):
        """Returns email address to caller."""
        if event.button.name == "next":
            self.dismiss(self.input.value)
        else:
            self.dismiss()


class EmailVerificationScreen(Screen[Optional[str]]):
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
                yield Button("Cancel")
                self.next_button = Button(
                    "Next >", "primary", name="next", disabled=True
                )
                yield self.next_button

    def on_input_changed(self, event: Input.Changed):
        """Enables next button when input not empty."""
        self.next_button.disabled = not event.input.value

    def on_input_submitted(self, event: Input.Submitted):
        self.next_button.press()

    def on_button_pressed(self, event: Button.Pressed):
        """Returns verification code to caller."""
        self.dismiss(self.input.value)


class PasswordScreen(Screen[Optional[str]]):
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
                yield Button("Cancel")
                self.next_button = Button(
                    "Next >", "primary", name="next", disabled=True
                )
                yield self.next_button

    def on_input_changed(self, event: Input.Changed):
        """Disables finish button if password empty or don't match."""
        self.next_button.disabled = (
            not event.input.value
            or self.password_input.value != self.confirm_password_input.value
        )

    def on_input_submitted(self, event: Input.Submitted):
        self.next_button.press()

    def on_button_pressed(self, event: Button.Pressed):
        """Returns password to caller."""
        if event.button.name == "next":
            self.dismiss(self.password_input.value)
        else:
            self.dismiss()


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

    def __init__(self):
        super().__init__()
        self.app: OpenMyid98

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
                emails = self.app.identity_store.get_emails()
                self.identity_select = Select.from_values(
                    emails,
                    prompt="Select identity",
                    allow_blank=not bool(emails),
                )
                yield self.identity_select
                yield Input(placeholder="Password", password=True)
                self.sign_in_button = Button("Sign In", "primary", disabled=True)
                yield self.sign_in_button
                yield Static()
                yield Button(
                    "Create New Identity",
                    "success",
                    action="screen.create_new_identity",
                )
                yield Button("Quit", variant="error", action="app.quit")

    def on_input_changed(self, event: Input.Changed):
        """Enables sign in button when password not empty."""
        self.sign_in_button.disabled = (
            not event.input.value and self.identity_select.is_blank()
        )

    @work
    async def action_create_new_identity(self):
        """Creates new identity through a series of Screens."""
        self.loading = True
        async with UnauthenticatedClient() as client:
            terms_and_conditions = await client.get_terms_and_conditions()
            if not await self.app.push_screen_wait(
                TermsOfUseScreen(terms_and_conditions)
            ):
                self.loading = False
                return
            proof_of_identity_process = await client.initiate_proof_of_identity_process(
                terms_and_conditions.version
            )
            email = await self.app.push_screen_wait(EmailAddressScreen())
            if email is None:
                self.loading = False
                return
            email_verification_task = await client.initiate_email_verification_task(
                proof_of_identity_process.processId, email
            )
            verification_code = await self.app.push_screen_wait(
                EmailVerificationScreen(email)
            )
            if verification_code is None:
                self.loading = False
                return
            email_verification_result = await client.complete_email_verification_task(
                proof_of_identity_process.processId,
                email_verification_task.id,
                EmailVerificationBody(email, verification_code),
            )

        identity = Identity(email)

        async with AssuranceClient(
            email_verification_result.poiAssuranceToken
        ) as client:
            certificate_signing_task = await client.initiate_certificate_signing_task(
                identity.create_certificate_signing_request(
                    proof_of_identity_process.processId
                )
            )
            await asyncio.sleep(certificate_signing_task.eta * 1.5)
            certificate_response = await client.get_signed_certificate(
                certificate_signing_task.id
            )

        identity.process_certificate_response(certificate_response)

        async with CredentialClient(certificate_response.credentialToken) as client:
            personal_details_body = await self.app.push_screen_wait(
                PersonalDetailsScreen()
            )
            if personal_details_body is None:
                self.loading = False
                return
            await client.post_personal_details(
                proof_of_identity_process.processId, personal_details_body
            )

        password = await self.app.push_screen_wait(PasswordScreen())
        if password is None:
            self.loading = False
            return
        self.app.identity_store.insert(identity, password)

        # Update and select new identity.
        self.identity_select.set_options(
            [(email, email) for email in self.app.identity_store.get_emails()]
        )
        self.identity_select.value = identity.email

        await self.app.push_screen_wait(CompleteScreen())
        self.loading = False


class OpenMyid98(App):
    """A myID Textual app."""

    def __init__(self, identity_store: IdentityStore):
        super().__init__()
        self.identity_store = identity_store

    def on_mount(self):
        self.theme = "textual-light"
        self.push_screen(InitialScreen())


if __name__ == "__main__":
    identity_store = IdentityStore("openmyid.db")
    app = OpenMyid98(identity_store)
    app.run()
    identity_store.connection.close()
