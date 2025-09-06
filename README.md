# Open myID ![](wizard.png)

**Use [myID](https://www.myid.gov.au/) without a smartphone**

myID is the Australian Government's Digital ID app, used to access online government
services.

Reviews on Apple's [App Store](https://apps.apple.com/au/app/myid-australian-government/id1397699449?see-all=reviews)
and [Google Play](https://play.google.com/store/apps/details?id=au.gov.ato.mygovid.droid)
express the Australian public's opinion of the official myID app:

- "Always a pain to use but tonight 45 minutes wasted."
- "Awful, and right before Christmas!"
- "This app is absolute garbage."
- "How is this still so bad?"
- "This app is useless!"
- "Endless circles."
- "Impossible."
- "Terrible."
- "Trash."
- "NO"

## Getting started

Open myID is a Python application that can run on any computer. It allows you authenticate
to government services with myID if

- your smartphone is lost or stolen
- you only have a wired connection (no Wi-Fi or cellular)
- you have issues with the official app

Open myID works best in conjunction with the official app:

- install myID
- create an identity
- verify your identity to highest security level required

If you're familiar with Python and the command line, you can run Open myID with [uv](https://docs.astral.sh/uv/):

    uvx --from git+https://github.com/eidorb/openmyid openmyid

Or launch it in a browser instead of the command line:

    uvx --from git+https://github.com/eidorb/openmyid textual serve openmyid

## Demo

<video src="https://github.com/user-attachments/assets/7696db66-9e9b-4337-8c7e-7e692b2ee706" controls></video>

## Development

Clone this repository if you want to tweak or extend Open myID.

- `myid.py` is a module implementing classes and models used to interact with the myID API
- `openmyid.py` is a [Textual](https://textual.textualize.io) application

## Security

- Your digital identity is backed by an RSA public/private key pair
- `openmyid.py` stores your identity in an SQLite database (`openmyid.py`), encrypted using a password
- It is your responsibility to keep your digital identity safe, and use a strong password
