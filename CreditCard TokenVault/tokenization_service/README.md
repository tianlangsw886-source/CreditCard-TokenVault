# Card Tokenization Service (Reference Implementation)

A vault-based credit card tokenization service: real PANs go in, random
opaque tokens come out. The token can be safely stored and passed around
your systems; only this service (with the master key) can turn it back
into a real card number.

## ⚠️ Before you put real cardholder data anywhere near this

This code is a **reference implementation of the tokenization logic** —
the encryption, token generation, and API shape. It is **not**, by
itself, a PCI-DSS compliant system. Storing or transmitting real PANs
brings you into PCI-DSS Level 1 scope, which requires things no amount
of application code can provide on its own:

- A certified HSM or cloud KMS for the master key (never a `.env` file)
- Network segmentation isolating the cardholder data environment (CDE)
- A Qualified Security Assessor (QSA) review / formal PCI audit
- Centralized, tamper-evident audit logging
- Documented key-rotation, incident-response, and data-retention policies
- Penetration testing and vulnerability scanning on a schedule

If you're building this for a real payment flow, talk to a PCI QSA
before going further, and seriously consider whether you actually need
to touch raw PANs at all — most companies are better served by using
their payment processor's tokenization (Stripe, Braintree, Adyen, etc.)
and never touching a raw card number in their own infrastructure.

## What's in here

```
tokenization_service/
├── main.py              FastAPI app: /v1/tokenize, /v1/detokenize, /v1/tokens/{id}
├── vault/
│   ├── crypto.py         Envelope encryption (AES-256-GCM, DEK wrapped by KEK)
│   ├── tokens.py          Random Luhn-valid token generation
│   └── storage.py         SQLite vault (swap for an isolated encrypted DB in prod)
├── test_vault.py         Standalone smoke test, no server needed
└── requirements.txt
```

## How the encryption works

1. Each PAN gets its own random **Data Encryption Key (DEK)**.
2. The PAN is encrypted with the DEK (AES-256-GCM).
3. The DEK itself is encrypted ("wrapped") by a **Key Encryption Key
   (KEK)** — in production this call goes to a KMS/HSM and the KEK
   never enters application memory in plaintext for longer than the
   wrap/unwrap call.
4. The vault stores the wrapped DEK + ciphertext. Compromising the
   database alone does not yield usable PANs.

This also makes **key rotation cheap**: rotating the KEK means
re-wrapping DEKs, not re-encrypting every stored PAN.

## Running locally (demo only)

```bash
pip install -r requirements.txt

# Generate a master key (stand-in for a KMS key in this demo)
export TOKENIZATION_MASTER_KEY=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
export TOKENIZATION_API_KEYS="dev-local-key-123"

python3 test_vault.py        # library-level smoke test, no server

uvicorn main:app --reload    # start the API on http://127.0.0.1:8000
```

Example request:

```bash
curl -X POST http://127.0.0.1:8000/v1/tokenize \
  -H "x-api-key: dev-local-key-123" \
  -H "Content-Type: application/json" \
  -d '{"pan": "4111111111111111"}'
```

## Windows packaging (.exe installer) and report-access RBAC

This project now includes:

- **`windows/service_wrapper.py`** — runs the FastAPI app as a real Windows
  Service (via `pywin32`) so it starts on boot and is managed through
  `services.msc` instead of a console window.
- **`reporting_app.py`** — a Tkinter desktop app for importing a token
  list and generating reports, gated by the signed-in Windows user's
  group membership.
- **`reporting/auth.py`** — resolves role from Windows local group
  membership (or AD group, if you swap in an LDAP lookup — see comments).
- **`reporting/report_generator.py`** — builds masked or decrypted
  reports depending on role, with full-PAN export requiring an explicit
  reason and always being audit-logged.
- **`windows/installer.iss`** — Inno Setup script that creates the two
  access groups, installs both exes, and registers the Windows service.
- **`windows/manage_access.ps1`** — admin PowerShell helper to add/remove
  users from the two groups.

### The two report-access roles

| Windows group | Role | Can do |
|---|---|---|
| `TokenVault_EncryptedViewers` | Encrypted-form viewer | Import token lists, view/export reports with **masked** card data (`VISA **** **** **** 1111`). Never sees a decrypted PAN. |
| `TokenVault_FullViewers` | Full viewer | Everything above, **plus** can request decrypted reports. Full PAN inclusion is opt-in per report, requires typing a reason, and is audit-logged (who, when, how many records, why). |

A user in neither group is denied access entirely when launching the
reporting app.

> **PCI note:** PCI-DSS requirement 3.3 restricts full PAN display to a
> documented legitimate business need. Treat `TokenVault_FullViewers`
> membership and full-PAN exports as a controlled, audited exception —
> not the default way reports are viewed — and review the audit log
> (`tokenvault_audit.log`) regularly.

### Building the installer (must be done on Windows)

PyInstaller does not cross-compile, so this step has to run on an actual
Windows machine or a Windows CI runner — not in this Linux sandbox. I've
written and logic-tested everything that *can* be tested cross-platform
(the crypto, RBAC, and report logic all have passing tests in this repo);
the packaging steps below are the part that needs a real Windows box to
execute and verify.

```cmd
cd tokenization_service

REM 1. Build both exes
windows\build.bat

REM 2. Compile the installer (requires Inno Setup: https://jrsoftware.org/isinfo.php)
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" windows\installer.iss

REM Output: dist_installer\TokenVaultSetup.exe
```

Running `TokenVaultSetup.exe` (as Administrator) will:
1. Create the `TokenVault_EncryptedViewers` and `TokenVault_FullViewers` local groups
2. Install the service + reporting app under Program Files
3. Register and start `TokenVaultService`
4. Add Start Menu shortcuts

### Windows 10 64-bit: exact build steps

This is targeted/verified-by-script for Windows 10, 64-bit specifically:

1. **Install 64-bit Python 3.11+** from python.org (the regular "Windows
   installer (64-bit)" — not the Microsoft Store version, which sandboxes
   file access in ways that break PyInstaller's service-exe output and
   pywin32's service registration). Check "Add python.exe to PATH" during
   install.
2. **Install Inno Setup** (any recent 6.x) from jrsoftware.org. Inno
   Setup's own binary is 32-bit, but it correctly builds installers that
   target and install onto 64-bit Windows — that's normal, not a bug.
3. Open a plain `cmd.exe` (not as Administrator — the build itself
   doesn't need admin rights, only running the final installer does) and run:
   ```cmd
   cd tokenization_service
   windows\build.bat
   ```
   This script: verifies your Python is actually 64-bit, creates a venv,
   installs dependencies, runs the required pywin32 post-install step,
   builds both exes, and (if Inno Setup is found at its default path)
   compiles the final installer automatically. If Inno Setup is at a
   custom path, it'll tell you the manual compile command to run instead.
4. Take the resulting `dist_installer\TokenVaultSetup.exe` to the target
   Windows 10 64-bit machine and run it **as Administrator**.

If `dumpbin.exe` (from Visual Studio Build Tools) is available on your
PATH, `build.bat` will print the architecture of each built exe so you
can directly confirm `x64` rather than assuming it.



```powershell
# Run as Administrator
.\windows\manage_access.ps1 -Action AddEncryptedViewer -User "jsmith"
.\windows\manage_access.ps1 -Action AddFullViewer -User "asingh"
.\windows\manage_access.ps1 -Action List
```

### What I could and couldn't verify in this environment

- Tested: AES-256-GCM envelope encryption round-trip, token generation/Luhn
  validation, vault storage/soft-delete, role resolution logic, masked vs.
  full-PAN report generation, CSV/JSON export masking, and the importer's
  rejection of raw PANs vs. acceptance of real tokens (caught and fixed a
  real bug here — tokens are deliberately Luhn-valid, so the naive "reject
  Luhn-valid numbers" check was wrongly rejecting legitimate tokens too).
- Not tested here (needs a Windows machine): the actual PyInstaller
  build, the Inno Setup compile, real Windows-group lookups via
  `win32net`, and the Windows Service start/stop lifecycle. Do a full
  install/uninstall test on a real Windows VM before rolling this out,
  especially the service registration and group creation steps.

## Production checklist (non-exhaustive)

- [ ] Replace `LocalKEKProvider` with a real KMS/HSM client
- [ ] Replace SQLite with an isolated, encrypted-at-rest database
- [ ] Put the service behind TLS, in a network segment with no public ingress
- [ ] Replace static API keys with mTLS or OAuth2 client-credentials
- [ ] Add a separate authorization scope for `/v1/detokenize` specifically
- [ ] Add structured audit logging (who/when/why) — never log PANs
- [ ] Rate-limit and alert on `/v1/detokenize` volume anomalies
- [ ] Define and implement a data retention / purge policy
- [ ] Get a PCI-DSS QSA assessment before processing real cardholder data
