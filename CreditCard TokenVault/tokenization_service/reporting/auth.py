"""
Role-based access control backed by Windows local group membership.

Two roles:
  - ENCRYPTED_VIEWER  (Windows group: TokenVault_EncryptedViewers)
        May import and view reports where card data stays masked/encrypted.
        Never sees a decrypted PAN.
  - FULL_VIEWER       (Windows group: TokenVault_FullViewers)
        May import and view decrypted reports (last4 + brand always;
        full PAN only when explicitly requested, see report_generator.py).

A user can be in neither (no access) or, in principle, both — if both,
the higher-privilege FULL_VIEWER role applies, but every elevated action
is still audit-logged with the resolved Windows identity.

Group membership is checked live against the OS on every privileged
action (not cached at login) so a group change takes effect immediately
without requiring users to log out.

PRODUCTION NOTE: For a domain environment, swap the local-group lookup
below for an AD/LDAP group lookup (e.g. via `pywin32`'s win32security
token groups, or `ldap3` against your domain controller) so the same
group names can be managed centrally via Group Policy / AD.
"""
import enum
import getpass
import logging
import socket

logger = logging.getLogger("tokenization_reporting.auth")

ENCRYPTED_GROUP = "TokenVault_EncryptedViewers"
FULL_GROUP = "TokenVault_FullViewers"

try:
    import win32net
    import win32api

    _WINDOWS_AVAILABLE = True
except ImportError:
    _WINDOWS_AVAILABLE = False


class Role(enum.Enum):
    NONE = "none"
    ENCRYPTED_VIEWER = "encrypted_viewer"
    FULL_VIEWER = "full_viewer"


def current_windows_user() -> str:
    if _WINDOWS_AVAILABLE:
        return win32api.GetUserName()
    return getpass.getuser()  # dev/non-Windows fallback


def _local_groups_for_user(username: str) -> set:
    """
    Returns the set of local group names the given local user belongs to,
    using the Windows NetUserGetLocalGroups API. Requires running on
    Windows with pywin32 installed.
    """
    if not _WINDOWS_AVAILABLE:
        raise RuntimeError(
            "Windows group lookup requires pywin32 and must run on Windows. "
            "Use ROLE_OVERRIDE_FOR_DEV for local testing on other platforms."
        )
    groups = win32net.NetUserGetLocalGroups(socket.gethostname(), username)
    return set(groups)


# For local/dev/testing on non-Windows machines only. Never set this in
# a real deployment — production must resolve roles from actual Windows
# group membership.
ROLE_OVERRIDE_FOR_DEV = None  # e.g. Role.FULL_VIEWER


def resolve_role(username: str = None) -> Role:
    if ROLE_OVERRIDE_FOR_DEV is not None:
        logger.warning(
            "ROLE_OVERRIDE_FOR_DEV is set (%s) — this must never be enabled "
            "in production.",
            ROLE_OVERRIDE_FOR_DEV,
        )
        return ROLE_OVERRIDE_FOR_DEV

    username = username or current_windows_user()
    groups = _local_groups_for_user(username)

    if FULL_GROUP in groups:
        role = Role.FULL_VIEWER
    elif ENCRYPTED_GROUP in groups:
        role = Role.ENCRYPTED_VIEWER
    else:
        role = Role.NONE

    logger.info("Resolved role for user '%s': %s (groups: %s)", username, role.value, groups)
    return role


def require_role(minimum: Role, username: str = None) -> Role:
    """Raises PermissionError if the resolved role doesn't meet `minimum`."""
    order = [Role.NONE, Role.ENCRYPTED_VIEWER, Role.FULL_VIEWER]
    role = resolve_role(username)
    if order.index(role) < order.index(minimum):
        raise PermissionError(
            f"User '{username or current_windows_user()}' has role "
            f"'{role.value}', which does not meet the required minimum "
            f"'{minimum.value}'."
        )
    return role
