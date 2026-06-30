"""
Desktop reporting application.

On launch, resolves the current Windows user's role via reporting/auth.py.
  - No group membership      -> access denied, app closes.
  - TokenVault_EncryptedViewers -> can import tokens & view masked reports only.
  - TokenVault_FullViewers      -> can additionally request decrypted
                                    reports, with full-PAN export requiring
                                    an explicit reason (audit-logged).

This app talks to the local vault DB directly (not over the network) —
in a multi-machine deployment, point VAULT_DB_PATH at the same path the
API service uses, or replace the direct Vault() calls with calls to a
read-only reporting endpoint on the API service instead.
"""
import os
import sys
import logging
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault.crypto import LocalKEKProvider
from vault.storage import Vault
from reporting.auth import Role, resolve_role, current_windows_user
from reporting.importer import parse_token_csv, ImportError_
from reporting.report_generator import generate_report, rows_to_csv, rows_to_json

logging.basicConfig(
    level=logging.INFO,
    filename=os.environ.get("TOKENVAULT_AUDIT_LOG", "tokenvault_audit.log"),
)
logger = logging.getLogger("tokenization_reporting.app")


class ReportingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TokenVault Reporting")
        self.geometry("720x480")

        self.user = current_windows_user()
        try:
            self.role = resolve_role(self.user)
        except RuntimeError as e:
            messagebox.showerror("Configuration error", str(e))
            self.destroy()
            return

        if self.role == Role.NONE:
            messagebox.showerror(
                "Access denied",
                f"User '{self.user}' is not a member of "
                f"TokenVault_EncryptedViewers or TokenVault_FullViewers.\n\n"
                f"Contact your administrator to be added to one of these "
                f"Windows local groups.",
            )
            self.destroy()
            return

        self.vault = Vault(db_path=os.environ.get("VAULT_DB_PATH", "vault.db"))
        self.kek_provider = None
        if self.role == Role.FULL_VIEWER:
            try:
                self.kek_provider = LocalKEKProvider()
            except RuntimeError as e:
                messagebox.showwarning(
                    "Decryption unavailable",
                    f"Master key not configured ({e}). Full-PAN reports "
                    f"will be unavailable this session; masked reports "
                    f"still work.",
                )

        self.tokens = []
        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(
            top,
            text=f"Signed in as: {self.user}    Role: {self.role.value}",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left")

        controls = ttk.Frame(self, padding=10)
        controls.pack(fill="x")
        ttk.Button(controls, text="Import token CSV...", command=self.on_import).pack(
            side="left", padx=4
        )

        self.full_pan_var = tk.BooleanVar(value=False)
        full_pan_check = ttk.Checkbutton(
            controls,
            text="Include full PAN (requires reason, audit-logged)",
            variable=self.full_pan_var,
        )
        if self.role != Role.FULL_VIEWER:
            full_pan_check.state(["disabled"])
        full_pan_check.pack(side="left", padx=12)

        ttk.Button(controls, text="Generate report", command=self.on_generate).pack(
            side="left", padx=4
        )
        ttk.Button(controls, text="Export CSV...", command=self.on_export_csv).pack(
            side="left", padx=4
        )

        self.status_var = tk.StringVar(value="No tokens imported yet.")
        ttk.Label(self, textvariable=self.status_var, padding=(10, 0)).pack(fill="x")

        columns = ("token", "card", "brand", "status")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for col, width in zip(columns, (180, 220, 100, 80)):
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        self._last_rows = []

    def on_import(self):
        path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        try:
            self.tokens = parse_token_csv(content)
        except ImportError_ as e:
            messagebox.showerror("Import failed", str(e))
            return
        self.status_var.set(f"Imported {len(self.tokens)} token(s) from {os.path.basename(path)}.")
        logger.info("User %s imported %d tokens from %s", self.user, len(self.tokens), path)

    def on_generate(self):
        if not self.tokens:
            messagebox.showinfo("No tokens", "Import a token CSV first.")
            return

        include_full_pan = self.full_pan_var.get() and self.role == Role.FULL_VIEWER
        reason = None
        if include_full_pan:
            reason = simpledialog.askstring(
                "Reason required",
                "Full PAN export requires a business reason "
                "(this will be recorded in the audit log):",
            )
            if not reason:
                messagebox.showwarning(
                    "Cancelled", "Full PAN export cancelled — no reason provided."
                )
                return

        try:
            rows = generate_report(
                self.vault,
                self.tokens,
                kek_provider=self.kek_provider,
                include_full_pan=include_full_pan,
                reason=reason,
                username=self.user,
            )
        except PermissionError as e:
            messagebox.showerror("Permission denied", str(e))
            return
        except ValueError as e:
            messagebox.showerror("Invalid request", str(e))
            return

        self._last_rows = rows
        self._mask_in_export = not include_full_pan

        self.tree.delete(*self.tree.get_children())
        for row in rows:
            card_display = row.pan if (row.pan and include_full_pan) else f"{row.brand.upper()} ****{row.last4}"
            self.tree.insert("", "end", values=(row.token, card_display, row.brand, row.status))

        self.status_var.set(
            f"Report generated: {len(rows)} record(s)"
            + (" (full PAN included)" if include_full_pan else " (masked)")
        )

    def on_export_csv(self):
        if not self._last_rows:
            messagebox.showinfo("No report", "Generate a report first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path:
            return
        csv_text = rows_to_csv(self._last_rows, mask_pan_column=self._mask_in_export)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_text)
        logger.info("User %s exported report to %s", self.user, path)
        messagebox.showinfo("Exported", f"Report written to {path}")


if __name__ == "__main__":
    app = ReportingApp()
    app.mainloop()
