"""
Wraps the FastAPI app as a native Windows Service using pywin32, so it
starts automatically on boot and is managed via services.msc / `sc.exe`
rather than a console window staying open.

Build this into TokenVaultService.exe via PyInstaller (see windows/build.bat).
After install, register/manage with:

    TokenVaultService.exe install
    TokenVaultService.exe start
    TokenVaultService.exe stop
    TokenVaultService.exe remove

The installer (Inno Setup script) runs `install` + `start` automatically.
"""
import os
import sys
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

import uvicorn


class TokenVaultService(win32serviceutil.ServiceFramework):
    _svc_name_ = "TokenVaultService"
    _svc_display_name_ = "TokenVault Tokenization Service"
    _svc_description_ = (
        "Card tokenization API (vault-based tokenization, AES-256-GCM "
        "envelope encryption). See README for PCI compliance requirements "
        "before processing real cardholder data."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.server = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.server is not None:
            self.server.should_exit = True
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self._run_server()

    def _run_server(self):
        # main:app must be importable -- bundled alongside this script by
        # PyInstaller (see windows/tokenvault_service.spec).
        install_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        os.chdir(install_dir)

        config = uvicorn.Config(
            "main:app",
            host="127.0.0.1",
            port=int(os.environ.get("TOKENVAULT_PORT", "8000")),
            log_level="info",
        )
        self.server = uvicorn.Server(config)

        thread = threading.Thread(target=self.server.run, daemon=True)
        thread.start()

        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(TokenVaultService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(TokenVaultService)
