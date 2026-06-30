; Inno Setup script for TokenVault.
; Compile with the Inno Setup Compiler (ISCC.exe) on Windows, after running
; windows\build.bat to produce the PyInstaller dist\ output:
;
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" windows\installer.iss
;
; Produces dist_installer\TokenVaultSetup.exe
;
; The installer:
;   1. Requires admin rights (creating local groups + a service needs them)
;   2. Creates two local Windows groups for report-viewing permissions:
;        TokenVault_EncryptedViewers  - masked/encrypted reports only
;        TokenVault_FullViewers       - decrypted reports, full PAN gated
;   3. Installs the service exe + reporting app exe
;   4. Registers and starts TokenVaultService as a Windows service
;   5. Creates Start Menu shortcuts for the reporting app

#define MyAppName "TokenVault"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Your Company"

[Setup]
AppId={{B6B0B6C9-6E54-4E2E-9B7E-2F6B6F4B9A11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist_installer
OutputBaseFilename=TokenVaultSetup
Compression=lzma
MinVersion=10.0
; Restrict to 64-bit Windows and install into the native 64-bit Program Files.
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
SolidCompression=yes
PrivilegesRequired=admin

[Files]
Source: "..\dist\TokenVaultService\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs
Source: "..\dist\TokenVaultReporting\*"; DestDir: "{app}\reporting"; Flags: ignoreversion recursesubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\TokenVault Reporting"; Filename: "{app}\reporting\TokenVaultReporting.exe"
Name: "{group}\Uninstall TokenVault"; Filename: "{uninstallexe}"

[Run]
; --- Create local groups used for report-access RBAC (ignore error if they already exist) ---
Filename: "{sys}\net.exe"; Parameters: "localgroup TokenVault_EncryptedViewers /add /comment:""TokenVault: view masked/encrypted reports only"""; Flags: runhidden; StatusMsg: "Creating TokenVault_EncryptedViewers group..."
Filename: "{sys}\net.exe"; Parameters: "localgroup TokenVault_FullViewers /add /comment:""TokenVault: view decrypted reports"""; Flags: runhidden; StatusMsg: "Creating TokenVault_FullViewers group..."

; --- Install and start the Windows service ---
Filename: "{app}\service\TokenVaultService.exe"; Parameters: "install"; Flags: runhidden; StatusMsg: "Registering TokenVault service..."
Filename: "{app}\service\TokenVaultService.exe"; Parameters: "start"; Flags: runhidden; StatusMsg: "Starting TokenVault service..."

; --- Offer to launch the reporting app at the end ---
Filename: "{app}\reporting\TokenVaultReporting.exe"; Description: "Launch TokenVault Reporting"; Flags: postinstall nowait skipifsilent unchecked

[UninstallRun]
Filename: "{app}\service\TokenVaultService.exe"; Parameters: "stop"; Flags: runhidden
Filename: "{app}\service\TokenVaultService.exe"; Parameters: "remove"; Flags: runhidden

[Code]
procedure InitializeWizard;
begin
  // Placeholder for any pre-install checks (e.g. .NET/VC++ redistributable
  // checks) if your environment needs them.
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsAdminLoggedOn() and not IsAdmin() then
  begin
    MsgBox('This installer must be run as Administrator (it creates ' +
           'Windows local groups and registers a service).', mbError, MB_OK);
    Result := False;
  end;
end;
