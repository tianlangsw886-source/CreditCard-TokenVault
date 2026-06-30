# Admin helper for managing TokenVault report-access groups.
# Run from an elevated PowerShell prompt.
#
# Examples:
#   .\manage_access.ps1 -Action AddEncryptedViewer -User "jsmith"
#   .\manage_access.ps1 -Action AddFullViewer -User "asingh"
#   .\manage_access.ps1 -Action Remove -User "jsmith" -Group TokenVault_EncryptedViewers
#   .\manage_access.ps1 -Action List

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("AddEncryptedViewer", "AddFullViewer", "Remove", "List")]
    [string]$Action,

    [string]$User,
    [string]$Group
)

$EncryptedGroup = "TokenVault_EncryptedViewers"
$FullGroup = "TokenVault_FullViewers"

function Require-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }
}

Require-Admin

switch ($Action) {
    "AddEncryptedViewer" {
        if (-not $User) { Write-Error "-User is required"; exit 1 }
        Add-LocalGroupMember -Group $EncryptedGroup -Member $User
        Write-Host "Added '$User' to $EncryptedGroup (masked/encrypted reports only)."
    }
    "AddFullViewer" {
        if (-not $User) { Write-Error "-User is required"; exit 1 }
        Add-LocalGroupMember -Group $FullGroup -Member $User
        Write-Host "Added '$User' to $FullGroup (decrypted reports allowed)."
        Write-Host "NOTE: full PAN export still requires an explicit reason and is audit-logged."
    }
    "Remove" {
        if (-not $User -or -not $Group) { Write-Error "-User and -Group are required"; exit 1 }
        Remove-LocalGroupMember -Group $Group -Member $User
        Write-Host "Removed '$User' from $Group."
    }
    "List" {
        foreach ($g in @($EncryptedGroup, $FullGroup)) {
            Write-Host "`n=== $g ==="
            try {
                Get-LocalGroupMember -Group $g | Select-Object Name, ObjectClass | Format-Table
            } catch {
                Write-Host "(group not found -- has the installer been run?)"
            }
        }
    }
}
