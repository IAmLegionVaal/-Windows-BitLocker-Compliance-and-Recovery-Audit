# Windows BitLocker Compliance and Recovery Audit

A read-only PowerShell toolkit for assessing BitLocker protection, TPM readiness, encryption state, key-protector coverage, and recovery-key escrow evidence.

## Features

- Fixed, operating-system, and removable volume inventory
- Encryption method, percentage, lock state, and protection state
- Key-protector type and count without exposing recovery passwords
- TPM presence, readiness, ownership, and restart requirements
- Secure Boot and Windows edition context
- Recovery-password protector presence checks
- Optional Microsoft Entra ID and Active Directory escrow indicators where available
- BitLocker operational event collection
- CSV, JSON, HTML, and text outputs

## Usage

Run from an elevated PowerShell console:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\src\Get-BitLockerCompliance.ps1
```

```powershell
.\src\Get-BitLockerCompliance.ps1 -OutputPath C:\Temp\BitLockerAudit -Hours 168
```

## Safety

The toolkit does not enable or disable BitLocker, decrypt drives, suspend protection, rotate keys, expose recovery passwords, or change TPM configuration.

## Interpretation

A recovery-password protector on a drive does not by itself prove that the key is safely escrowed. Escrow findings should be confirmed against the organisation's approved management platform.

## Validation

Test on encrypted and unencrypted lab devices, a device with suspended protection, and a device without TPM support.

## Author

Dewald Pretorius — L2 IT Support Engineer
