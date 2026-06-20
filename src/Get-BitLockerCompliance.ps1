[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1,720)]
    [int]$Hours = 168,

    [Parameter()]
    [string]$OutputPath = (Join-Path $PWD ("BitLocker-Audit-{0:yyyyMMdd_HHmmss}" -f (Get-Date)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$ErrorLog = Join-Path $OutputPath 'command-errors.log'

function Invoke-Safe {
    param([scriptblock]$ScriptBlock,[string]$Label)
    try { & $ScriptBlock }
    catch { "[$(Get-Date -Format o)] $Label :: $($_.Exception.Message)" | Add-Content $ErrorLog; $null }
}

$os = Invoke-Safe -Label 'Operating system' -ScriptBlock { Get-CimInstance Win32_OperatingSystem }
$tpm = Invoke-Safe -Label 'TPM' -ScriptBlock { Get-Tpm }
$secureBoot = Invoke-Safe -Label 'Secure Boot' -ScriptBlock { Confirm-SecureBootUEFI }
$rawVolumes = Invoke-Safe -Label 'BitLocker volumes' -ScriptBlock { Get-BitLockerVolume }

$volumes = foreach ($volume in @($rawVolumes)) {
    $protectorTypes = @($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
    $recoveryCount = @($protectorTypes | Where-Object { $_ -eq 'RecoveryPassword' }).Count
    [pscustomobject]@{
        MountPoint = $volume.MountPoint
        VolumeType = $volume.VolumeType
        VolumeStatus = $volume.VolumeStatus
        ProtectionStatus = $volume.ProtectionStatus
        LockStatus = $volume.LockStatus
        EncryptionMethod = $volume.EncryptionMethod
        EncryptionPercentage = $volume.EncryptionPercentage
        AutoUnlockEnabled = $volume.AutoUnlockEnabled
        KeyProtectorCount = @($volume.KeyProtector).Count
        KeyProtectorTypes = ($protectorTypes -join '; ')
        RecoveryPasswordProtectorPresent = ($recoveryCount -gt 0)
        ComplianceStatus = if ($volume.VolumeType -eq 'OperatingSystem' -and $volume.ProtectionStatus -ne 'On') { 'NonCompliant' }
                           elseif ($volume.VolumeType -eq 'OperatingSystem' -and $volume.EncryptionPercentage -lt 100) { 'NonCompliant' }
                           elseif ($volume.ProtectionStatus -eq 'On') { 'Protected' }
                           else { 'Review' }
    }
}
$volumes | Export-Csv (Join-Path $OutputPath 'bitlocker-volumes.csv') -NoTypeInformation -Encoding UTF8

$manageBde = Invoke-Safe -Label 'manage-bde status' -ScriptBlock { & manage-bde.exe -status 2>&1 | Out-String }
$manageBde | Set-Content (Join-Path $OutputPath 'manage-bde-status.txt') -Encoding UTF8

$eventStart = (Get-Date).AddHours(-$Hours)
$events = Invoke-Safe -Label 'BitLocker events' -ScriptBlock {
    Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-BitLocker/BitLocker Management'; StartTime=$eventStart } -ErrorAction Stop |
        Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message
}
$events | Export-Csv (Join-Path $OutputPath 'bitlocker-events.csv') -NoTypeInformation -Encoding UTF8

$entraEscrow = Invoke-Safe -Label 'Entra escrow indicators' -ScriptBlock {
    $dsreg = (& dsregcmd.exe /status 2>&1 | Out-String)
    [pscustomobject]@{
        AzureAdJoined = if ($dsreg -match '(?m)^\s*AzureAdJoined\s*:\s*(\S+)') { $Matches[1] } else { 'Unknown' }
        DeviceId = if ($dsreg -match '(?m)^\s*DeviceId\s*:\s*(\S+)') { $Matches[1] } else { $null }
        Note = 'Join state only. Confirm recovery key escrow in the management portal.'
    }
}
$entraEscrow | Export-Csv (Join-Path $OutputPath 'entra-escrow-indicators.csv') -NoTypeInformation -Encoding UTF8

$adEscrow = Invoke-Safe -Label 'AD escrow indicators' -ScriptBlock {
    if (-not (Get-Module -ListAvailable ActiveDirectory)) { return $null }
    Import-Module ActiveDirectory -ErrorAction Stop
    $computer = Get-ADComputer -Identity $env:COMPUTERNAME -ErrorAction Stop
    $children = Get-ADObject -SearchBase $computer.DistinguishedName -LDAPFilter '(objectClass=msFVE-RecoveryInformation)' -Properties whenCreated -ErrorAction Stop
    [pscustomobject]@{
        ComputerDistinguishedName = $computer.DistinguishedName
        RecoveryObjectsFound = @($children).Count
        LatestRecoveryObjectDate = @($children | Sort-Object whenCreated -Descending | Select-Object -First 1).whenCreated
        Note = 'Counts escrow objects only. Recovery passwords are never exported.'
    }
}
$adEscrow | Export-Csv (Join-Path $OutputPath 'active-directory-escrow-indicators.csv') -NoTypeInformation -Encoding UTF8

$summary = [pscustomobject]@{
    CollectedAt = (Get-Date).ToString('o')
    ComputerName = $env:COMPUTERNAME
    WindowsCaption = $os.Caption
    WindowsVersion = $os.Version
    TpmPresent = if ($tpm) { [bool]$tpm.TpmPresent } else { $false }
    TpmReady = if ($tpm) { [bool]$tpm.TpmReady } else { $false }
    TpmOwned = if ($tpm) { [bool]$tpm.TpmOwned } else { $false }
    TpmRestartPending = if ($tpm) { [bool]$tpm.RestartPending } else { $false }
    SecureBoot = if ($null -ne $secureBoot) { [bool]$secureBoot } else { $null }
    VolumeCount = @($volumes).Count
    ProtectedVolumes = @($volumes | Where-Object ProtectionStatus -eq 'On').Count
    NonCompliantVolumes = @($volumes | Where-Object ComplianceStatus -eq 'NonCompliant').Count
    OperatingSystemRecoveryProtectorPresent = [bool](@($volumes | Where-Object { $_.VolumeType -eq 'OperatingSystem' -and $_.RecoveryPasswordProtectorPresent }).Count)
    RecentBitLockerEvents = @($events).Count
    AdRecoveryObjectsFound = if ($adEscrow) { $adEscrow.RecoveryObjectsFound } else { $null }
}
$summary | Export-Csv (Join-Path $OutputPath 'summary.csv') -NoTypeInformation -Encoding UTF8
$summary | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputPath 'summary.json') -Encoding UTF8

$style = '<style>body{font-family:Segoe UI,Arial;margin:28px;color:#172033}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d5dde7;padding:7px;text-align:left}th{background:#eaf2f8}h1,h2{color:#0b3558}</style>'
$body = @()
$body += $summary | ConvertTo-Html -Fragment -PreContent '<h2>Summary</h2>'
$body += $volumes | ConvertTo-Html -Fragment -PreContent '<h2>Volume Compliance</h2>'
$body += @($events | Select-Object -First 200) | ConvertTo-Html -Fragment -PreContent '<h2>Recent Events</h2>'
$body += '<p>Recovery passwords are intentionally excluded. Confirm escrow using approved administrative portals and procedures.</p>'
ConvertTo-Html -Title 'BitLocker Compliance Audit' -Head $style -Body $body | Set-Content (Join-Path $OutputPath 'BitLocker-Compliance.html') -Encoding UTF8

Write-Host "BitLocker compliance collection completed: $OutputPath"
