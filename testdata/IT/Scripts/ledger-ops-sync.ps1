param(
    [string]$Destination = '\\fileserver\archives'
)

Write-Host 'Starting archive synchronisation'
$source = Join-Path $PSScriptRoot '..\..\Operations\Backups'
$manifest = Join-Path $source 'ledger_ops_sync.ps1-manifest.json'
if (Test-Path $Destination) {
    robocopy $source $Destination *.zip /Z /FFT /XO
}
Write-Host ('Manifest: ' + $manifest)
Write-Host 'Sync complete'
