param(
    [Parameter(Mandatory=$true)][string]$SourcePath,
    [Parameter(Mandatory=$true)][string]$Bucket,
    [Parameter(Mandatory=$true)][string]$KeyPrefix,
    [Parameter(Mandatory=$true)][string]$Region,
    [Parameter(Mandatory=$true)][string]$AccessKey,
    [Parameter(Mandatory=$true)][string]$SecretKey
)

. "$PSScriptRoot\Write-S3Object.ps1"

if (Test-Path $SourcePath -PathType Container) {
    Write-S3Directory -Directory $SourcePath -Bucket $Bucket -KeyPrefix $KeyPrefix -Region $Region -AccessKey $AccessKey -SecretKey $SecretKey 
} elseif (Test-Path $SourcePath -PathType Leaf) {
    Write-S3File -File $SourcePath -Bucket $Bucket -KeyPrefix $KeyPrefix -Region $Region -AccessKey $AccessKey -SecretKey $SecretKey
} else  {
    throw "Source '$SourcePath' n"
}
