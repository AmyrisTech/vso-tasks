#
#   Write-S3Directory
#
function Write-S3Directory {
param
(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$Bucket,
    [string]$KeyPrefix = "/",
    [string]$Region = $env:AWS_REGION,
    [string]$AccessKey = $env:AWS_ACCESS_KEY,
    [string]$SecretKey = $env:AWS_SECRET_KEY
)
    $Directory = [System.IO.Path]::GetFullPath($Directory)
    $files = get-childitem $Directory -Recurse -File
    $files | %{
        $File = $_.FullName
        $directoryName = [System.IO.Path]::GetDirectoryName($_.FullName) 
        $relativePath = $KeyPrefix + "\" + $directoryName.Substring($Directory.Length)
        $relativePath = [Regex]::Replace($relativePath, "(\\|/)+", "/")
        Write-S3File -Region $Region -Bucket $Bucket -File $File -KeyPrefix $relativePath -AccessKey $AccessKey -SecretKey $SecretKey
    }
}

#
#   Write-S3File
#
function Write-S3File {
param
(
    [Parameter(Mandatory=$true)][string]$Region,
    [Parameter(Mandatory=$true)][string]$Bucket,
    [Parameter(Mandatory=$true)][string]$File,
    [string]$KeyPrefix = "/",
    [string]$AccessKey = $env:AWS_ACCESS_KEY,
    [string]$SecretKey = $env:AWS_SECRET_ACCESS_KEY,
    [string]$ContentType
)
    $service = "s3"
    $body = [System.IO.File]::ReadAllBytes($File)
    $date = (Get-Date).ToUniversalTime()
    $fileName = [System.IO.Path]::GetFileName($File)
    
    # Cleanup Target Parg
    $KeyPrefix = $KeyPrefix.Trim('/')
    if ($KeyPrefix.Length -gt 0) {
        $KeyPrefix = $KeyPrefix + "/"
    }
    
    # Get ContentType if needed
    if ($ContentType -eq "") {
        $ContentType = Get-MimeType ([System.IO.Path]::getExtension($File))
    }
  
    # Create request and sign it  
    $request = @{
        Host = "${Bucket}.${service}.amazonaws.com"
        Method = "PUT"
        Uri = "/${KeyPrefix}${fileName}"
        QueryString = ""
        Date = $date
        Headers = @{
            "Host" = "${Bucket}.${service}.amazonaws.com"
            "X-Amz-Date" = $date.ToString("yyyyMMddTHHmmssZ")
            "Content-Type" = $ContentType
            "Content-Length" = $body.Length.ToString()
        }
        Payload = $body
    }
    Sign-Request -Request $request -Region $Region -Service $Service -AccessKey $AccessKey -SecretKey $SecretKey
    
    # Upload file
    Write-Host "$KeyPrefix$fileName (Content-Type=$ContentType, Content-Length=$($body.Length))"
    $url = "${Bucket}.s3.amazonaws.com/${KeyPrefix}${fileName}"
    $request.Headers.Remove("Content-Length")
    $request.Headers.Remove("Content-Type")
    $response = Invoke-WebRequest -uri $url -Method $request.Method -Headers $request.Headers -Body $request.Payload -ContentType $ContentType -UseBasicParsing
}

#
#
#
function Sign-Request {
param
(
    [Parameter(Mandatory=$true)]$Request,
    [Parameter(Mandatory=$true)][string]$Region,
    [Parameter(Mandatory=$true)][string]$Service,
    [Parameter(Mandatory=$true)][string]$AccessKey,
    [Parameter(Mandatory=$true)][string]$SecretKey
)
    $date = $request.Date
    
    # PayloadHash
    $payloadHash = Get-SHA256 -Data $request.Payload
    $payloadHashHex = ([BitConverter]::ToString($payloadHash).Replace("-", "")).ToLower()  
    
    $request.Headers["X-Amz-Date"] = $request.Date.ToString("yyyyMMddTHHmmssZ")
    $request.Headers["X-Amz-Content-SHA256"] = $payloadHashHex
    
    $signedHeaders = ($request.Headers.Keys | sort | %{ $_.ToLower()}) -Join ";"
    write-Verbose "SIGNED HEADERS: $signedHeaders`n"
    
    $canonicalRequest = $request.Method + "`n"  +
        $request.Uri + "`n" +
        $request.QueryString + "`n" +
        (($request.Headers.Keys | sort | %{ $_.ToLower() + ":" + $request.Headers[$_].Trim() }) -Join "`n") + "`n" + 
        "`n" +
        $signedHeaders + "`n" +
        $payloadHashHex
    write-Verbose "CANONICAL REQUEST:`n$canonicalRequest`n"
    
    $canonicalRequestBytes = Get-Sha256 $canonicalRequest
    write-Verbose "CANONICAL REQUEST BYTES:`n$canonicalRequestBytes`n"  
    
    $canonicalRequestHash = ([BitConverter]::ToString($canonicalRequestBytes).Replace("-", "")).ToLower()  
    write-Verbose "CANONICAL REQUEST HASH: $canonicalRequestHash`n" 
    
    $s2s = Get-String2Sign -RequestHash $canonicalRequestHash -Date $Date -Region $Region -Service $Service
    write-Verbose "STRING TO SIGN:`n$s2s`n"
    
    $signatureKey = Get-SignatureKey -Key $SecretKey -Region $Region -Service $Service -Date $Date
    write-Verbose "SIGNATURE KEY: $([BitConverter]::ToString($signatureKey))"
    
    $signature = Get-HmacSHA256 -Data $s2s -key $signatureKey
    $signatureHex = ([BitConverter]::ToString($signature).Replace("-", "")).ToLower()  
    write-Verbose "SIGNATURE: $signatureHex`n" 
    
    $authorization =
        "AWS4-HMAC-SHA256 Credential=" +
        "${AccessKey}/$($date.ToString("yyyyMMdd"))/${Region}/${Service}/aws4_request" +
        ", SignedHeaders=${signedHeaders}" +
        ", Signature=${signatureHex}"

    $request.Headers["Authorization"] = $authorization
    write-Verbose "AUTHORIZATION: $authorization`n"    
}

#
#
#
function Get-MimeType()
{
param($extension = $null)
    $mimeType = $null
    if ($null -ne $extension) {
        $drive = Get-PSDrive HKCR -ErrorAction SilentlyContinue
        if ($null -eq $drive) {
            $drive = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        }
        $mimeType = (Get-ItemProperty HKCR:$extension)."Content Type"
    }
    $mimeType
}

function Get-HmacSHA256($Data, $Key) {
    if ($Data.GetType().Name -eq "String") {
        $Data = [System.Text.Encoding]::UTF8.GetBytes($Data)
    }
    $a = [System.Security.Cryptography.KeyedHashAlgorithm]::Create("HmacSHA256");
    if ($Key.GetType().Name -eq "String") {
        $Key = [System.Text.Encoding]::UTF8.GetBytes($Key)
    }
    $a.Key = $Key
    return $a.ComputeHash($data);
}

function Get-SHA256($Data) {
    if ($Data.GetType().Name -eq "String") {
        $Data = [System.Text.Encoding]::UTF8.GetBytes($Data)
    }
    $a = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256");
    return $a.ComputeHash($data);
}

function Get-SignatureKey($Key, [DateTime]$Date, $Region, $Service) {
    $signing = [System.Text.Encoding]::UTF8.GetBytes(("AWS4" + $Key).ToCharArray()) 
    $signing = get-HmacSHA256 ($Date.ToString("yyyyMMdd")) $signing
    $signing =  get-HmacSHA256 $Region $signing
    $signing =  get-HmacSHA256 $Service $signing
    $signing =  get-HmacSHA256 "aws4_request" $signing
    return $signing    
}

function Get-String2Sign([string]$RequestHash, [DateTime]$Date, [string]$Region, [string]$Service) {
    $s2s =
        "AWS4-HMAC-SHA256" + "`n" +
        "$($date.ToString("yyyyMMddTHHmmssZ"))" + "`n" +
        "$($date.ToString("yyyyMMdd"))/${Region}/${Service}/aws4_request" + "`n" +
        "$RequestHash"
    return $s2s
}
