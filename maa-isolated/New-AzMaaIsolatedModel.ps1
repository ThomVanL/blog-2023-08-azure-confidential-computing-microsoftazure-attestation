#Requires -Version 7
#Requires -Modules @{ ModuleName="Az"; ModuleVersion="10.2.0" }
<#
.SYNOPSIS
    Deploys an Microsoft Azure Attestation service in the isolated model, along with a signer certificate and a signed JWT appraisal policy.
.DESCRIPTION
    Deploys an Microsoft Azure Attestation service in the isolated model, along with a signer certificate and a signed JWT appraisal policy.
.INPUTS
    None. You cannot pipe objects to New-AzMaaIsolatedModel.ps1.
.OUTPUTS
    None.
.EXAMPLE
    PS C:\> .\New-AzMaaIsolatedModel.ps1
#>
[CmdletBinding()]
param ()

function ConvertTo-Base64UrlEncodedString {
    param (
        [Parameter(Position = 0, ParameterSetName = "text")]
        [string]$Text,
        [Parameter(Position = 0, ParameterSetName = "bytes")]
        [byte[]]$Bytes
    )
    switch ($PSCmdlet.ParameterSetName) {
        'text' {
            $bytes = [System.Text.UTF8Encoding]::UTF8.GetBytes($text)
            break
        }
    }
    [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').Split("=")[0]
}

function ConvertTo-ByteArray {
    param (
        [string]$Base64UrlEncodedData
    )
    $Base64EncodedString = ConvertTo-Base64EncodedString -Base64UrlEncodedData $Base64UrlEncodedData
    return [Convert]::FromBase64String($Base64EncodedString)
}

function ConvertTo-Base64EncodedString {
    param (
        [string]$Base64UrlEncodedData
    )
    $Base64EncodedString = $Base64UrlEncodedData.Replace('-', '+').Replace('_', '/')
    switch ($Base64EncodedString.Length % 4) {
        0 { break; }
        2 { $Base64EncodedString += '=='; break; }
        3 { $Base64EncodedString += '='; break; }
    }
    return $Base64EncodedString
}

if (!(Get-AzContext)) {
    Connect-AzAccount
}


$keyFile = "key.pem"
$certFile = "certificate.pem"

# Create and export a random 4096-bit RSA key to a file
$rsa = [System.Security.Cryptography.RSA]::Create(4096)
$rsa.ExportPkcs8PrivateKeyPem() | Out-File $keyFile -Force

# Create an X509 certificate, using our RSA key file.
$certSubject = "/C=BE/ST=Antwerp/L=Antwerp/O=Thomas Van Laere, CommV./OU=IT/CN=thomasvanlaere.com"
openssl req -key $keyFile -x509 -days 365 -subj $certSubject  -out $certFile
openssl x509 -text -noout -in $certFile

$tokensToRemove = @("`n", "`r", "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")

$certData = (Get-Content -Path $certFile -Raw)
$tokensToRemove | ForEach-Object { $certData = $certData -replace $_, "" }

# Initialize an array with a JsonWebKey object
$policySigningCertificateKeys = @(
    @{
        kty = "RSA"
        use = "sig"
        x5c = @($certData)
    }
)

$attestationResourceGroup = "tvl-remote-attestation-rg"
$attestationResourceGroupLocation = "westeurope"
$attestationProviderName = "tvlisolatedmaa"
$bicepFile = "maa_isolated.bicep"

if ($null -eq (Get-AzResourceGroup -Name $attestationResourceGroup -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $attestationResourceGroup -Location $attestationResourceGroupLocation
}

New-AzResourceGroupDeployment -TemplateFile $bicepFile `
    -ResourceGroupName $attestationResourceGroup `
    -attestationProviderName $attestationProviderName `
    -policySigningCertificateKeys $policySigningCertificateKeys

# We will verify the trust model..
Get-AzResource -ResourceName $attestationProviderName -ExpandProperties | Format-List -Property "Properties"
#  Drum roll please.. 👇      ✅
# Properties : @{trustModel=Isolated; status=Ready; attestUri=https://tvlisolatedmaa.weu.attest.azure.net; publicNetworkAccess=; tpmAttestationAuthentication=}

$policyFormat = "JWT" # 👈 This has changed! The policy format can be either Text or JSON Web Token (JWT).
$teeType = "OpenEnclave" # Four types of environment are supported: SgxEnclave, OpenEnclave, CyResComponent and VBSEnclave.
$policy = @"
version= 1.1;

configurationrules
{
    => issueproperty(type="x-ms-sgx-tcbidentifier", value="10");
};
authorizationrules{
    => permit();
};

issuancerules
{
    c:[type=="x-ms-sgx-is-debuggable"] => issue(type="is-debuggable", value=c.value);
    c:[type=="x-ms-sgx-mrsigner"] => issue(type="sgx-mrsigner", value=c.value);
    c:[type=="x-ms-sgx-mrenclave"] => issue(type="sgx-mrenclave", value=c.value);
    c:[type=="x-ms-sgx-product-id"] => issue(type="product-id", value=c.value);
    c:[type=="x-ms-sgx-svn"] => issue(type="svn", value=c.value);
    c:[type=="x-ms-attestation-type"] => issue(type="tee", value=c.value);
    c:[type=="x-ms-attestation-type"] => issue(type="tee", value=c.value);
};
"@

$jwsHeader = [ordered]@{
    alg = "RS256"
    x5c = @($certData)
} | ConvertTo-Json -Compress

$jwsPayload = [ordered]@{
    AttestationPolicy = ConvertTo-Base64UrlEncodedString -Text $policy
} | ConvertTo-Json -Compress

$JwsResult = "{0}.{1}" -f (ConvertTo-Base64UrlEncodedString -Text $jwsHeader), (ConvertTo-Base64UrlEncodedString -Text $jwsPayload)
$JwsResultAsByteArr = [System.Text.UTF8Encoding]::UTF8.GetBytes($JwsResult)
$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($JwsResultAsByteArr)

$hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256;
$padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
$signedResult = $rsa.SignHash($hash, $hashAlgorithm, $padding)

$signedResultb64url = ConvertTo-Base64UrlEncodedString -Bytes $signedResult
$JwsResult += ".{0}" -f $signedResultb64url

$jwsSignatureBytes = ConvertTo-ByteArray -Base64UrlEncodedData $signedResultb64url
$rsa.VerifyHash($hash, $jwsSignatureBytes, $hashAlgorithm, $padding)
# Should return: True

Set-AzAttestationPolicy -Name $attestationProviderName `
    -ResourceGroupName $attestationResourceGroup `
    -PolicyFormat $policyFormat `
    -Tee $teeType `
    -Policy $JwsResult
