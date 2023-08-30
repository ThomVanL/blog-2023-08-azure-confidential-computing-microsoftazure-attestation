#Requires -Version 7
#Requires -Modules @{ ModuleName="Az"; ModuleVersion="10.2.0" }
<#
.SYNOPSIS
    Deploys an Microsoft Azure Attestation service in the AAD model and an unsigned appraisal policy.
.DESCRIPTION
    Deploys an Microsoft Azure Attestation service in the AAD model, and an unsigned appraisal policy.
.INPUTS
    None. You cannot pipe objects to New-AzMaaAadModel.ps1.
.OUTPUTS
    None.
.EXAMPLE
    PS C:\> .\New-AzMaaAadModel.ps1
#>
$attestationResourceGroup = "tvl-remote-attestation-rg"
$attestationResourceGroupLocation = "westeurope"
$attestationProviderName = "tvlaadmaa"

if ($null -eq (Get-AzResourceGroup -Name $attestationResourceGroup -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $attestationResourceGroup -Location $attestationResourceGroupLocation
}

New-AzResourceGroupDeployment -TemplateFile "maa_aad.bicep" -ResourceGroupName $attestationResourceGroup -attestationProviderName $attestationProviderName

# We will check the trust model..
Get-AzResource -ResourceName $attestationProviderName -ExpandProperties | Format-List -Property "Properties"
# Drum roll please.. 👇     ✅
#Properties : @{trustModel=AAD; status=Ready; attestUri=https://tvlaadmaa.weu.attest.azure.net;

$policyFormat = "Text" # The policy format can be either Text or JSON Web Token (JWT).
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
};
"@

Set-AzAttestationPolicy -Name $attestationProviderName `
    -ResourceGroupName $attestationResourceGroup `
    -PolicyFormat $policyFormat `
    -Tee $teeType `
    -Policy $policy -Verbose -Debug
