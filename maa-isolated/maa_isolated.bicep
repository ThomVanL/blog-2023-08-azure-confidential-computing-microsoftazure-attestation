@description('Optional. Name of the Attestation provider. Must be between 3 and 24 characters in length and use numbers and lower-case letters only.')
param attestationProviderName string = uniqueString(resourceGroup().name)

@description('Optional. Location for all resources.')
param location string = resourceGroup().location

@description('Optional. List of JSON Web Keys (JWK)')
param policySigningCertificateKeys array = []

resource attestationProvider 'Microsoft.Attestation/attestationProviders@2021-06-01' = {
  name: attestationProviderName
  location: location
  properties: {
    policySigningCertificates: {
      keys: policySigningCertificateKeys
    }

  }
}

output attestationName string = attestationProviderName
