@description('Optional. Name of the Attestation provider. Must be between 3 and 24 characters in length and use numbers and lower-case letters only.')
param attestationProviderName string = uniqueString(resourceGroup().name)

@description('Optional. Location for all resources.')
param location string = resourceGroup().location

resource attestationProvider 'Microsoft.Attestation/attestationProviders@2021-06-01' = {
  name: attestationProviderName
  location: location
  properties: {}
}

output attestationName string = attestationProviderName
