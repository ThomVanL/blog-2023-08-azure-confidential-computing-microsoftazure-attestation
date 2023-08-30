# Azure Confidential Computing: Microsoft Azure Attestation

## Description

"_Remote attestation_", one of these important elements, often gets only mentioned briefly due to time constraints. However, it's a __vital cornerstone__ of confidential computing that I think deserves its own dedicated blog post. This post does just that and focusses on the Remote ATtestation Procedures (RATS) architecture, as outlined in IETF RFC 9334, and its connection to Microsoft Azure Attestation (MAA). Additionally, we explore the deployment of both the AAD and Isolated models within the Microsoft Azure Attestation service. Using PowerShell, we generate a random RSA key pair that enables us to deploy a signer certificate, allowing us to sign customized attestation policies.

The Microsoft Azure Attestation (MAA) service operates within __three distinct trust models__, each defining the authorization model for attestation providers in terms of creating and updating appraisal policies.

- Shared
- Azure AD (AAD) authorization
- Isolated

The primary __distinction__ among these modes of operation lies in the __usable operations__ within each, and whether the customer is required to create an instance of the provider.

Service Mode | Instance Creation  | Attestation | Policy Get   | Policy Set | Signed Policies| Policy Management Certificate |
:----------- | :----------------- | :---------- | :----------- | :--------- | :------------- | :---------------------------- |
Shared       | No                 | Yes         | Yes          | No         | No             | No
AAD          | Yes                | Yes         | Yes          | Yes        | Optional       | No
Isolated     | Yes                | Yes         | Yes          | Yes        | Yes            | Yes

## 🔗 Links

- [Microsoft Azure Attestation blog post](https://thomasvanlaere.com/posts/2023/08/azure-confidential-computing-microsoft-azure-attestation/)
