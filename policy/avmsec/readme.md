# Azure Verified Module Security Ruleset

`avmsec`(Azure Verified Module Security Ruleset) are inspired by builtin rules come from [BridgeCrew Checkov](https://github.com/bridgecrewio/checkov/).

## Why not Checkov?

Checkov is a great tool for scanning your Terraform code for security issues. We'd like to thanks Checkov and Bridgecrew, and Palo Alto Networks for all these marvelous work!

However, we'd like to implement these policies in a way that is more tailored to Azure modules:

1. [Open-Policy-Agent policy could be used with HCP Terraform](https://developer.hashicorp.com/terraform/cloud-docs/policy-enforcement/define-policies/opa).
2. We'd like to support `azapi` provider, since now it supports [dynamic schema](https://techcommunity.microsoft.com/blog/azuretoolsblog/announcing-azapi-dynamic-properties/4121855).
3. We'd like to integrate with [Azure Proactive Resiliency Library](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/), with one unified policy solution.

According to [Checkov general policies for Azure](https://docs.prismacloud.io/en/enterprise-edition/policy-reference/azure-policies/azure-general-policies/azure-general-policies), we'd like to implement these policies:

## Azure General Policies

| Policy | AVMSEC ID | Severity |
| --- | --- | --- |
| Azure Key Vault Keys does not have expiration date | AVM_SEC_40 | HIGH |
| Azure Linux scale set does not use an SSH key | AVM_SEC_49 | HIGH |
| Azure Microsoft Defender for Cloud is set to Off for Container Registries | AVM_SEC_86 | HIGH |
| Azure Security Center Defender set to Off for Kubernetes | AVM_SEC_85 | HIGH |
| Azure SQL server send alerts to field value is not set | AVM_SEC_26 | HIGH |
| Azure SQL Server threat detection alerts are not enabled for all threat types | AVM_SEC_25 | HIGH |
| Backend of the API management system does not utilize HTTPS | AVM_SEC_215 | HIGH |
| Event Hub Namespace not using TLS 1.2 or greater | AVM_SEC_223 | HIGH |
| Linux VM Without SSH Key | AVM_SEC_178 | HIGH |
| Storage for critical data are not encrypted with Customer Managed Key | AVM_SEC_2_1 | HIGH |
| AKS Secrets Store Without Auto-Rotation | AVM_SEC_172 | MEDIUM |
| API Management Without Minimum TLS 1.2 | AVM_SEC_173 | MEDIUM |
| App Configuration Encryption Block Not Set | AVM_SEC_186 | MEDIUM |
| App Configuration Without Purge Protection Enabled | AVM_SEC_187 | MEDIUM |
| Azure ACR HTTPS not enabled for webhook | AVM_SEC_2_28 | MEDIUM |
| Azure App Services Remote debugging is enabled | AVM_SEC_72 | MEDIUM |
| Azure Application gateways listener that allow connection requests over HTTP | AVM_SEC_217 | MEDIUM |
| Azure Automation account configured with overly permissive network access | AVM_SEC_2_24 | MEDIUM |
| Azure Container Registry (ACR) Does Not Have a Quarantine Policy Enabled | AVM_SEC_166 | MEDIUM |
| Azure Container Registry (ACR) Isn't Configured to Use Signed/Trusted Images | AVM_SEC_164 | MEDIUM |
| Azure Database for MariaDB not configured with private endpoint | AVM_SEC_2_43 | MEDIUM |
| Azure Database for MySQL server not configured with private endpoint | AVM_SEC_2_44 | MEDIUM |
| Azure Microsoft Defender for Cloud set to Off for Resource Manager | AVM_SEC_234 | MEDIUM |
| Azure PostgreSQL database flexible server configured with overly permissive network access | AVM_SEC_2_26 | MEDIUM |
| Azure PostgreSQL servers not configured with private endpoint | AVM_SEC_2_42 | MEDIUM |
| Azure Service Bus Doesn't Use Customer-Managed Key Encryption | AVM_SEC_201 | MEDIUM |
| Azure Service Bus Doesn't Use Double Encryption | AVM_SEC_199 | MEDIUM |
| Azure SQL Database server not configured with private endpoint | AVM_SEC_2_45 | MEDIUM |
| Azure Storage account is not configured with private endpoint connection | AVM_SEC_2_33 | MEDIUM |
| Azure Synapse Workspace vulnerability assessment is disabled | AVM_SEC_2_46 | MEDIUM |
| MSSQL is not using the latest version of TLS encryption | AVM_SEC_52 | MEDIUM |
| MySQL is not using the latest version of TLS encryption | AVM_SEC_54 | MEDIUM |
| Unencrypted Data Lake Store accounts | AVM_SEC_105 | MEDIUM |
| Virtual Machine extensions are installed | AVM_SEC_50 | MEDIUM |
| Vulnerability Scanning not enabled for Azure Container Registry | AVM_SEC_163 | MEDIUM |
| Windows VM Without Automatic Updates | AVM_SEC_177 | MEDIUM |
| Active Directory is not used for authentication for Service Fabric | AVM_SEC_125 | LOW |
| AKS Doesn't Use the Paid SKU for its SLA | AVM_SEC_170 | LOW |
| App Configuration Not Using Standard SKU | AVM_SEC_188 | LOW |
| App services do not use Azure files | AVM_SEC_88 | LOW |
| Automatic OS image patching is disabled for Virtual Machine scale sets | AVM_SEC_95 | LOW |
| Azure App Service Instance Lacks Redundancy | AVM_SEC_212 | LOW |
| Azure App Service Not Always On | AVM_SEC_214 | LOW |
| Azure App Service Plan is Not Suitable for Production | AVM_SEC_211 | LOW |
| Azure App Service Web app authentication is off | AVM_SEC_13 | LOW |
| Azure App Service Web app does not use latest Java version | AVM_SEC_83 | LOW |
| Azure App Service Web app does not use latest PHP version | AVM_SEC_81 | LOW |
| Azure App Service Web app does not use latest Python version | AVM_SEC_82 | LOW |
| Azure App Service Web app doesn't use latest .Net framework version | AVM_SEC_80 | LOW |
| Azure App Services FTP deployment is All allowed | AVM_SEC_78 | LOW |
| Azure Application Gateway is configured with SSL policy having TLS version 1.1 or lower | AVM_SEC_218 | LOW |
| Azure Automation account variables are not encrypted | AVM_SEC_73 | LOW |
| Azure Batch account does not use key vault to encrypt data | AVM_SEC_76 | LOW |
| Azure Built-in logging for Azure function app is disabled | AVM_SEC_159 | LOW |
| Azure Client Certificates are not enforced for API management | AVM_SEC_152 | LOW |
| Azure Cognitive Search Without SLA for Search Index Queries | AVM_SEC_209 | LOW |
| Azure Cognitive Search Without SLA Index Updates | AVM_SEC_208 | LOW |
| Azure Cognitive Services does not Customer Managed Keys (CMKs) for encryption | AVM_SEC_2_22 | LOW |
| Azure Container Instance environment variable with regular value type | CK | LOW |

For now we have implemented all high severity policies, more policies are coming soon.