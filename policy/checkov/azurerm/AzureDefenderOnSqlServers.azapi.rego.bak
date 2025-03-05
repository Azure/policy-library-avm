package checkov

import rego.v1

valid_azapi_security_center_subscription_pricing_defender(resource) if {
    resource.type != "Microsoft.Security/pricings/2023-01-01"
}

valid_azapi_security_center_subscription_pricing_defender(resource) if {
    resource.type == "Microsoft.Security/pricings/2023-01-01"
    resource.body.properties.pricingTier == "Standard"
}

deny_CKV_AZURE_69_azapi contains reason if {
    resource := input.resource.azapi_resource[_]
    not valid_azapi_security_center_subscription_pricing_defender(resource)

    reason := sprintf("checkov/CKV_AZURE_69: Ensure that Azure Defender is set to On for Azure SQL database servers. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnSqlServers.py")
}
