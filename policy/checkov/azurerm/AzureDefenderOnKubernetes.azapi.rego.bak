package checkov

import rego.v1

valid_azapi_security_center_subscription_pricing_configuration(resource) if {
    resource.type != "Microsoft.Security/pricings/2023-01-01"
}

valid_azapi_security_center_subscription_pricing_configuration(resource) if {
    resource.properties.pricingTier == "Standard"
}

deny_CKV_AZURE_85_azapi contains reason if {
    resource_change := input.resource_changes[_]
    resource_change.type == "azapi_resource"
    resource := resource_change.changes.after
    not valid_azapi_security_center_subscription_pricing_configuration(resource)

    reason := sprintf("checkov/CKV_AZURE_85: Ensure that Azure Defender is set to On for Kubernetes. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnKubernetes.py")
}
