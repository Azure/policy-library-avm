
package checkov

import rego.v1

valid_azapi_security_center_subscription_pricing(resource) if {
    resource.type != "Microsoft.Security/pricings/2023-01-01"
}

valid_azapi_security_center_subscription_pricing(resource) if {
    resource.changes.after.body.properties.pricingTier == "Standard"
}

deny_CKV_AZURE_79_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    not valid_azapi_security_center_subscription_pricing(resource)

    reason := sprintf("checkov/CKV_AZURE_79: Ensure that Azure Defender is set to On for SQL servers on machines. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnSqlServerVMS.py")
}
