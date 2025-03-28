package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_api_managmement_premium_sku(resource) if {
    allowed_sku_prefixes := ["Premium"]
    some prefix in allowed_sku_prefixes
    contains(resource.values.sku_name, prefix)
}

deny_azurerm_api_managmement_premium_sku contains reason if {
    resource := data.utils.resource(input, "azurerm_api_management")[_]
    not valid_azurerm_api_managmement_premium_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/azurerm_api_managmement_premium_sku: '%s' `azurerm_api_management` should have 'sku_name' set to type 'Premium': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ApiManagement/service/#migrate-api-management-services-to-premium-sku-to-support-availability-zones", [resource.address])
}