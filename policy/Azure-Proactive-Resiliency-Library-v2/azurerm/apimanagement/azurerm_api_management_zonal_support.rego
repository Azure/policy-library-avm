package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_api_management_zonal_support(resource) if {
    count(resource.values.zones) >= 2
}

deny_enable_zone_redundancy_for_api_management contains reason if {
    resource := data.utils.resource(input, "azurerm_api_management")[_]
    not valid_azurerm_api_management_zonal_support(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/enable_zone_redundancy_for_api_management: '%s' `azurerm_api_management` must have a `zones` attribute that contains at least 2 zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ApiManagement/service/#enable-availability-zones-on-premium-api-management-instances", [resource.address])
}