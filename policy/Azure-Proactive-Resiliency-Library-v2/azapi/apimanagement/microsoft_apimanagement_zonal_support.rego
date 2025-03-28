package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_enable_zone_redundancy_for_api_management(resource) if {
    count(resource.values.body.zones) >= 2
}


deny_azapi_azapi_enable_zone_redundancy_for_api_management contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ApiManagement/service")
    not valid_azapi_enable_zone_redundancy_for_api_management(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/azapi_enable_zone_redundancy_for_api_management: '%s' `azapi_resource` must be configured to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ApiManagement/service/#enable-availability-zones-on-premium-api-management-instances", [resource.address])
}