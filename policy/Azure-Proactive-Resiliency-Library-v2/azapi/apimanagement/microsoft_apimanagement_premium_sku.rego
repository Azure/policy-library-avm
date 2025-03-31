package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_api_management_services_are_premium_sku(resource) if {
    resource.values.body.sku.name == "Premium"
}

deny_api_management_services_are_premium_sku contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ApiManagement/service")
    not valid_azapi_api_management_services_are_premium_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/api_management_services_are_premium_sku: '%s' `azapi_resource` migrate api management services to premium sku: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ApiManagement/service/#migrate-api-management-services-to-premium-sku-to-support-availability-zones", [resource.address])
}