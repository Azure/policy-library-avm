package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_deploy_azure_firewall_across_multiple_availability_zones(resource) if {
    resource.values.body.zones == resource.values.body.zones
    count(resource.values.body.zones) >= 2
}

deny_deploy_azure_firewall_across_multiple_availability_zones contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Network/azureFirewalls")
    not valid_azapi_deploy_azure_firewall_across_multiple_availability_zones(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/deploy_azure_firewall_across_multiple_availability_zones: '%s' `azapi_resource` must be configured to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/azureFirewalls/#deploy-azure-firewall-across-multiple-availability-zones", [resource.address])
}