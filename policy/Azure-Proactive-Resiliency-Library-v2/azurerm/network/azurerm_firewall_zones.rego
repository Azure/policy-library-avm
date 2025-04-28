package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_deploy_azure_firewall_across_multiple_availability_zones(resource) if {
    resource.values.zones == resource.values.zones
    count(resource.values.zones) >= 2
}

deny_deploy_azure_firewall_across_multiple_availability_zones contains reason if {
    resource := data.utils.resource(input, "azurerm_firewall")[_]
    not valid_azurerm_deploy_azure_firewall_across_multiple_availability_zones(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/deploy_azure_firewall_across_multiple_availability_zones: '%s' `azurerm_firewall` must have configured to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/azureFirewalls/#deploy-azure-firewall-across-multiple-availability-zones", [resource.address])
}