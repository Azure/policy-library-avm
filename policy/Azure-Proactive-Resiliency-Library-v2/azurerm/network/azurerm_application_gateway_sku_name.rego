package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_migrate_to_application_gateway_v2(resource) if {
    resource.values.sku[_].name == "Standard_v2"
}

valid_azurerm_migrate_to_application_gateway_v2(resource) if {
    resource.values.sku[_].name == "WAF_v2"
}

deny_migrate_to_application_gateway_v2 contains reason if {
    resource := data.utils.resource(input, "azurerm_application_gateway")[_]
    not valid_azurerm_migrate_to_application_gateway_v2(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/migrate_to_application_gateway_v2: '%s' `azurerm_application_gateway` must have 'sku.name' set to 'Standard_v2' or 'WAF_v2': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2", [resource.address])
}