package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_ensure_autoscale_feature_has_been_enabled(resource) if {
    resource.values.autoscale_configuration[0].min_capacity >= 0
}

deny_application_gateway_ensure_autoscale_feature_has_been_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_application_gateway")[_]
    not valid_azurerm_ensure_autoscale_feature_has_been_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/application_gateway_ensure_autoscale_feature_has_been_enabled: '%s' `azurerm_application_gateway` must have configured to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#ensure-autoscale-feature-has-been-enabled", [resource.address])
}