package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_ensure_autoscale_feature_has_been_enabled(resource) if {
    resource.values.body.autoscaleConfiguration.minCapacity >= 0
}

deny_azapi_ensure_autoscale_feature_has_been_enabled contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Network/applicationGateways")
    not valid_azapi_ensure_autoscale_feature_has_been_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/azapi_ensure_autoscale_feature_has_been_enabled: '%s' `azapi_resource` should have autoscale enabled with minCapacity configured: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#ensure-autoscale-feature-has-been-enabled", [resource.address])
}