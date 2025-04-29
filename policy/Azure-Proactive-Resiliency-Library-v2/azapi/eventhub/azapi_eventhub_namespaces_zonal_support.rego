package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_eventhub_namespace_zonal_support(resource) if {
    resource.values.body.properties.zoneRedundant == true
}


deny_eventhub_namespace_zonal_support contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.EventHub/namespaces")
    not valid_azapi_eventhub_namespace_zonal_support(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/eventhub_namespace_zonal_support: '%s' `azapi_resource` must config `body.properties.zoneRedundant` to `true`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/EventHub/namespaces/#ensure-zone-redundancy-is-enabled-in-supported-regions", [resource.address])
}