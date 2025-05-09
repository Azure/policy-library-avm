package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_eventhub_namespace_enable_auto_inflate(resource) if {
    resource.values.body.properties.isAutoInflateEnabled == true
}


deny_eventhub_namespace_enable_auto_inflate contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.EventHub/namespaces")
    not valid_azapi_eventhub_namespace_enable_auto_inflate(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/eventhub_namespace_enable_auto_inflate: '%s' `azapi_resource` should have auto-inflate enabled.: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/EventHub/namespaces/#enable-auto-inflate-on-event-hub-standard-tier", [resource.address])
}