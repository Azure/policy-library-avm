package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_eventhub_namespace_enable_auto_inflate(resource) if {
    resource.values.auto_inflate_enabled == true
}

deny_eventhub_namespace_enable_auto_inflate contains reason if {
    resource := data.utils.resource(input, "azurerm_eventhub_namespace")[_]
    not valid_azurerm_eventhub_namespace_enable_auto_inflate(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/eventhub_namespace_enable_auto_inflate: '%s' `azurerm_eventhub_namespace` should have 'auto_inflate_enabled' set to 'true': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/EventHub/namespaces/#enable-auto-inflate-on-event-hub-standard-tier", [resource.address])
}