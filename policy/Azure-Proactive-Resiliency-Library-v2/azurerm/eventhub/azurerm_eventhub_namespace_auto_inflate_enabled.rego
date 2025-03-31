package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_eventhub_namespace_auto_inflate_enabled(resource) if {
    resource.values.auto_inflate_enabled == true
}

deny_eventhub_namespace_auto_inflate_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_eventhub_namespace")[_]
    not valid_azurerm_eventhub_namespace_auto_inflate_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/eventhub_namespace_auto_inflate_enabled: '%s' `azurerm_eventhub_namespace` should have 'auto_inflate_enabled' set to 'true': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/EventHub/namespaces/#enable-auto-inflate-on-event-hub-standard-tier", [resource.address])
}