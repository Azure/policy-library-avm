package avmsec

import rego.v1

valid_azurerm_eventhub_namespace_minimum_tls_version(resource) if {
    resource.values.minimum_tls_version == "1.2"
}

valid_azurerm_eventhub_namespace_minimum_tls_version(resource) if {
    # ensure that `minimum_tls_version` is default value, not `known_after_apply`
    not resource.after_unknown.minimum_tls_version == resource.after_unknown.minimum_tls_version
    not resource.values.minimum_tls_version == resource.values.minimum_tls_version
}

deny_AVM_SEC_223 contains reason if {
    resource := data.utils.resource(input, "azurerm_eventhub_namespace")[_]
    not valid_azurerm_eventhub_namespace_minimum_tls_version(resource)

    reason := sprintf("avmsec/AVM_SEC_223: Event Hub Namespace not using TLS 1.2 or greater. %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventHubNamespaceMinTLS12.py", [resource.address])
}
