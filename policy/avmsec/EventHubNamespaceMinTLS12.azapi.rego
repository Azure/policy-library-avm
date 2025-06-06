package avmsec

import rego.v1

valid_azapi_eventhub_namespace_minimum_tls_version(resource) if {
    resource.values.body.properties.minimumTlsVersion == "1.2"
}

deny_AVM_SEC_223 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.EventHub/namespaces")
    not valid_azapi_eventhub_namespace_minimum_tls_version(resource)

    reason := sprintf("avmsec/AVM_SEC_223: Event Hub Namespace not using TLS 1.2 or greater. %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventHubNamespaceMinTLS12.py", [resource.address])
}
