package avmsec

import rego.v1

valid_azurerm_security_center_kubernetes_service_subscription_pricing_configuration(resource) if {
    resource.values.resource_type != "KubernetesService"
}

valid_azurerm_security_center_kubernetes_service_subscription_pricing_configuration(resource) if {
    resource.values.tier == "Standard"
}

deny_AVM_SEC_85 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_kubernetes_service_subscription_pricing_configuration(resource)

    reason := sprintf("avmsec/AVM_SEC_85: Ensure that Azure Defender is set to On for Kubernetes. %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnKubernetes.py", [resource.address])
}
