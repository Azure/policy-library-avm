package checkov

import rego.v1

valid_azapi_security_center_kubernetes_service_subscription_pricing_configuration(resource) if {
    resource.values.name != "KubernetesService"
}

valid_azapi_security_center_kubernetes_service_subscription_pricing_configuration(resource) if {
    resource.properties.pricingTier == "Standard"
}

deny_CKV_AZURE_85_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Security/pricings")
    not valid_azapi_security_center_kubernetes_service_subscription_pricing_configuration(resource)

    reason := sprintf("checkov/CKV_AZURE_85: Ensure that Azure Defender is set to On for Kubernetes. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnKubernetes.py")
}