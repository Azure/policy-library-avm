
package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_uses_azure_policies_addon(resource) if {
    # since Azure provider v2.97.0
    resource.values.azure_policy_enabled == true
}

valid_azurerm_kubernetes_cluster_uses_azure_policies_addon(resource) if {
    # up to and including Azure provider v2.96.0
    addon_profile := resource.values.addon_profile[0]
    addon_profile.azure_policy[0].enabled == true
}

valid_azapi_kubernetes_cluster_uses_azure_policies_addon(resource) if {
    resource.changes.after.body.properties.addonProfiles.azurepolicy.enabled == true
}

deny_CKV_AZURE_116 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_uses_azure_policies_addon(resource)

    reason := sprintf("checkov/CKV_AZURE_116: Ensure that AKS uses Azure Policies Add-on %s", [resource.address])
}

deny_CKV_AZURE_116 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    not valid_azapi_kubernetes_cluster_uses_azure_policies_addon(resource)

    reason := sprintf("checkov/CKV_AZURE_116: Ensure that AKS uses Azure Policies Add-on %s", [resource.address])
}
