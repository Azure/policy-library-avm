package Azure_Proactive_Resiliency_Library_v2

import rego.v1

deny_virtual_machine_scaleset_orchestration_mode_flexible contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_virtual_machine_scale_set")[_]

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_machine_scaleset_orchestration_mode_flexible: '%s' `azurerm_orchestrated_virtual_machine_scale_set` should be used instead of `azurerm_windows_virtual_machine_scale_set` or `azurerm_linux_virtual_machine_scale_set`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#deploy-vmss-with-flex-orchestration-mode-instead-of-uniform", [resource.address])
}