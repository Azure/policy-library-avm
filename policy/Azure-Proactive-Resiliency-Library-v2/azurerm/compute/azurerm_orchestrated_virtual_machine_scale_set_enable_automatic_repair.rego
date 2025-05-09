package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_virtual_machine_scaleset_enable_automatic_repair(resource) if {
    resource.values.automatic_instance_repair[_].enabled == true
}

deny_virtual_machine_scaleset_enable_automatic_repair contains reason if {
    resource := data.utils.resource(input, "azurerm_orchestrated_virtual_machine_scale_set")[_]
    not valid_azurerm_virtual_machine_scaleset_enable_automatic_repair(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_machine_scaleset_enable_automatic_repair: '%s' `azurerm_orchestrated_virtual_machine_scale_set` must have `automatic_instance_repair.enabled` set to `true`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#enable-automatic-repair-policy-on-azure-virtual-machine-scale-sets", [resource.address])
}