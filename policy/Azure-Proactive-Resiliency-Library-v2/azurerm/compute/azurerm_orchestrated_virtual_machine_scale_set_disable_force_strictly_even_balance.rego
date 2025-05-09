package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_virtual_machine_scaleset_disable_force_strictly_even_zone_balancing(resource) if {
    resource.values.zone_balance == false
}

deny_virtual_machine_scaleset_disable_force_strictly_even_zone_balancing contains reason if {
    resource := data.utils.resource(input, "azurerm_orchestrated_virtual_machine_scale_set")[_]
    not valid_azurerm_virtual_machine_scaleset_disable_force_strictly_even_zone_balancing(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_machine_scaleset_disable_force_strictly_even_zone_balancing: '%s' `azurerm_orchestrated_virtual_machine_scale_set` must have `zone_balance` set to `false`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#disable-force-strictly-even-balance-across-zones-to-avoid-scale-in-and-out-fail-attempts", [resource.address])
}