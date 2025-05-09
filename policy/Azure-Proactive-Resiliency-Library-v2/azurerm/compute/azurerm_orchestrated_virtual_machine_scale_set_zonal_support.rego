package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_virtual_machine_scaleset_zonal_support(resource) if {
    count(resource.values.zones) >= 2
}

deny_virtual_machine_scaleset_zonal_support contains reason if {
    resource := data.utils.resource(input, "azurerm_orchestrated_virtual_machine_scale_set")[_]
    not valid_azurerm_virtual_machine_scaleset_zonal_support(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_machine_scaleset_zonal_support: '%s' `azurerm_orchestrated_virtual_machine_scale_set` should have `zones` with multiple zones defined.: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#deploy-vmss-across-availability-zones-with-vmss-flex", [resource.address])
}