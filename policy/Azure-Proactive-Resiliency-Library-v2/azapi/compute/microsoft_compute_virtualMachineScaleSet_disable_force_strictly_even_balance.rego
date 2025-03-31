package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_virtual_machine_scaleset_disable_force_strictly_even_zone_balancing(resource) if {
    resource.values.body.properties.zoneBalance == false
}

deny_virtual_machine_scaleset_disable_force_strictly_even_zone_balancing contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachineScaleSets")
    not valid_azapi_virtual_machine_scaleset_disable_force_strictly_even_zone_balancing(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_machine_scaleset_disable_force_strictly_even_zone_balancing: '%s' `azapi_resource` should set strict zone balancing (`properties.zoneBalance`) to false. : https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#disable-force-strictly-even-balance-across-zones-to-avoid-scale-in-and-out-fail-attempts", [resource.address])
}