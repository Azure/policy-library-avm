package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_virtual_machine_scaleset_zonal_support(resource) if {
    count(resource.values.body.zones) >= 2
}

deny_virtual_machine_scaleset_zonal_support contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachineScaleSets")
    not valid_azapi_virtual_machine_scaleset_zonal_support(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_machine_scaleset_zonal_support: '%s' `azapi_resource` should enable multi-zone support. : https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#deploy-vmss-across-availability-zones-with-vmss-flex", [resource.address])
}