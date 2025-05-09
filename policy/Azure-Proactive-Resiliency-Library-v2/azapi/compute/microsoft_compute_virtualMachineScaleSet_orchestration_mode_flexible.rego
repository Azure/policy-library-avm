package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_virtual_machine_scaleset_orchestration_mode_flexible(resource) if {
    resource.values.body.properties.orchestrationMode == "Flexible"
}

deny_virtual_machine_scaleset_orchestration_mode_flexible contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachineScaleSets")
    not valid_azapi_virtual_machine_scaleset_orchestration_mode_flexible(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_machine_scaleset_orchestration_mode_flexible: '%s' `azapi_resource` should use flexible orchestration mode. : https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachineScaleSets/#deploy-vmss-with-flex-orchestration-mode-instead-of-uniform", [resource.address])
}