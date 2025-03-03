package checkov

import rego.v1

valid_azurerm_vm_disable_password_authentication(resource) if {
    resource.values.disable_password_authentication == true
}

valid_azapi_vm_disable_password_authentication(resource) if {
    resource.body.properties.virtualMachineProfile.osProfile.linuxConfiguration.disablePasswordAuthentication == true
}

deny_CKV_AZURE_149 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine_scale_set")[_]
    not valid_azurerm_vm_disable_password_authentication(resource)
    reason := sprintf("checkov/CKV_AZURE_149: Ensure that Virtual machine does not enable password authentication. Resource %s must have disable_password_authentication set to true. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMDisablePasswordAuthentication.py", [resource.address])
}

deny_CKV_AZURE_149 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine")[_]
    not valid_azurerm_vm_disable_password_authentication(resource)
    reason := sprintf("checkov/CKV_AZURE_149: Ensure that Virtual machine does not enable password authentication. Resource %s must have disable_password_authentication set to true. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMDisablePasswordAuthentication.py", [resource.address])
}

deny_CKV_AZURE_149 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Compute/virtualMachineScaleSets/2024-07-01"
    not valid_azapi_vm_disable_password_authentication(resource)
    reason := sprintf("checkov/CKV_AZURE_149: Ensure that Virtual machine does not enable password authentication. Resource %s must have disable_password_authentication set to true. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMDisablePasswordAuthentication.py", [resource.address])
}
