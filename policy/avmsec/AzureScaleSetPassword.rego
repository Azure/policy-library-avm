package avmsec

import rego.v1

valid_azurerm_linux_virtual_machine_scale_set_password_authentication(resource) if {
    resource.values.disable_password_authentication == true
}

valid_azurerm_linux_virtual_machine_scale_set_password_authentication(resource) if {
    not resource.values.disable_password_authentication == resource.values.disable_password_authentication
}

deny_AVM_SEC_49 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine_scale_set")[_]
    not valid_azurerm_linux_virtual_machine_scale_set_password_authentication(resource)

    reason := sprintf("avmsec/AVM_SEC_49: Ensure Azure linux scale set does not use basic authentication(Use SSH Key Instead). %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureScaleSetPassword.py", [resource.address])
}
