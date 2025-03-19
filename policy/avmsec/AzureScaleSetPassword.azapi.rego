package avmsec

import rego.v1

valid_azapi_linux_virtual_machine_scale_set_password_authentication(resource) if {
    resource.values.body.properties.virtualMachineProfile.osProfile.linuxConfiguration.disablePasswordAuthentication == true
}

deny_AVM_SEC_49 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachineScaleSets")
    not valid_azapi_linux_virtual_machine_scale_set_password_authentication(resource)

    reason := sprintf("avmsec/AVM_SEC_49: Ensure Azure linux scale set does not use basic authentication(Use SSH Key Instead). %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureScaleSetPassword.py", [resource.address])
}
