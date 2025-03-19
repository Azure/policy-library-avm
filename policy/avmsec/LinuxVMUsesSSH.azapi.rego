package avmsec

import rego.v1

is_azapi_linux_virtual_machine(resource) if {
    resource.values.body.properties.storageProfile.osDisk.osType == "Linux"
}

valid_azapi_linux_virtual_machine_use_ssh(resource) if {
    resource.values.body.properties.osProfile.linuxConfiguration.ssh.publicKeys[0].keyData == resource.values.body.properties.osProfile.linuxConfiguration.ssh.publicKeys[0].keyData
}

valid_azapi_linux_virtual_machine_use_ssh(resource) if {
    resource.after_unknown.body.properties.osProfile.linuxConfiguration.ssh.publicKeys[0].keyData == resource.after_unknown.body.properties.osProfile.linuxConfiguration.ssh.publicKeys[0].keyData
}

deny_AVM_SEC_178 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachines")
    is_azapi_linux_virtual_machine(resource)
    not valid_azapi_linux_virtual_machine_use_ssh(resource)

    reason := sprintf("avmsec/AVM_SEC_178: Ensure that Linux VMs and Linux VM Scale Sets in Azure are configured to use SSH keys for authentication %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/LinuxVMUsesSSH.py", [resource.address])
}

deny_AVM_SEC_178 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachineScaleSets")
    is_azapi_linux_virtual_machine(resource)
    not valid_azapi_linux_virtual_machine_use_ssh(resource)

    reason := sprintf("avmsec/AVM_SEC_178: Ensure that Linux VMs and Linux VM Scale Sets in Azure are configured to use SSH keys for authentication %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/LinuxVMUsesSSH.py", [resource.address])
}