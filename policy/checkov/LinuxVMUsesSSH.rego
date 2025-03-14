package checkov

import rego.v1

valid_azurerm_linux_virtual_machine_use_ssh(resource) if {
    resource.values.admin_ssh_key[0].public_key == resource.values.admin_ssh_key[0].public_key
}

valid_azurerm_linux_virtual_machine_use_ssh(resource) if {
    resource.after_unknown.admin_ssh_key[0].public_key == resource.after_unknown.admin_ssh_key[0].public_key
}

deny_CKV_AZURE_178 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine")[_]
    not valid_azurerm_linux_virtual_machine_use_ssh(resource)

    reason := sprintf("checkov/CKV_AZURE_178: Ensure that Linux VMs and Linux VM Scale Sets in Azure are configured to use SSH keys for authentication %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/LinuxVMUsesSSH.py", [resource.address])
}

deny_CKV_AZURE_178 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine_scale_set")[_]
    not valid_azurerm_linux_virtual_machine_use_ssh(resource)

    reason := sprintf("checkov/CKV_AZURE_178: Ensure that Linux VMs and Linux VM Scale Sets in Azure are configured to use SSH keys for authentication %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/LinuxVMUsesSSH.py", [resource.address])
}