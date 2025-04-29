package Azure_Proactive_Resiliency_Library_v2

import rego.v1

#all valid managed disk sku's end with S.  If a sku is defined then the disk should be a managed disk.
valid_azapi_virtual_machines_should_use_managed_disks(resource) if {
    endswith(resource.values.body.properties.storageProfile.osDisk.managedDisk.storageAccountType, "S")
}

deny_virtual_machines_should_use_managed_disks contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachines")
    not valid_azapi_virtual_machines_should_use_managed_disks(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_machines_should_use_managed_disks: '%s' `azapi_resource` must have configured `storageProfile.osDisk.managedDisk`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#use-managed-disks-for-vm-disks", [resource.address])
}