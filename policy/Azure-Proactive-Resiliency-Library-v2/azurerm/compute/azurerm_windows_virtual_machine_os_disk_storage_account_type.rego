package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_mission_critical_virtual_machine_should_use_premium_or_ultra_disks_os_disk_win(resource) if {
    startswith(resource.values.os_disk[_].storage_account_type, "Premium")
}

valid_azurerm_mission_critical_virtual_machine_should_use_premium_or_ultra_disks_os_disk_win(resource) if {
    startswith(resource.values.os_disk[_].storage_account_type, "Ultra")
}

deny_mission_critical_virtual_machine_should_use_premium_or_ultra_disks contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_virtual_machine")[_]
    not valid_azurerm_mission_critical_virtual_machine_should_use_premium_or_ultra_disks_os_disk_win(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/mission_critical_virtual_machine_should_use_premium_or_ultra_disks: '%s' `azurerm_windows_virtual_machine` must have configured `os_disk.storage_account_type` to use Premium or Ultra type: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#mission-critical-workloads-should-consider-using-premium-or-ultra-disks", [resource.address])
}