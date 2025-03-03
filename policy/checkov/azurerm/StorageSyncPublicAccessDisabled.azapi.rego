package checkov

import rego.v1

valid_azurerm_storage_sync_public_access_disabled(resource) if {
    resource.values.incoming_traffic_policy == "AllowVirtualNetworksOnly"
}

valid_azapi_storage_sync_public_access_disabled(resource) if {
    resource.body.properties.incomingTrafficPolicy == "AllowVirtualNetworksOnly"
}

deny_CKV_AZURE_64 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_sync")[_]
    not valid_azurerm_storage_sync_public_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_64: Ensure that Azure File Sync disables public network access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageSyncPublicAccessDisabled.py")
}

deny_CKV_AZURE_64_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.StorageSync/storageSyncServices/2020-03-01"
    not valid_azapi_storage_sync_public_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_64: Ensure that Azure File Sync disables public network access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageSyncPublicAccessDisabled.py")
}
