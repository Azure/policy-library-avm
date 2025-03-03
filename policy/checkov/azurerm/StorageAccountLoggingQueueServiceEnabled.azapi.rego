package checkov

import rego.v1

valid_azurerm_storage_account_queue_logging(resource) if {
    resource.values.account_kind != "Storage"
    resource.values.account_kind != "StorageV2"
}

valid_azurerm_storage_account_queue_logging(resource) if {
    queue_properties := resource.values.queue_properties[_]
    logging := queue_properties.logging[_]
    logging.delete == true
    logging.write == true
    logging.read == true
}

deny_CKV_AZURE_33 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_account_queue_logging(resource)

    reason := sprintf("checkov/CKV_AZURE_33: Ensure Storage logging is enabled for Queue service for read, write and delete requests. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountLoggingQueueServiceEnabled.py")
}


valid_azapi_storage_account_queue_logging(resource) if {
    resource.body.kind != "Storage"
    resource.body.kind != "StorageV2"
}

valid_azapi_storage_account_queue_logging(resource) if {
    #queue_properties := resource.body.properties.queue_properties[_] #queue_properties is not exist in azapi
    #logging := queue_properties.logging[_] #logging is not exist in azapi
    #logging.delete == true #logging.delete is not exist in azapi
    #logging.write == true #logging.write is not exist in azapi
    #logging.read == true #logging.read is not exist in azapi

    # workaround since queue_properties.logging is not available, check encryption for queue service
    encryption_services := resource.body.properties.encryption.services
    encryption_services.queue.keyType == "Service"

}

deny_CKV_AZURE_33_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Storage/storageAccounts/2023-05-01"
    not valid_azapi_storage_account_queue_logging(resource)

    reason := sprintf("checkov/CKV_AZURE_33: Ensure Storage logging is enabled for Queue service for read, write and delete requests. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountLoggingQueueServiceEnabled.py")
}
