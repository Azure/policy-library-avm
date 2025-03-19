package avmsec

import rego.v1

valid_azurerm_api_management_backend_url_use_https(resource) if {
    startswith(resource.values.url, "https")
}

valid_azurerm_api_management_backend_url_use_https(resource) if {
    # It's quite common to use an known_after_apply value as url, right?
    resource.after_unknown.url == resource.after_unknown.url
}

deny_AVM_SEC_215 contains reason if {
    resource := data.utils.resource(input, "azurerm_api_management_backend")[_]
    not valid_azurerm_api_management_backend_url_use_https(resource)

    reason := sprintf("avmsec/AVM_SEC_215: Ensure API management backend uses https %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIManagementBackendHTTPS.py", [resource.address])
}
