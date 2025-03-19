package avmsec

import rego.v1

valid_azapi_api_management_backend_url_use_https(resource) if {
    startswith(resource.values.body.properties.url, "https")
}

valid_azapi_api_management_backend_url_use_https(resource) if {
    # It's quite common to use an known_after_apply value as url, right?
    resource.after_unknown.body.properties.url == resource.after_unknown.body.properties.url
}

deny_AVM_SEC_215 contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ApiManagement/service/backends")
    not valid_azapi_api_management_backend_url_use_https(resource)

    reason := sprintf("avmsec/AVM_SEC_215: Ensure API management backend uses https %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIManagementBackendHTTPS.py", [resource.address])
}
