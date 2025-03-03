package checkov

import rego.v1

valid_azurerm_api_management_client_certs_enabled(resource) if {
    resource.values.sku_name == ["Consumption"]
    resource.values.client_certificate_enabled == [true]
}

deny_CKV_AZURE_152 contains reason if {
    resource := data.utils.resource(input, "azurerm_api_management")[_]
    resource.values.sku_name == ["Consumption"]
    not valid_azurerm_api_management_client_certs_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_152: Ensure Client Certificates are enforced for API management. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIManagementCertsEnforced.py")
}

valid_azapi_api_management_client_certs_enabled(resource) if {
    resource.changes.after.body.sku.name == "Consumption"
    resource.changes.after.body.properties.enableClientCertificate == true
}

deny_CKV_AZURE_152_azapi contains reason if {
    resource := input.mock.default.resource_changes[_]
    resource.type == "azapi_resource"
    resource.changes.after.type == "Microsoft.ApiManagement/service/2022-08-01"
    resource.changes.after.body.sku.name == "Consumption"
    not valid_azapi_api_management_client_certs_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_152: Ensure Client Certificates are enforced for API management. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIManagementCertsEnforced.py")
}
