
package checkov

import rego.v1

valid_azapi_container_registry_anonymous_pull_disabled(resource) if {
    resource.body.sku.name != "Standard"
    resource.body.sku.name != "Premium"
}

valid_azapi_container_registry_anonymous_pull_disabled(resource) if {
    not resource.body.properties.anonymousPullEnabled == resource.body.properties.anonymousPullEnabled
}

valid_azapi_container_registry_anonymous_pull_disabled(resource) if {
    resource.body.properties.anonymousPullEnabled == false
}

deny_CKV_AZURE_138_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.ContainerRegistry/registries"
    not valid_azapi_container_registry_anonymous_pull_disabled(resource)
    reason := sprintf("checkov/CKV_AZURE_138: Ensures that ACR disables anonymous pulling of images. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRAnonymousPullDisabled.py")
}
