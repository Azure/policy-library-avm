package checkov

import rego.v1

valid_azapi_eventgrid_domain_network_access_disabled(resource) if {
    resource.body.properties.publicNetworkAccess == "Disabled"
}

deny_CKV_AZURE_106_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.EventGrid/domains/2022-06-15"
    not valid_azapi_eventgrid_domain_network_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_106: Ensure that Azure Event Grid Domain public network access is disabled. Resource %s has public_network_access_enabled set to true. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventgridDomainNetworkAccess.py", [resource.address])
}
