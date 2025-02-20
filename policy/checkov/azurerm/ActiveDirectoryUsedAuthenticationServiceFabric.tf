
# This configuration has been generated by the Azure Terraform plugin which utilizes Generative AI which may result in unintended or inaccurate configuration code. A human must validate that this configuration accomplishes the desired goal before applying the configuration.

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_service_fabric_cluster" "example" {
  name                 = "example-servicefabric"
  resource_group_name  = azurerm_resource_group.example.name
  location             = azurerm_resource_group.example.location
  reliability_level    = "Bronze"
  upgrade_mode         = "Manual"
  management_endpoint  = "https://example:80"
  vm_image             = "Windows"

  azure_active_directory {
    tenant_id            = "00000000-0000-0000-0000-000000000000" # Replace with a valid UUID
    cluster_application_id = "00000000-0000-0000-0000-000000000000" # Replace with a valid UUID
    client_application_id  = "00000000-0000-0000-0000-000000000000" # Replace with a valid UUID
  }

  node_type {
    name                 = "first"
    instance_count       = 3
    is_primary           = true
    client_endpoint_port = 2020
    http_endpoint_port   = 80
  }
}
