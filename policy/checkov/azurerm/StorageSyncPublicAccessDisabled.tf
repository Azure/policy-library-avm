
# This configuration has been generated by the Azure Terraform plugin which utilizes Generative AI which may result in unintended or inaccurate configuration code. A human must validate that this configuration accomplishes the desired goal before applying the configuration.

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_storage_sync" "example" {
  name                = "example-storage-sync"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  incoming_traffic_policy = "AllowVirtualNetworksOnly"

  tags = {
    foo = "bar"
  }
}
