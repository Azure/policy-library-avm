
# This configuration has been generated by the Azure Terraform plugin which utilizes Generative AI which may result in unintended or inaccurate configuration code. A human must validate that this configuration accomplishes the desired goal before applying the configuration.

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_network_security_group" "test" {
  name                = "acctestnsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_network_watcher" "test" {
  name                = "acctestnw"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_storage_account" "test" {
  name                     = "acctestsa"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_kind             = "StorageV2"
  account_replication_type = "LRS"
}

resource "azurerm_log_analytics_workspace" "test" {
  name                = "acctestlaw"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "PerGB2018"
}

resource "azurerm_network_watcher_flow_log" "test" {
  network_watcher_name = azurerm_network_watcher.test.name
  resource_group_name  = azurerm_resource_group.example.name
  name                 = "example-log"

  target_resource_id = azurerm_network_security_group.test.id
  storage_account_id = azurerm_storage_account.test.id
  enabled            = true

  retention_policy {
    enabled = true
    days    = 90
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.test.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.test.location
    workspace_resource_id = azurerm_log_analytics_workspace.test.id
    interval_in_minutes   = 10
  }
}
