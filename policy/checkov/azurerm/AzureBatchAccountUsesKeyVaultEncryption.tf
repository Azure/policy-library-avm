
# This configuration has been generated by the Azure Terraform plugin which utilizes Generative AI which may result in unintended or inaccurate configuration code. A human must validate that this configuration accomplishes the desired goal before applying the configuration.

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_storage_account" "example" {
  name                     = "examplestoracc"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_key_vault" "example" {
  name                        = "examplekeyvault"
  location                    = azurerm_resource_group.example.location
  resource_group_name         = azurerm_resource_group.example.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  purge_protection_enabled    = false
}

resource "azurerm_batch_account" "example" {
  name                                = "examplebatchaccount"
  resource_group_name                 = azurerm_resource_group.example.name
  location                            = azurerm_resource_group.example.location
  pool_allocation_mode                = "BatchService"
  storage_account_id                  = azurerm_storage_account.example.id
  storage_account_authentication_mode = "StorageKeys"

  key_vault_reference {
    id  = azurerm_key_vault.example.id
    url = azurerm_key_vault.example.vault_uri
  }

  tags = {
    env = "test"
  }
}
