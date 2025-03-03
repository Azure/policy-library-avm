
# This configuration has been generated by the Azure Terraform plugin which utilizes Generative AI which may result in unintended or inaccurate configuration code. A human must validate that this configuration accomplishes the desired goal before applying the configuration.

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_storage_account" "example" {
  name                     = "functionappstorage"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_service_plan" "example" {
  name                = "example-app-service-plan"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  os_type             = "Windows"
  sku_name            = "Y1"
}

resource "azurerm_windows_function_app" "example" {
  name                 = "example-function-app"
  resource_group_name  = azurerm_resource_group.example.name
  location             = azurerm_resource_group.example.location
  storage_account_name = azurerm_storage_account.example.name
  service_plan_id      = azurerm_service_plan.example.id

  site_config {
    enable_builtin_logging = true
  }
}

resource "azurerm_windows_function_app_slot" "example_slot" {
  name                 = "example-slot"
  function_app_id      = azurerm_windows_function_app.example.id
  storage_account_name = azurerm_storage_account.example.name

  site_config {
    enable_builtin_logging = true
  }
}

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.20.0"
    }
  }
}
