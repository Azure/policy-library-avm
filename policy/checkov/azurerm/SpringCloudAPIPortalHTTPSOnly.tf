
# This configuration has been generated by the Azure Terraform plugin which utilizes Generative AI which may result in unintended or inaccurate configuration code. A human must validate that this configuration accomplishes the desired goal before applying the configuration.

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_spring_cloud_service" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku_name            = "E0"
}

resource "azurerm_spring_cloud_gateway" "example" {
  name                    = "default"
  spring_cloud_service_id = azurerm_spring_cloud_service.example.id
}

resource "azurerm_spring_cloud_api_portal" "example" {
  name                          = "default"
  spring_cloud_service_id       = azurerm_spring_cloud_service.example.id
  gateway_ids                   = [azurerm_spring_cloud_gateway.example.id]
  https_only_enabled            = true
  public_network_access_enabled = true
  instance_count                = 1
  api_try_out_enabled           = true
  sso {
    client_id     = "test"
    client_secret = "secret"
    issuer_uri    = "https://www.example.com/issueToken"
    scope         = ["read"]
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
