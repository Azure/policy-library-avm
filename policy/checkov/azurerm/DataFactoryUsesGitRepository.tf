
# This configuration has been generated by the Azure Terraform plugin which utilizes Generative AI which may result in unintended or inaccurate configuration code. A human must validate that this configuration accomplishes the desired goal before applying the configuration.

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_data_factory" "example" {
  name                = "example-data-factory"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  github_configuration {
    account_name   = "example-github-account"
    branch_name    = "main"
    repository_name = "example-repo"
    root_folder     = "/"
    publishing_enabled = true
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
