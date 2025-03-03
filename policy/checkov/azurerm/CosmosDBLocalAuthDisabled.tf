
# This configuration has been generated by the Azure Terraform plugin which utilizes Generative AI which may result in unintended or inaccurate configuration code. A human must validate that this configuration accomplishes the desired goal before applying the configuration.

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "East US"
}

resource "azurerm_cosmosdb_account" "example" {
  name                = "example-cosmosdb-account"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  offer_type         = "Standard"
  kind               = "GlobalDocumentDB"
  
  local_authentication_disabled = true

  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }

  consistency_policy {
    consistency_level       = "Session"
  }
}

output "cosmosdb_account_id" {
  value = azurerm_cosmosdb_account.example.id
}

resource "azurerm_cosmosdb_sql_database" "example" {
  name                = "example-sql-database"
  resource_group_name = azurerm_cosmosdb_account.example.resource_group_name
  account_name        = azurerm_cosmosdb_account.example.name
  throughput          = 400
}

resource "azurerm_cosmosdb_sql_container" "example" {
  name                  = "example-container"
  resource_group_name   = azurerm_cosmosdb_account.example.resource_group_name
  account_name          = azurerm_cosmosdb_account.example.name
  database_name         = azurerm_cosmosdb_sql_database.example.name
  partition_key_paths   = ["/examplePartitionKey"]

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }

    excluded_path {
      path = "/excluded/?"
    }
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
