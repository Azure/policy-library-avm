package utils_test

import data.utils
import rego.v1

test_resource_plan_resource_changes if {
    # According to HashiCorp's document, on Terraform Cloud (HCP Terraform) the plan was wrapped under `plan` field in `input`: https://github.com/hashicorp/terraform-docs-common/blob/ef6f18fd22f78e9437fa7ac9ecb85295d51988a3/website/docs/cloud-docs/policy-enforcement/define-policies/opa.mdx?plain=1#L40
    _input := {
        "plan": {
            "resource_changes": [
                {
                    "address": "azurerm_cosmosdb_account.example",
                    "change": {
                        "after": {
                            "backup": [
                                {
                                    "type": "Continuous"
                                }
                            ]
                        }
                    },
                    "mode": "managed",
                    "type": "azurerm_cosmosdb_account"
                }
            ]
        }
    }
    resources := utils.resource(_input, "azurerm_cosmosdb_account")
    count(resources) == 1
    resource := resources[_]
    resource.address == "azurerm_cosmosdb_account.example"
    resource.values.backup[0].type == "Continuous"
    resource.mode == "managed"
    resource.type == "azurerm_cosmosdb_account"
}

test_resource_resource_changes if {
    _input := {
        "resource_changes": [
            {
                "address": "azurerm_cosmosdb_account.example",
                "change": {
                    "after": {
                        "backup": [
                            {
                                "type": "Continuous"
                            }
                        ]
                    }
                },
                "mode": "managed",
                "type": "azurerm_cosmosdb_account"
            }
        ]
    }
    resources := utils.resource(_input, "azurerm_cosmosdb_account")
    count(resources) == 1
    resource := resources[_]
    resource.address == "azurerm_cosmosdb_account.example"
    resource.values.backup[0].type == "Continuous"
    resource.mode == "managed"
    resource.type == "azurerm_cosmosdb_account"
}

test_resource_values_root_module_resources if {
    _input := {
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "azurerm_cosmosdb_account.example",
                        "values": {
                            "backup": [
                                {
                                    "type": "Continuous"
                                }
                            ]
                        },
                        "mode": "managed",
                        "type": "azurerm_cosmosdb_account"
                    }
                ]
            }
        }
    }
    resources := utils.resource(_input, "azurerm_cosmosdb_account")
    count(resources) == 1
    resource := resources[_]
    resource.address == "azurerm_cosmosdb_account.example"
    resource.values.backup[0].type == "Continuous"
    resource.mode == "managed"
    resource.type == "azurerm_cosmosdb_account"
}

test_resource_values_child_module_resources if {
    _input := {
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "azurerm_cosmosdb_account.example",
                        "values": {
                            "backup": [
                                {
                                    "type": "Continuous"
                                }
                            ]
                        },
                        "mode": "managed",
                        "type": "azurerm_cosmosdb_account"
                    }
                ],
                "child_modules": [
                    {
                        "address": "module.sub",
                        "resources": [
                            {
                                "address": "module.sub.null_resource.res",
                                "mode": "managed",
                                "type": "null_resource",
                                "values": {
                                    "id": "2822366925496045444",
                                    "triggers": null
                                },
                            }
                        ]
                    },
                    {
                        "address": "module.sub2",
                        "resources": [
                            {
                                "address": "module.sub2.null_resource.res",
                                "mode": "managed",
                                "type": "null_resource",
                                "values": {
                                    "id": "2822366925496045445",
                                    "triggers": null
                                },
                            }
                        ]
                    },
                ]
            }
        }
    }
    cosmosdb_resources := utils.resource(_input, "azurerm_cosmosdb_account")
    count(cosmosdb_resources) == 1
    cosmosdb := cosmosdb_resources[_]
    cosmosdb.address == "azurerm_cosmosdb_account.example"
    cosmosdb.values.backup[0].type == "Continuous"
    cosmosdb.mode == "managed"
    cosmosdb.type == "azurerm_cosmosdb_account"

    null_resources := utils.resource(_input, "null_resource")
    count(null_resources) == 2
    null_resource := null_resources[1]
    null_resource.address == "module.sub2.null_resource.res"
    null_resource.values.id == "2822366925496045445"
    null_resource.mode == "managed"
    null_resource.type == "null_resource"
}

test_resource_values_child_module_resources_only if {
    _input := {
        "values": {
            "root_module": {
                "child_modules": [
                    {
                        "address": "module.sub",
                        "resources": [
                            {
                                "address": "module.sub.null_resource.res",
                                "mode": "managed",
                                "type": "null_resource",
                                "values": {
                                    "id": "2822366925496045444",
                                    "triggers": null
                                },
                            }
                        ]
                    },
                    {
                        "address": "module.sub2",
                        "resources": [
                            {
                                "address": "module.sub2.null_resource.res",
                                "mode": "managed",
                                "type": "null_resource",
                                "values": {
                                    "id": "2822366925496045445",
                                    "triggers": null
                                },
                            }
                        ]
                    },
                ]
            }
        }
    }
    null_resources := utils.resource(_input, "null_resource")
    count(null_resources) == 2
    null_resource := null_resources[1]
    null_resource.address == "module.sub2.null_resource.res"
    null_resource.values.id == "2822366925496045445"
    null_resource.mode == "managed"
    null_resource.type == "null_resource"
}

test_is_create_or_update if {
	data.utils.is_create_or_update(["create"])
	data.utils.is_create_or_update(["update", "create"])
	data.utils.is_create_or_update(["create", "update"])
	data.utils.is_create_or_update(["delete", "create"])
	data.utils.is_create_or_update(["delete", "update"])
	not data.utils.is_create_or_update(["create", "delete"])
	data.utils.is_create_or_update(["update"])
}

test_is_resource_create_or_update if {
	data.utils.is_resource_create_or_update({"change": {"actions": ["create"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["update", "create"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["create", "update"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["delete", "create"]}})
	not data.utils.is_resource_create_or_update({"change": {"actions": ["create", "delete"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["update"]}})
}

test_is_azure_type if {
    # Test case: resource type matches the specified Azure type
    utils.is_azure_type({"type": "Microsoft.DocumentDB/databaseAccounts@2024-12-01-preview"}, "Microsoft.DocumentDB/databaseAccounts")

    # Test case: resource type does not match the specified Azure type
    r := {"type": "Microsoft.Network/loadBalancers@2024-12-01-preview"}
    azure_type := "Microsoft.DocumentDB/databaseAccounts"
    not utils.is_azure_type({"type": "Microsoft.Network/loadBalancers@2024-12-01-preview"}, "Microsoft.DocumentDB/databaseAccounts")

    # Test case: resource type matches a different Azure type
   utils.is_azure_type({"type": "Microsoft.Network/loadBalancers@2024-12-01-preview"}, "Microsoft.Network/loadBalancers")

    # Test case: resource type does not match any Azure type
    not utils.is_azure_type({"type": "Custom.ResourceType@2024-12-01-preview"}, "Microsoft.DocumentDB/databaseAccounts")
}

test_get_change_after_unknown if {
    # Test case: after_unknown is true
    input_with_after_unknown := {
        "change": {
            "after_unknown": 123
        }
    }
    result_with_after_unknown := utils._get_change_after_unknown(input_with_after_unknown)
    result_with_after_unknown == 123

    # Test case: after_unknown is not present
    input_without_after_unknown := {
        "change": {}
    }
    result_without_after_unknown := utils._get_change_after_unknown(input_without_after_unknown)
    result_without_after_unknown == []
}

test_resource_in_configuration_direct if {
    _input := {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "azurerm_cosmosdb_account.example",
                        "mode": "managed",
                        "type": "azurerm_cosmosdb_account",
                        "expressions": {
                            "backup": {
                                "constant_value": [
                                    {
                                        "type": "Continuous"
                                    }
                                ]
                            }
                        }
                    }
                ]
            }
        }
    }
    configuration := utils._configuration(_input)
    configuration.root_module.resources[0].address == "azurerm_cosmosdb_account.example"
    configuration.root_module.resources[0].type == "azurerm_cosmosdb_account"
    configuration.root_module.resources[0].expressions.backup.constant_value[0].type == "Continuous"
}

test_resource_in_configuration_in_plan if {
    _input := {
        "plan": {
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "address": "azurerm_cosmosdb_account.example",
                            "mode": "managed",
                            "type": "azurerm_cosmosdb_account",
                            "expressions": {
                                "backup": {
                                    "constant_value": [
                                        {
                                            "type": "Continuous"
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
    configuration := utils._configuration(_input)
    configuration.root_module.resources[0].address == "azurerm_cosmosdb_account.example"
    configuration.root_module.resources[0].type == "azurerm_cosmosdb_account"
    configuration.root_module.resources[0].expressions.backup.constant_value[0].type == "Continuous"
}

test_resources_in_configuration_root_module if {
    _input := {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "azurerm_storage_account_customer_managed_key.example",
                        "mode": "managed",
                        "type": "azurerm_storage_account_customer_managed_key",
                        "expressions": {
                            "key_name": {
                                "references": [
                                    "azurerm_key_vault_key.example.name"
                                ]
                            }
                        }
                    }
                ]
            }
        }
    }

    resources := utils.resource_configuration(_input)
    count(resources) == 1
    resource := resources["azurerm_storage_account_customer_managed_key.example"]
    resource.address == "azurerm_storage_account_customer_managed_key.example"
    resource.type == "azurerm_storage_account_customer_managed_key"
    resource.expressions.key_name.references[0] == "azurerm_key_vault_key.example.name"
}

test_resources_in_configuration_module_calls if {
    _input := {
        "configuration": {
            "root_module": {
                "module_calls": {
                    "mod1": {
                        "source": "./mod1",
                        "module": {
                            "resources": [
                                {
                                    "address": "azurerm_storage_account_customer_managed_key.example",
                                    "mode": "managed",
                                    "type": "azurerm_storage_account_customer_managed_key",
                                    "expressions": {
                                        "key_vault_id": {
                                            "references": [
                                                "azurerm_key_vault.example.id"
                                            ]
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
    }

    resources := utils.resource_configuration(_input)
    count(resources) == 1
    resource := resources["module.mod1.azurerm_storage_account_customer_managed_key.example"]
    resource.address == "module.mod1.azurerm_storage_account_customer_managed_key.example"
    resource.type == "azurerm_storage_account_customer_managed_key"
    resource.expressions.key_vault_id.references[0] == "azurerm_key_vault.example.id"
}

test_resources_in_configuration_nested_modules if {
    _input := {
        "configuration": {
            "root_module": {
                "module_calls": {
                    "mod2": {
                        "source": "./mod2",
                        "module": {
                            "module_calls": {
                                "mod1": {
                                    "source": "../mod1",
                                    "module": {
                                        "resources": [
                                            {
                                                "address": "azurerm_storage_account_customer_managed_key.example",
                                                "mode": "managed",
                                                "type": "azurerm_storage_account_customer_managed_key",
                                                "expressions": {
                                                    "storage_account_id": {
                                                        "references": [
                                                            "azurerm_storage_account.example.id"
                                                        ]
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    resources := utils.resource_configuration(_input)
    count(resources) == 1
    resource := resources["module.mod2.module.mod1.azurerm_storage_account_customer_managed_key.example"]
    resource.address == "module.mod2.module.mod1.azurerm_storage_account_customer_managed_key.example"
    resource.type == "azurerm_storage_account_customer_managed_key"
    resource.expressions.storage_account_id.references[0] == "azurerm_storage_account.example.id"
}

test_resources_in_configuration_combined if {
    _input := {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "azurerm_storage_account.root_level",
                        "mode": "managed",
                        "type": "azurerm_storage_account",
                        "expressions": {
                            "account_replication_type": {
                                "constant_value": "GRS"
                            }
                        }
                    }
                ],
                "module_calls": {
                    "mod1": {
                        "source": "./mod1",
                        "module": {
                            "resources": [
                                {
                                    "address": "azurerm_key_vault.module_level",
                                    "mode": "managed",
                                    "type": "azurerm_key_vault",
                                    "expressions": {
                                        "sku_name": {
                                            "constant_value": "premium"
                                        }
                                    }
                                }
                            ],
                            "module_calls": {
                                "nested_mod": {
                                    "source": "./nested",
                                    "module": {
                                        "resources": [
                                            {
                                                "address": "azurerm_cosmosdb_account.nested_level",
                                                "mode": "managed",
                                                "type": "azurerm_cosmosdb_account",
                                                "expressions": {
                                                    "offer_type": {
                                                        "constant_value": "Standard"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    resources := utils.resource_configuration(_input)
    count(resources) == 3

    # Verify each resource was found
    resource_types := {r.type | r := resources[_]}
    resource_types["azurerm_storage_account"]
    resource_types["azurerm_key_vault"]
    resource_types["azurerm_cosmosdb_account"]

    # Verify specific details of each resource
    storage := [r | r := resources[_]; r.type == "azurerm_storage_account"][0]
    storage.address == "azurerm_storage_account.root_level"
    storage.expressions.account_replication_type.constant_value == "GRS"

    keyvault := [r | r := resources[_]; r.type == "azurerm_key_vault"][0]
    keyvault.address == "module.mod1.azurerm_key_vault.module_level"
    keyvault.expressions.sku_name.constant_value == "premium"

    cosmosdb := [r | r := resources[_]; r.type == "azurerm_cosmosdb_account"][0]
    cosmosdb.address == "module.mod1.module.nested_mod.azurerm_cosmosdb_account.nested_level"
    cosmosdb.expressions.offer_type.constant_value == "Standard"
}

test_arraycontains if {
    # Test with strings
    utils.arraycontains(["a", "b", "c"], "b")
    not utils.arraycontains(["a", "b", "c"], "d")

    # Test with numbers
    utils.arraycontains([1, 2, 3], 2)
    not utils.arraycontains([1, 2, 3], 4)

    # Test with booleans
    utils.arraycontains([true, false], true)
    not utils.arraycontains([true, false], null)

    # Test with empty array
    not utils.arraycontains([], "anything")

    # Test with mixed type array
    mixed_array := [1, "a", true, {"key": "value"}]
    utils.arraycontains(mixed_array, "a")
    utils.arraycontains(mixed_array, true)
    utils.arraycontains(mixed_array, 1)
    utils.arraycontains(mixed_array, {"key": "value"})
    not utils.arraycontains(mixed_array, "b")

    # Test with complex objects
    obj := {"name": "test", "id": 123}
    arr := [1, 2, 3]
    complex_array := [obj, arr]
    utils.arraycontains(complex_array, obj)
    utils.arraycontains(complex_array, arr)
    not utils.arraycontains(complex_array, {"name": "test", "id": 123}) # Different reference
}