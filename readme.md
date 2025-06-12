# Azure Rego Policies

This repository contains some [Rego](https://www.openpolicyagent.org/) policy files designed for Azure, both AzureRM and AzAPI. The policy files are structured as follows:

## How to use it

To use these policies, you can use the [Conftest](https://www.conftest.dev/) tool. You can use the following command to run the policies against your Terraform plan:

```bash
conftest test --all-namespaces --update git::https://github.com/Azure/policy-library-avm.git//policy <path-to-tfplan>
```

To generate a Terraform plan file:

```bash
terraform plan -out=tfplan.binary && terraform show -json tfplan.binary > tfplan.json
```

Or you can use this library against the brown field infrastructure:

```bash
terraform show -json > state.json
conftest test --all-namespaces --update git::https://github.com/Azure/policy-library-avm.git//policy state.json
```

## Supported Policies

[Azure-Proactive-Resiliency-Library-v2](policy/Azure-Proactive-Resiliency-Library-v2/readme.md)
[Azure Verified Module Security Ruleset](policy/avmsec/readme.md)

### Special Thanks

`avmsec`(Azure Verified Module Security Ruleset) are inspired by builtin rules come from [BridgeCrew Checkov](https://github.com/bridgecrewio/checkov/).

## Apply(skip) policies

To apply a subset of policies, you can specify the policy folders you want to apply, e.g.:

```Bash
conftest test --all-namespaces --update git::https://github.com/Azure/policy-library-avm.git//policy/Azure-Proactive-Resiliency-Library-v2 <path-to-tfplan>
```

This will only apply the policies under `Azure-Proactive-Resiliency-Library-v2`.

To apply `avmsec` policies:

```Bash
conftest test --all-namespaces --update git::https://github.com/Azure/policy-library-avm.git//policy/avmsec <path-to-tfplan>
```

To skip a subset of policies, you can create an exception rego file, e.g.:

```rego
package Azure_Proactive_Resiliency_Library_v2

import rego.v1

exception contains rules if {
  rules = ["use_nat_gateway_instead_of_outbound_rules_for_production_load_balancer", "storage_accounts_are_zone_or_region_redundant"]
}
```

Save it to `exception.rego`, then you can apply the exception file with the policies:

```Bash
conftest test --all-namespaces --update git::https://github.com/Azure/policy-library-avm.git//policy/Azure-Proactive-Resiliency-Library-v2 -p policy -p exception.rego <path-to-tfplan>
```

`avmsec` has four severity levels: `high`, `medium`, `low` and `info`. To apply only `high` severity policies, please compose the exception file like this:

````Rego
package avmsec

import rego.v1

# Skip all policies except high severity
exception contains rules if {
  rules = rules_below_high
}
````

To apply `high` and `medium` severity policies, please compose the exception file like this:

```Rego
package avmsec

import rego.v1

# Skip all policies except high severity
exception contains rules if {
  rules = rules_below_medium
}
```

## Contribution

All contribution are welcome.

All policies **MUST** provide both `azurerm` and `azapi` providers at best effort. Mixed use of `azurerm` and `azapi` is not considered.

To contribute Azure-Proactive-Resiliency-Library-v2 rule, please follow the structure below:

```text
.
├── common
├── ruleset1
│       ├── provider1
│       └── provider2
└── ruleset2
    ├── provider1
    └── provider2
```

The policy files are grouped by ruleset, then provider. Now `azurerm` policies should be further grouped by service folder as [`terraform-provider-azurerm`](https://github.com/hashicorp/terraform-provider-azurerm/tree/main/internal/services).

To contribute `avmsec` rule, please put policy files for `azurerm` and `azapi` together, add `azapi` in file extension name.

All shared util code **MUST** be stored in `common` folder, and must provide 100% coverage unit tests.

Each rego file **MUST** has a corresponding `xxx.mock.json` file. The mock JSON file should contain a top-level key named "mock", which maps to a dictionary. This dictionary can have keys "valid" and "invalid", each mapping to another dictionary of test cases.

Example structure for mock JSON files:

```json
{
  "mock": {
    "valid": {
      "case1": {...},
      "case2": {...}
    },
    "invalid": {
      "case1": {...},
      "case2": {...}
    }
  }
}
```

Alternatively, you can put all cases under the `mock` key directly:

```json
{
  "mock": {
    "case1": {...},
    "invalid_case2": {...}
  }
}
```

Any keys other than `valid` and `invalid` would be treated as a single case, any single cases without invalid prefix would be considered as a valid case.

To contribute a new policy, you **MUST** provide at least one valid case.

All policies **MUST** support both `azurerm` and `azapi` providers.

## Use unique rule name as `deny` rule name

Please do:

```rego
deny_migrate_to_application_gateway_v2 contains reason if {
    resource := data.utils.resource(input, "azurerm_application_gateway")[_]
    not valid_azurerm_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_application_gateway` must have 'sku.name' set to 'Standard_v2' or 'WAF_v2': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2", [resource.address])
}
```

Please **DO NOT**:

```rego
deny contains reason if {
    resource := data.utils.resource(input, "azurerm_application_gateway")[_]
    not valid_azurerm_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_application_gateway` must have 'sku.name' set to 'Standard_v2' or 'WAF_v2': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2", [resource.address])
}
```

These rule names could be used in [`exceptions`](https://www.conftest.dev/exceptions/) so users could skip the check for specific resources.

## Make your helper function name unique

As we are using rule name as package name suffix, we need to make sure the helper function name is unique. Please use the helper function name unique, the provider name could help here:

```rego
valid_azapi_cosmosdb_account_backup_policy_type(resource) if {
    resource.values.body.properties.backupPolicy.type == "Continuous"
}
```

## Do not use `input` directly in your policy

According to the [HashiCorp's OPA policies document](https://github.com/aws-samples/aws-infra-policy-as-code-with-terraform):

>The run data contains information like workspace details and the organization name. To access the properties from the Terraform plan data in your policies, use `input.plan`. To access properties from the Terraform run, use `input.run`.

Unlike Terraform plan file, the actual plan on HCP Terraform are wrapped in `input.plan`, so you **MUST** use `resource := data.utils.resource(input, "azurerm_postgresql_flexible_server")[_]` to get the actual plan object.

## Don't forget to update the README

Please update the README file to include the new policy in [#Supported Policies](#supported-policies) section.