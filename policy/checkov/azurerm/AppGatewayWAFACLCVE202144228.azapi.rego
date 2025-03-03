package checkov

import rego.v1

valid_azurerm_web_application_firewall_policy_cve_2021_44228_azapi(resource) if {
    managed_rules := resource.properties.managedRules.managedRuleSets
    some i, rule_set in managed_rules {
        rule_set.ruleSetType == "OWASP"
        rule_set.ruleSetVersion == "3.1" || rule_set.ruleSetVersion == "3.2"
        rule_overrides := rule_set.ruleGroupOverrides
        not contains_disabled_rule_944240_azapi(rule_overrides)
    }
}

contains_disabled_rule_944240_azapi(rule_overrides) if {
    some k, rule_override in rule_overrides {
        rule_override.ruleGroupName == "REQUEST-944-APPLICATION-ATTACK-JAVA"
        disabled_rules := rule_override.disabledRules
        some l, disabled_rule in disabled_rules {
            disabled_rule == "944240"
        }
    }
}

deny_CKV_AZURE_135_azapi contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    resource.type == "Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/2024-05-01"
    not valid_azurerm_web_application_firewall_policy_cve_2021_44228_azapi(resource)

    reason := sprintf("checkov/CKV_AZURE_135: Ensure Application Gateway WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGatewayWAFACLCVE202144228.py")
}
