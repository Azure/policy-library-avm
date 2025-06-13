package utils

import rego.v1

arraycontains(arr, element) := contains if {
    some item in arr
    item == element
    contains := true
} else := false

is_azure_type(resource, azure_type) if {
	regex.match(sprintf("^%s@", [azure_type]), resource.type)
}

is_azure_type(azure_type_array, resource) if {
   t := azure_type_array[_]
   regex.match(sprintf("^%s@", [t]), resource.type)
}

_get_change_after_unknown(r) := output if {
    r.change.after_unknown == r.change.after_unknown
    output := r.change.after_unknown
} else = []

_resource(_input) := output if {
	_input.plan.resource_changes == _input.plan.resource_changes
	output := {
	body |
		r := _input.plan.resource_changes[_]
		body := {
			"address": r.address,
			"values": r.change.after,
			"after_unknown": _get_change_after_unknown(r),
			"mode": r.mode,
			"type": r.type,
		}
	}
}

_resource(_input) := output if {
	_input.resource_changes == _input.resource_changes
	output := {
	body |
		r := _input.resource_changes[_]
		body := {
			"address": r.address,
			"values": r.change.after,
			"after_unknown": _get_change_after_unknown(r),
			"mode": r.mode,
			"type": r.type,
		}
	}
}

_configuration(_input) := output if {
    _input.configuration == _input.configuration
    output := _input.configuration
}

_configuration(_input) := output if {
    _input.plan.configuration == _input.plan.configuration
    output := _input.plan.configuration
}

resource_configuration(_input) := output if {
    configuration := _configuration(_input)
    output :=  {
        address: resource |
        walk(configuration, [path, value])
        value.resources == value.resources
        module_prefix := concat("", [sprintf("module.%s.", [path[i+1]]) | some i; path[i] == "module_calls"])
        res := value.resources[_]
        resource := {
            "address": sprintf("%s%s", [module_prefix, res.address]),
            "module_prefix": module_prefix,
            "mode": res.mode,
            "type": res.type,
            "expressions": res.expressions,
        }
        address := resource.address
    }
}

_resource(_input) := output if {
	_input.values.root_module == _input.values.root_module
	root_resources := [
	    body |
	    	r := _input.values.root_module.resources[_]
	    	body := {
	    		"address": r.address,
	    		"values": r.values,
	    		"mode": r.mode,
	    		"type": r.type,
	    	}
	]
	child_resources := [
	    body |
	        cm := _input.values.root_module.child_modules[_]
	        r := cm.resources[_]
	        body := {
	            "address": r.address,
	            "values": r.values,
                "mode": r.mode,
                "type": r.type,
	        }
	]
	output := array.concat(root_resources, child_resources)
}

resource(_input, resource_type) := [
resource |
	some resource in _resource(_input)
	resource.mode == "managed"
	resource.type == resource_type
]

is_create_or_update(change_actions) if {
	change_actions[count(change_actions) - 1] == ["create", "update"][_]
}

is_resource_create_or_update(resource) if {
	is_create_or_update(resource.change.actions)
}