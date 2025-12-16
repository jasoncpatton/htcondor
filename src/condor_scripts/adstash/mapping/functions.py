# Copyright 2025 HTCondor Team, Computer Sciences Department,
# University of Wisconsin-Madison, WI.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

from collections import OrderedDict


def get_ignore_attrs(custom_mappings={}, custom_ignore_attrs=set(), default_ignore_attrs=set()) -> set:
    # First, duplicate lowercase version of defaults
    ignore_attrs = default_ignore_attrs | {attr.lower() for attr in default_ignore_attrs}
    # Then, do not ignore any attrs that have been defined in the custom mappings
    ignore_attrs = ignore_attrs - custom_mappings.get("properties", {}).keys()
    # Then, do ignore any attrs that have been specifically configured
    ignore_attrs = ignore_attrs | custom_ignore_attrs
    return ignore_attrs


def flatten_mapping_properties(properties: dict, parent="") -> dict:
    flattened_properties = {}
    for k, v in properties.items():
        if parent:
            k = f"{parent}.{k}"
        if "properties" in v:
            flattened_properties.update(flatten_mapping_properties(v.pop("properties"), k))
        flattened_properties[k] = v
    return flattened_properties


# Merging will add multi-fields where possible when there are conflicts.
# Ideally, this function's arguments are in order of:
# 1. Existing properties (since existing mappings cannot be mutated)
# 2. Custom properties
# 3. Default properties
def merge_properties(*properties_in: dict) -> dict:
    if len(properties_in) < 2:
        raise ValueError("merge_proprties requires at least two dicts")

    properties_out = {}

    # Start with properties from the first argument
    flattened_properties_in = flatten_mapping_properties(properties_in[0])
    properties_out.update(flattened_properties_in)

    # Merge the other properties, adding multi-fields when possible if there are conflicts
    for property_in in properties_in[1:]:
        flattened_properties_in = flatten_mapping_properties(property_in)
        for field, mapping in flattened_properties_in.items():
            new_field_type = mapping.get("type", "object")

            # Add the field if it doesn't exist yet
            if field not in properties_out:
                properties_out[field] = mapping
                continue

            existing_field_type = properties_out[field].get("type", "object")

            # If the fields have the same type, merge additional properties
            if new_field_type == existing_field_type:
                for key, value in mapping.items():
                    properties_out[field][key] = value
                continue

            # If the new or existing field types are object or nested, skip it
            if {existing_field_type, new_field_type} & {"object", "nested"}:
                logging.error(f"Field {field} is already set to {existing_field_type}, could not set field to type {new_field_type} or add multi-fields")
                continue

            # Check for existing multi-field definitions
            if "fields" in properties_out[field]:

                # Ignore if this multi-field already exists
                if new_field_type in properties_out[field]["fields"]:
                    continue

                # Add the mapping to the existing mutli-fields
                properties_out[field]["fields"][new_field_type] = mapping

            else:
                # Add multi-fields to this field (with same name as the field type) and add the mapping
                properties_out[field]["fields"] = {new_field_type: mapping}

    return properties_out


# Dynamic templates are evaluated in order, and once a
# template matches a field, the rest are ignored for that field.
# The catchall "DEFAULT" template should always be last.
def merge_dynamic_templates(default_dts, custom_dts) -> list:
    dts_out = OrderedDict()

    # Updating an OrderedDict puts any new values at the bottom,
    # so the order here matters. Try to match default templates
    # first, then custom templates, and make sure the DEFAULT
    # template is last.
    dts_out.update(default_dts)
    dt_default = dts_out.pop("DEFAULT", None)

    for key, value in custom_dts.items():
        if key == "DEFAULT":
            dts_out["CUSTOM_DEFAULT"] = value
        else:
            dts_out[key] = value

    if dt_default is not None:
        dts_out["DEFAULT"] = dt_default

    # Return a list that can be turned into JSON
    return [{dt_name: dt} for dt_name, dt in dts_out.items()]


# This will estimate the number of fields based on the
# explicit mapping properties defined, including subfield
# mappings.
def count_total_fields(mapping) -> int:
    count = 0
    flattened_properties = flatten_mapping_properties(mapping["properties"])
    for prop in flattened_properties.values():
        count += 1
        if "fields" in prop:
            count += len(prop["fields"])
    return count


def get_default_mapping_properties(ad_type) -> dict:
    properties = {
        field: field_type for field, field_type in
            [(field, {"type": "text"}) for field in ad_type.INDEXED_TEXT_ATTRS] +
            [(field, {"type": "text", "norms": "false", "index": "false"}) for field in ad_type.NON_INDEXED_TEXT_ATTRS] +
            [(field, {"type": "keyword", "ignore_above": ad_type.MAX_KEYWORD_LEN}) for field in ad_type.INDEXED_KEYWORD_ATTRS] +
            [(field, {"type": "keyword", "index": "false", "ignore_above": ad_type.MAX_KEYWORD_LEN}) for field in ad_type.NON_INDEXED_KEYWORD_ATTRS] +
            [(field, {"type": "double"}) for field in ad_type.FLOAT_ATTRS] +
            [(field, {"type": "long"}) for field in ad_type.INT_ATTRS] +
            [(field, {"type": "date", "format": "epoch_second"}) for field in ad_type.DATE_ATTRS] +
            [(field, {"type": "boolean"}) for field in ad_type.BOOL_ATTRS] +
            [(field, {"type": "object", "dynamic": True}) for field in ad_type.OBJECT_ATTRS] +
            [(field, {"type": "nested", "dynamic": True}) for field in ad_type.NESTED_ATTRS]
    }
    properties.update(ad_type.METADATA_MAPPING)
    return properties


def get_default_mappings(ad_type) -> dict:
    mappings = {
        "properties": get_default_mapping_properties(ad_type),
        "dynamic_templates": ad_type.DYNAMIC_TEMPLATES,
        **ad_type.OTHER_MAPPING_SETTINGS,
    }
    return mappings
