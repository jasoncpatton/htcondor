# Copyright 2021 HTCondor Team, Computer Sciences Department,
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

import re
import json
import time
import logging

from functools import lru_cache
from collections import defaultdict, OrderedDict

from adstash.mapping import MAX_KEYWORD_LEN, IGNORE_ATTRS, REQUIRED_ATTRS, TIMESTAMP_ATTRS, DOC_ID_ATTRS

import classad2 as classad


STATUS = {
    0: "Unexpanded",
    1: "Idle",
    2: "Running",
    3: "Removed",
    4: "Completed",
    5: "Held",
    6: "Error",
}

UNIVERSE = {
    1: "Standard",
    2: "Pipe",
    3: "Linda",
    4: "PVM",
    5: "Vanilla",
    6: "PVMD",
    7: "Scheduler",
    8: "MPI",
    9: "Grid",
    10: "Java",
    11: "Parallel",
    12: "Local",
}


_LAUNCH_TIME = int(time.time())


def strict_bool(i):
    if isinstance(i, bool):
        return bool(i)
    if isinstance(i, str):
        if str(i).lower() in {"1", "t", "true"}:
            return True
        if str(i).lower() in {"0", "f", "false"}:
            return False
    if isinstance(i, (int, float)):
        if abs(i - 1) < 1e-8:  # allow for some tiny error
            return True
        if abs(i) < 1e-8:
            return False
    raise ValueError(f"The truth value of {i} is ambiguous")


FIELD_TYPE_MAP = {
    "text": str,
    "keyword": str,
    "double": float,
    "long": int,
    "date": int,
    "boolean": strict_bool,
    "object": dict,
    "nested": list,
}


class ClassAdConverter():

    def __init__(
            self,
            mapping={},
            projection=set(),
            ignore_attrs=IGNORE_ATTRS,
            required_attrs=REQUIRED_ATTRS,
            timestamp_attrs=TIMESTAMP_ATTRS,
            doc_id_attrs=DOC_ID_ATTRS,
            ):
        self.mapping = mapping
        self.ignore_attrs = ignore_attrs
        self.timestamp_attrs = timestamp_attrs
        self.doc_id_attrs = doc_id_attrs
        if len(projection) > 0:
            self.projection = {attr.lower() for attr in projection | required_attrs}
        else:
            self.projection = None
        self.known_field_types = self.get_known_field_types(self.mapping)
        self.dynamic_templates_matchers = self.get_dynamic_template_matchers(self.mapping)

    def get_known_field_types(self, mapping, parent_field_names=[]):
        '''
        Build up a map of sets of known field names and types,
        keyed on the lowercased attribute names. For example,
        if "lastremotewallclocktime" and "LastRemoteWallClockTime"
        are both defined in the mapping as keyword and long,
        respectively, the map should include:
        {
            ...
            "lastremotewallclocktime": {
                ("lastremotewallclocktime": str),
                ("LastRemoteWallClockTime": int),
            }
            ...
        }

        Also flatten any objects' subproperty names, e.g.:
        {
            ...
            "numholdsbyreason.failedtocheckpoint": {
                ("NumHoldsByReason.FailedToCheckpoint": int),
            }
            ...
        }
        '''
        known_field_types = defaultdict(set)
        for base_field_name, field_properties in mapping["properties"].items():
            field_name_heirarchy = parent_field_names + [base_field_name]
            flattened_field_name = ".".join(field_name_heirarchy)
            if self.projection is not None and flattened_field_name.lower() not in self.projection:
                continue
            field_type = FIELD_TYPE_MAP[field_properties.get("type", "object")]
            known_field_types[flattened_field_name.lower()].add((flattened_field_name, field_type,))
            if field_type is dict and "properties" in field_properties:
                known_field_types = known_field_types | self.get_known_field_types(field_properties, field_name_heirarchy)
        return known_field_types

    def get_dynamic_template_matchers(self, mapping):
        matchers = OrderedDict()
        for dt_name, dt in mapping.get("dynamic_templates", {}).items():
            match_type = "wildcard"
            match_pattern = dt.get("match", "")
            if dt.get("match_pattern") == "regex":
                match_type = "regex"
                match_pattern = re.compile(dt.get("match", r"^$"))
            elif dt_name == "DEFAULT":
                match_type = "default"
                match_pattern = ""
            matchers[dt_name] = {
                "match_type": match_type,
                "match_pattern": match_pattern,
                "field_type": FIELD_TYPE_MAP[dt.get("mapping", {}).get("type", "keyword")],
            }
        return matchers

    @lru_cache(maxsize=2048)
    def map_unknown_field_type(self, attr):
        '''
        Test to see if attr fits any dynamic templates,
        otherwise fall back to whatever the "DEFAULT"
        dynamic template is. Always return the *first*
        match (if any).
        '''
        field_name = attr.lower()  # fallback to lowercase attr name if no match
        field_type = self.dynamic_templates_matchers["DEFAULT"]["field_type"]
        for dt_name, dt in self.dynamic_templates_matchers.items():
            if dt["match_type"] == "regex" and dt["match_pattern"].match(attr):
                field_name = attr
                field_type = dt["field_type"]
                logging.info(f"Attr {attr} matched dynamic template {dt_name}")
                break
            if dt["match_type"] == "wildcard":
                left, right = dt["match_pattern"].split("*", maxsplit=1)
                if attr.startswith(left) and attr.endswith(right):
                    field_name = attr
                    field_type = dt["field_type"]
                    logging.info(f"Attr {attr} matched dynamic template {dt_name}")
                    break
        return field_name, field_type

    @lru_cache(maxsize=2048)
    def warn_once(self, msg):
        '''
        Only print the same warning once every 2048 instances.
        '''
        logging.warning(msg)

    def convert_attr_to_dict(self, attr, value, full_ad):
        doc = {}

        # 1. Get the field name and field type mappings if known
        known_mappings = True
        field_names_types = dict(self.known_field_types[attr.lower()])

        # 2. Get the field name and field type mappings if unknown
        if not field_names_types:
            self.warn_once(f"Looking up {attr}")
            known_mappings = False
            field_names_types = dict([self.map_unknown_field_type(attr)])

        # 3. Map attr to all matching fields
        for field_name, field_type in field_names_types.items():

            field_value = None

            # 4. Handle objects separately
            if isinstance(value, (dict, classad.ClassAd)):

                # Make sure the mapping is expected
                if known_mappings and field_type is not dict:
                    self.warn_once(f"Could not convert {field_name} to {field_type}, got a dict-like")
                    continue

                # If we know this to be a string, try to make it a JSON blob
                if known_mappings and field_type is str:
                    if isinstance(value, classad.ClassAd):
                        try:
                            field_value = value.printJson()
                        except Exception:
                            self.warn_once(f"Failed to convert ClassAd object in {attr} to JSON")
                            continue
                    else:
                        try:
                            field_value = json.dumps(value)
                        except Exception:
                            self.warn_once(f"Failed to convert dict-like object in {attr} to JSON")
                            continue

                else:  # Otherwise recursively convert it, flattening the namespace
                    if not known_mappings:  # Preserve original case if we don't know what this is
                        field_name = attr  # because it might match a dynamic template later.
                    doc.update(self.convert_ad_to_dict(value, field_name))
                    continue  # Then at this point, this mapping is already done

            # 5. Handle everything else
            else:

                # Evaluate any ClassAd expressions
                # (in the context of their ad if possible)
                if isinstance(value, classad.ExprTree):
                    try:
                        if isinstance(full_ad, classad.ClassAd):
                            eval_value = value.eval(full_ad)
                        else:
                            eval_value = value.eval()
                    except Exception:
                        self.warn_once(f"Failed to ClassAd eval {attr}")
                        eval_value = classad.Value.Error

                    # If eval doesn't work, store the expr as a string if possible
                    if isinstance(eval_value, (classad.Value, classad.ExprTree)):
                        field_name = f"{field_name}_EXPR"
                        field_type = str
                        try:
                            field_value = field_type(value)
                        except Exception:
                            self.warn_once(f"Failed to get string repr of expr in {attr}")
                            continue
                    else:
                        value = eval_value

                # Prevent Error or Undefined ClassAd values from getting through,
                # for example, classad.Value.Undefined acts a literal 2 for
                # any type casting done on it, which we don't want.
                if isinstance(value, classad.Value):
                    self.warn_once(f"Got ClassAd value {value.name} for {attr}")
                    continue

                try:
                    field_value = field_type(value)
                except Exception:
                    self.warn_once(f"Failed to cast {attr} = {value} as a {field_type.__name__}")
                    continue

            if field_value is None:  # Somehow we didn't get a value? This shouldn't happen.
                self.warn_once(f"Failed to get a value for {attr}")
                continue

            # 6. Truncate strings if necessary
            if isinstance(field_value, str) and len(field_value) > MAX_KEYWORD_LEN:
                field_value = f"{field_value[:MAX_KEYWORD_LEN-3]}..."

            # 7. Store value
            doc[field_name] = field_value

        return doc

    def convert_ad_to_dict(self, ad, parent_attr=""):
        doc = {}

        # 1. Loop over all attrs
        for attr, value in ad.items():

            # 2. Flatten the namespace
            if parent_attr:
                attr = f"{parent_attr}.{attr}"

            # 3. Skip any ignored attrs
            if attr in self.ignore_attrs:
                continue

            # 4. Skip any attrs not in the projection
            if self.projection is not None and attr.lower() not in self.projection:
                continue

            # 5. Convert attr
            doc.update(self.convert_attr_to_dict(attr, value, ad))

        return doc

    def get_timestamp(self, ad, fallback_to_launch=True):
        for timestamp_attr in self.timestamp_attrs:
            if ad.get(timestamp_attr, 0) > 0:
                return ad[timestamp_attr]

        if fallback_to_launch:
            self.warn_once(f"Could not find valid value for any timestamp attr ({', '.join(self.timestamp_attrs)}), falling back to adstash launch date")
            return _LAUNCH_TIME

        self.warn_once(f"Could not find valid value for any timestamp attr ({', '.join(self.timestamp_attrs)}), timestamp will be 0!")
        return 0

    def get_unique_doc_id(self, ad):
        """
        Return a string to uniquely identify documents
        """
        doc_id_list = [v for v in [ad.get(attr) for attr in self.doc_id_attrs] if v is not None]
        return "#".join(doc_id_list)

    def convert_ad_to_doc(self, ad, decorate_job_ad=True):
        if ad.get("TaskType") == "ROOT":
            return None

        # Do the bulk of the conversions
        doc = self.convert_ad_to_dict(ad)

        # Add timestamps
        doc["@timestamp"] = doc["RecordTime"] = self.get_timestamp(ad)

        # Add decorations (only useful for job ads)
        if decorate_job_ad:
            doc["ScheddName"] = ad.get("GlobalJobId", "UNKNOWN").split("#")[0]
            doc["StartdSlot"] = ad.get("RemoteHost", ad.get("LastRemoteHost", "UNKNOWN@UNKNOWN")).split("@")[0]
            doc["StartdName"] = ad.get("RemoteHost", ad.get("LastRemoteHost", "UNKNOWN@UNKNOWN")).split("@")[-1]
            doc["Status"] = STATUS.get(ad.get("JobStatus"), "Unknown")
            doc["Universe"] = UNIVERSE.get(ad.get("JobUniverse"), "Unknown")

        return doc


if __name__ == "__main__":

    from adstash.mapping import get_default_mapping_properties
    from adstash.mapping import merge_properties
    from adstash.mapping import METADATA_MAPPING, DYNAMIC_TEMPLATES

    mappings = {
        "dynamic_templates": DYNAMIC_TEMPLATES,
        "properties": merge_properties(get_default_mapping_properties(), METADATA_MAPPING),
        "date_detection": False,
        "numeric_detection": False,
    }
    converter = ClassAdConverter(mappings)