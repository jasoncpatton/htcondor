import logging
import json

from pathlib import Path

from adstash.mapping import count_total_fields

DEFAULT_SETTINGS = {
    "index": {
        "mapping": {
            "ignore_malformed": True,  # https://www.elastic.co/guide/en/elasticsearch/reference/7.17/ignore-malformed.html#ignore-malformed-setting
        },
        "refresh_interval": "30s",  # https://www.elastic.co/guide/en/elasticsearch/reference/7.17/tune-for-indexing-speed.html#_unset_or_increase_the_refresh_interval
    }
}

DEFAULT_ILM_POLICY = {
    "policy": {
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {
                    "rollover": {
                        "max_size": "50gb",  # 50gb segments
                        "max_age": "120d"  # rollover approx. quarterly
                    },
                    "set_priority": {
                        "priority": 100
                    }
                }
            },
            "warm": {
                "min_age": "100d",  # rollover approx. quarterly
                "actions": {
                    "forcemerge": {
                        "max_num_segments": 1  # merge down to single segment
                    }
                }
            },
            "cold": {
                "min_age": "400d",  # rollover after approx. year
                "actions": {
                    "set_priority": {
                        "priority": 0
                    }
                }
            }
        }
    }
}


class SearchEngineSettings():

    def __init__(self, index_name, mappings, custom_settings={}, existing_settings={}, custom_ilm_policy={}):
        self.alias = index_name
        self.mappings = mappings
        self.settings = self.merge_settings(DEFAULT_SETTINGS, existing_settings, custom_settings)
        self.update_settings_fields_limit()
        self.ilm_policy = custom_ilm_policy or DEFAULT_ILM_POLICY
        self.ilm_policy_name = f"{index_name}-ilm"
        self.index_template_name = f"{index_name}-template"

    def flatten_settings(self, settings={}, parent=""):
        flattened_settings = {}
        for k, v in settings.items():
            if parent:
                k = f"{parent}.{k}"
            if isinstance(v, dict):
                flattened_settings.update(self.flatten_settings(v, k))
                continue
            flattened_settings[k] = v
        return flattened_settings

    def merge_settings(self, *settings_list):
        merged_settings = {}
        for settings in settings_list:
            merged_settings.update(self.flatten_settings(settings))
        return merged_settings

    def get_index_template(self):
        index_template = {
            "index_patterns": [f"{self.alias}-*"],
            "template": {
                "settings": self.settings,
                "mappings": self.mappings,
            }
        }
        return index_template

    def update_settings_fields_limit(self):
        self.settings["index.mapping.total_fields.limit"] = 2 * count_total_fields(self.mappings)

    def write_index_settings(self, output_directory=Path(), use_alias=True, use_ilm=True, use_template=True):
        index = {}
        files = {}

        if use_ilm:
            if not use_alias:
                raise RuntimeError("Use of ILM requires using aliases for rollover")
            if not use_template:
                logging.warning(f"Recommend use of index templates when using ILM to preserve")
                logging.warning(f"setttings and mappings after rollovers.")
            self.settings["index.lifecycle.name"] = self.ilm_policy_name
            self.settings["index.rollover_alias"] = self.alias
            files["ilm"] = {"name": f"{self.ilm_policy_name}.json", "contents": self.ilm_policy}

        if use_template:
            if not use_alias:
                logging.warning(f"Recommend use of aliases when using index templates.")
                logging.warning(f"Assuming that the index match pattern is {self.alias}-*.")
            template = self.get_index_template()
            files["template"] = {"name": f"{self.alias}-template.json", "contents": template}
        else:
            index["settings"] = self.settings
            index["mappings"] = self.mappings

        if use_alias:
            index["aliases"] = {self.alias: {"is_write_index": True}}
            index_name = f"{self.alias}-000001"
        else:
            index_name = self.alias
        files["index"] = {"name": f"{index_name}.json", "contents": index}

        logging.warning(f"Writing out JSON files and README instructions for setting up your index to {output_directory}")
        if not output_directory.exists():
            logging.warning(f"{output_directory} does not exist, creating it for you")
            output_directory.mkdir(parents=True)

        readme = {
            "ilm": f"""ILM policy ({{filename}}) should be PUT to _ilm/policy/{self.ilm_policy_name}
See: https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ilm-put-lifecycle
ILM policy can be changed later!""",
            "template": f"""index template ({{filename}}) should be PUT to _index_template/{self.index_template_name}
See: https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-indices-put-index-template""",
            "index": f"""initial index ({{filename}}) should be PUT to {index_name}
See: https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-indices-create"""
        }
        readme_path = output_directory / "README"
        if readme_path.exists():
            raise IOError(f"{readme_path} already exists, please specify an empty directory.")
        with readme_path.open("w") as f:
            if len(files) > 1:
                f.write("""IMPORTANT: These operations should be done in order!
Failure to do so may result in templates and ILM policies not applying.\n\n""")
            for obj_type in ["ilm", "template", "index"]:
                if obj_type in files:
                    f.write(readme[obj_type].format(filename=files[obj_type]["name"]))
                    f.write("\n\n")

        for obj in files.values():
            file_path = output_directory / obj["name"]
            if file_path.exists():
                raise IOError(f"{file_path} already exists, please specify an empty directory.")
            with file_path.open("w") as f:
                json.dump(obj["contents"], f, indent=2)

        logging.warning(f"Index setup files written to {output_directory}")
