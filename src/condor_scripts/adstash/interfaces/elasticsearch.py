# Copyright 2022 HTCondor Team, Computer Sciences Department,
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

import json
import random
import logging

from operator import itemgetter
from collections import defaultdict

try:
    import elasticsearch
    from elasticsearch import VERSION as ES_VERSION
    _ES_MODULE_FOUND = True
except ModuleNotFoundError as err:
    _ES_MODULE_FOUND = False
    _ES_MODULE_NOT_FOUND_ERROR = err

from adstash.utils import get_host_port
from adstash.interfaces.generic import GenericInterface

ES8 = (8,0,0)
if _ES_MODULE_FOUND and (ES_VERSION < (7,0,0) or ES_VERSION >= (9,0,0)):
    logging.warning(f"Unsupported Elasticsearch Python library {ES_VERSION}, proceeding anyway...")


class ElasticsearchInterface(GenericInterface):


    def __init__(
            self,
            host="localhost",
            port="9200",
            url_prefix="",
            username=None,
            password=None,
            use_https=False,
            ca_certs=None,
            timeout=60,
            _check_for_module=True,
            **kwargs
            ):
        if _check_for_module and not _ES_MODULE_FOUND:  # raise module not found error if missing
            raise _ES_MODULE_NOT_FOUND_ERROR
        self.host, self.port = get_host_port(host, port)
        self.url_prefix = url_prefix or ""
        self.username = username
        self.password = password
        self.use_https = use_https
        self.ca_certs = ca_certs
        self.timeout = timeout
        self.handle = None
        super().__init__(**kwargs)


    def get_handle(self) -> elasticsearch.Elasticsearch:
        """
        Set up the Elasticsearch client if needed.
        """
        if self.handle is not None:
            return self.handle

        client_options = {}

        if ES_VERSION < ES8:
            client_options["hosts"] = [{
                "host": self.host,
                "port": self.port,
                "url_prefix": self.url_prefix,
                "use_ssl": self.use_https,
                }]
        elif ES_VERSION >= ES8:
            client_options["hosts"] = f"""http{"s" * self.use_https}://{self.host}:{self.port}/{self.url_prefix}"""

        if (self.username is None) and (self.password is None):
            pass  # anonymous auth
        elif (self.username is None) != (self.password is None):
            logging.warning("Only one of username and password have been defined, attempting anonymous connection to Elasticsearch")
        else:  # basic auth
            auth_tuple = (self.username, self.password,)
            if ES_VERSION < ES8:
                client_options["http_auth"] = auth_tuple
            elif ES_VERSION >= ES8:
                client_options["basic_auth"] = auth_tuple

        if self.ca_certs is not None:
            client_options["ca_certs"] = self.ca_certs
        if self.use_https:
            client_options["verify_certs"] = True

        client_options["timeout"] = self.timeout

        self.handle = elasticsearch.Elasticsearch(**client_options)
        return self.handle


    def get_active_index(self, alias: str) -> str:
        client = self.get_handle()
        try:
            indices = client.indices.get_alias(name=alias)
        except elasticsearch.exceptions.NotFoundError:
            logging.info(f"{alias} is not an alias, assuming {alias} is the active index")
            return alias

        # find which index is reporting as writable
        for index, alias_info in indices.items():
            if alias_info["aliases"][alias].get("is_write_index"):
                logging.info(f"{alias} is an alias, found active index {index}.")
                return index

        # fallback to lexigraphically last index
        indices = list(indices.keys())
        indices.sort(reverse=True)
        logging.warning(f"Could not find an activate index for alias {alias}, trying {indices[0]}")
        return indices[0]


    def get_mappings(self, index: str) -> dict:
        """
        Fetch the existing mappings for an index
        """
        client = self.get_handle()
        return client.indices.get_mapping(index=index)[index]["mappings"]


    def get_settings(self, index: str) -> dict:
        """
        Fetch the existing settings for an index
        """
        client = self.get_handle()
        return client.indices.get_settings(index=index)[index]["settings"]


    def update_mappings(self, index: str, mappings: dict, **kwargs):
        """
        Given an index and mappings, push the new mapping to the index
        """
        client = self.get_handle()

        logging.info(f"Updating mappings for index {index}")
        logging.debug(json.dumps(mappings, indent=2))
        if ES_VERSION < ES8:
            client.indices.put_mapping(index=index, body=json.dumps(mappings))
        elif ES_VERSION >= ES8:
            client.indices.put_mapping(index=index, **mappings)
        if self.log_mappings and self.log_dir:
            mappings_file = self.log_dir / "condor_adstash_elasticsearch_last_mappings.json"
            logging.debug(f"Writing updated mappings to {mappings_file}.")
            json.dump(mappings, open(mappings_file, "w"), indent=2)


    def make_bulk_body(self, docs: list, metadata={}) -> str:
        """
        Elasticsearch supports bulk indexing via NDJSON, where
        an action (e.g. "index") is followed by the data object
        being acted upon.
        https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk
        """
        body = []
        for doc_id, doc in docs:
            doc.update(metadata)  # bolt on the metadata
            action = {"index": {"_id": doc_id}}  # index the doc w/ this id
            body.append(json.dumps(action))
            body.append(json.dumps(doc))
        return "\n".join(body)


    def get_error_count(self, result: dict) -> int:
        """
        Crawl through the result from the bulk API,
        print out any errors,
        and return the number of errors encountered.
        https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk#operation-bulk-200
        """
        if not result["errors"]:
            return 0

        n_errors = 0
        error_types = defaultdict(int)
        error_reasons = []
        for item in result["items"]:
            try:
                error = item["index"]["error"]
                n_errors += 1
            except (KeyError, TypeError):
                continue
            try:
                error_reasons.append(error["reason"])
            except (KeyError, TypeError):
                pass
            try:
                error_type = error["type"]
            except (KeyError, TypeError):
                error_type = "unknown"
            error_types[error_type] += 1

        error_type_list = list(error_types.items())
        error_type_list.sort(key=itemgetter(1), reverse=True)
        error_type_strs = []
        for (error_type, n) in error_type_list[:3]:
            error_type_strs.append(f"{error_type} ({n} times)")
        logging.error(f"{n_errors} errors encountered during bulk index.")
        logging.error(f"""Most common error type(s): {", ".join(error_type_strs)}.""")
        try:
            logging.error(f"""Example reason: {random.choice(error_reasons)}.""")
        except IndexError:
            pass

        return n_errors


    def post_ads(self, ads: list, index: str, metadata={}, **kwargs) -> dict:
        """
        Push a list of JSON-ified ads in the format
        [(doc_id, ad), (doc_id, ad), ...]
        to the given Elasticsearch index.
        """
        client = self.get_handle()

        body = self.make_bulk_body(ads, metadata)
        result = client.bulk(body=body, index=index)
        n_errors = self.get_error_count(result)
        return {"success": len(ads)-n_errors, "error": n_errors}
