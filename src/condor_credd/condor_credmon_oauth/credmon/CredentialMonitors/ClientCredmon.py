
import random
import time

from urllib.parse import quote

import requests

from credmon.CredentialMonitors.LocalCredmon import LocalCredmon


class ClientCredmon(LocalCredmon):
    """
    A CredMon class that uses the OAuth2 Client Credentials flow for
    acquiring access tokens
    """

    @property
    def credmon_name(self):
        return "CLIENT"

    def __init__(self, *args, **kwargs):
        super(ClientCredmon, self).__init__(*args, **kwargs)
        self._token_endpoint = ""
        self._token_endpoint_resolved = 0
        self._token_endpoint_lifetime = int(self.get_credmon_config("TOKEN_ENDPOINT_LIFETIME", "3600")) + random.randint(0, 60)

        self.client_id = self.get_credmon_config("CLIENT_ID")
        if not self.client_id:
            raise RuntimeError(f"{self.credmon_name}_CREDMON_{self.provider}_CLIENT_ID configuration parameter must be set to use the client credential credmon")
        secret_file = self.get_credmon_config("CLIENT_SECRET_FILE")
        if not secret_file:
            raise RuntimeError(f"{self.credmon_name}_CREDMON_{self.provider}_CLIENT_SECRET_FILE configuration parameter must be set to use the client credential credmon")

        with open(secret_file) as fp:
            self._secret = fp.read().strip()

        if not self._secret:
            raise RuntimeError(f"Client credentials flow credmon configured with an empty secret file ({self.credmon_name}_CREDMON_{self.provider}_CLIENT_SECRET_FILE)")


    @property
    def token_endpoint(self):
        """
        Determine the token endpoint from the static configuration or dynamically from
        OIDC metadata discovery
        """
        endpoint = self.get_credmon_config("TOKEN_URL")
        if endpoint:
            return endpoint

        if self._token_endpoint and (self._token_endpoint_resolved + self._token_endpoint_lifetime > time.time()):
            return self._token_endpoint

        resp = requests.get(self.token_issuer + "/.well-known/openid-configuration")
        if resp.status_code != 200:
            msg = f"When performing OIDC metadata discovery, {self.token_issuer} responded with {resp.status_code}"
            self.log.error(msg)
            if self._token_endpoint:
                return self._token_endpoint
            raise RuntimeError(msg)

        try:
            resp_json = resp.json()
        except ValueError:
            msg = f"When performing OIDC metadata discovery, {self.token_issuer} had non-JSON response: {resp.text[:10]}..."
            self.log.error(msg)
            if self._token_endpoint:
                return self._token_endpoint
            raise

        if 'token_endpoint' not in resp_json:
            msg = f"When performing OIDC metadata discovery, {self.token_issuer} response lacked the `token_endpoint` key"
            self.log.error(msg)
            if self._token_endpoint:
                return self._token_endpoint
            raise RuntimeError(msg)

        self._token_endpoint = resp_json["token_endpoint"]
        self._token_endpoint_resolved = time.time()
        self.log.info(f"Resolved token endpoint of '{self._token_endpoint}' for issuer {self.token_issuer}")
        return self._token_endpoint


    def refresh_access_token(self, username, token_name):
        """
        Execute the client credentials flow with the remote token endpoint.

        If successful, write the access token to disk.
        """

        token_info = self.generate_access_token_info(username, token_name)

        scope_list = token_info.scopes
        if token_info.profile in {"wlcg", "wlcg:1.0"}:
            scope_list.append("wlcg")
        if token_info.sub:
            scope_list.append(f"condor.user:{quote(token_info.sub)}")

        payload = {
            "client_id": self.client_id,
            "grant_type": "client_credentials",
        }

        if scope_list:
            payload["scopes"] = " ".join(scope_list)
        if token_info.audience:
            payload["audience"] = " ".join(token_info.audience)

        self.log.debug(f"Requesting token from {self.token_endpoint} with following payload: {payload}")

        payload["client_secret"] = self._secret
        resp = requests.post(self.token_endpoint, data=payload)
        del payload["client_secret"]

        if resp.status_code != 200:
            self.log.error(f"HTTP status failure ({resp.status_code}) when requesting token from {self.token_endpoint} with payload {payload}")
            return False

        try:
            resp_json = resp.json()
        except ValueError:
            self.log.error(f"Token issuer {self.token_issuer} failed to have a valid JSON response: {resp.text[:10]}")
            return False

        access_token = resp_json.get("access_token")
        if not access_token:
            self.log.error(f"Token issuer {self.token_issuer} failed to respond with an access token")
            return False

        lifetime = resp_json.get("expires_in")
        if not lifetime:
            self.log.warning(f"Token issuer {self.token_issuer} failed to indicate when access token will expire; assuming {self.token_lifetime}")

        return self.write_access_token(username, token_name, lifetime, access_token, serialized=False)

