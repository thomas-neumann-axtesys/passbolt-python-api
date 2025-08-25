import configparser
import datetime
import json
import logging
import urllib.parse
import uuid
from typing import List, Mapping, Optional, Tuple, Union

import gnupg
import requests

from passboltapi.schema import (
    AllPassboltTupleTypes,
    PassboltDateTimeType,
    PassboltFavoriteDetailsType,
    PassboltFolderIdType,
    PassboltFolderTuple,
    PassboltGroupIdType,
    PassboltGroupTuple,
    PassboltOpenPgpKeyIdType,
    PassboltOpenPgpKeyTuple,
    PassboltPermissionIdType,
    PassboltPermissionTuple,
    PassboltResourceIdType,
    PassboltResourceTuple,
    PassboltResourceType,
    PassboltResourceTypeIdType,
    PassboltResourceTypeTuple,
    PassboltRoleIdType,
    PassboltSecretIdType,
    PassboltSecretTuple,
    PassboltUserIdType,
    PassboltUserTuple,
    constructor,
)

LOGIN_URL = "/auth/login.json"
VERIFY_URL = "/auth/verify.json"


class PassboltValidationError(Exception):
    pass


class PassboltError(Exception):
    pass


class APIClient:
    def __init__(
            self,
            config: Optional[str] = None,
            config_path: Optional[str] = None,
            new_keys: bool = False,
            delete_old_keys: bool = False,
            ssl_verify: bool = True,
            cert_auth: bool = False,
            jwt_auth: bool = True
    ):
        """
        :param config: Config as a dictionary
        :param config_path: Path to the config file.
        :param delete_old_keys: Set true if old keys need to be deleted
        """
        self.ssl_verify = ssl_verify
        self.config = config
        self.cert_auth = cert_auth
        self.jwt_auth = jwt_auth
        self.metadata_keys = {}
        self.cert = None
        if config_path:
            self.config = configparser.ConfigParser()
            self.config.read_file(open(config_path))
        self.requests_session = requests.Session()

        if not self.config:
            raise ValueError("Missing config. Provide config as dictionary or path to configuration file.")
        if not self.config["PASSBOLT"]["SERVER"]:
            raise ValueError("Missing value for SERVER in config.ini")

        self.server_url = self.config["PASSBOLT"]["SERVER"].rstrip("/")

        if self.cert_auth:
            if not (self.config["PASSBOLT"]["SERVER_CERT_AUTH_CRT"] and self.config["PASSBOLT"][
                "SERVER_CERT_AUTH_KEY"]):
                raise ValueError("Missing certificate and key in config.ini")
            self.cert = (self.config["PASSBOLT"]["SERVER_CERT_AUTH_CRT"],
                         self.config["PASSBOLT"]["SERVER_CERT_AUTH_KEY"])

        self.user_fingerprint = self.config["PASSBOLT"]["USER_FINGERPRINT"].upper().replace(" ", "")
        self.gpg = gnupg.GPG()
        if delete_old_keys:
            self._delete_old_keys()
        if new_keys:
            self._import_gpg_keys()
        try:
            self.gpg_fingerprint = [i for i in self.gpg.list_keys() if i["fingerprint"] == self.user_fingerprint][0][
                "fingerprint"
            ]
        except IndexError:
            raise Exception("GPG public key could not be found. Check: gpg --list-keys")

        if self.user_fingerprint not in [i["fingerprint"] for i in self.gpg.list_keys(True)]:
            raise Exception("GPG private key could not be found. Check: gpg --list-secret-keys")
        self._login()
        self._get_resource_types()

    def __enter__(self):
        return self

    def __del__(self):
        self.close_session()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close_session()

    def _delete_old_keys(self):
        for i in self.gpg.list_keys():
            self.gpg.delete_keys(i["fingerprint"], True, passphrase="")
            self.gpg.delete_keys(i["fingerprint"], False)

    def _import_gpg_keys(self):
        if not self.config["PASSBOLT"]["USER_PUBLIC_KEY_FILE"]:
            raise ValueError("Missing value for USER_PUBLIC_KEY_FILE in config.ini")
        if not self.config["PASSBOLT"]["USER_PRIVATE_KEY_FILE"]:
            raise ValueError("Missing value for USER_PRIVATE_KEY_FILE in config.ini")
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PUBLIC_KEY_FILE"]).read())
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PRIVATE_KEY_FILE"]).read())

    def _login(self):
        if self.jwt_auth:
            self._login_jwt_auth()
        else:
            self._login_gpg_auth()

    def _login_jwt_auth(self):
        srv_fingerprint, srv_key = self.get_server_public_key()
        if not any(key["fingerprint"] == srv_fingerprint for key in self.gpg.list_keys()):
            self.gpg.import_keys(srv_key)
        if "USER_ID" not in self.config["PASSBOLT"]:
            raise ValueError("Missing value for USER_ID (needed for JWT auth) in config.ini")
        user_id = self.config["PASSBOLT"]["USER_ID"]
        verify_token = str(uuid.uuid4())
        # force https for domain
        domain = self.config["PASSBOLT"]["SERVER"]
        if not domain.startswith("https://"):
            domain = "https://{}".format(domain.lstrip("http://").rstrip("/"))
        challenge = {
            "version": "1.0.0",
            "domain": domain,
            # create a new uuid
            "verify_token": verify_token,
            # unix epoch for challenge expiration
            "verify_token_expiry": str((datetime.datetime.now() + datetime.timedelta(seconds=30)).timestamp())
        }
        enc_challenge = self.gpg.encrypt(
            json.dumps(challenge),
            srv_fingerprint,
            sign=self.gpg_fingerprint,
            passphrase=self._get_passphrase(),
            always_trust=True
        )
        if not enc_challenge.ok:
            raise PassboltError("Encryption failed: " + str(enc_challenge.stderr))
        login_resp = self.requests_session.post(self.server_url + "/auth/jwt/login.json", json={
            "user_id": user_id,
            "challenge": str(enc_challenge),
        }, verify=self.ssl_verify)
        login_resp.raise_for_status()
        if "body" not in login_resp.json():
            raise PassboltError("Login response does not contain 'body' key: " + str(login_resp.json()))
        if "challenge" not in login_resp.json()["body"]:
            raise PassboltError("Login response does not contain 'challenge' key: " + str(login_resp.json()))
        enc_challenge = login_resp.json()["body"]["challenge"]
        decr_challenge = json.loads(str(self.gpg.decrypt(enc_challenge, passphrase=self._get_passphrase())))

        if verify_token != decr_challenge["verify_token"]:
            raise Exception("Verification tokens do not match in JWT auth!")

        self.jwt_auth_token = decr_challenge["access_token"]
        self.jwt_refresh_token = decr_challenge["refresh_token"]

        self.requests_session.headers.update({
            "Authorization": f"Bearer {self.jwt_auth_token}",
        })

    def _login_gpg_auth(self):
        r = self.requests_session.post(self.server_url + LOGIN_URL, json={"gpg_auth": {"keyid": self.gpg_fingerprint}},
                                       verify=self.ssl_verify, cert=self.cert)  # None is the default value in requests
        encrypted_token = r.headers["X-GPGAuth-User-Auth-Token"]
        encrypted_token = urllib.parse.unquote(encrypted_token)
        encrypted_token = encrypted_token.replace(r"\+", " ")
        token = self.decrypt(encrypted_token)
        self.requests_session.post(
            self.server_url + LOGIN_URL,
            json={
                "gpg_auth": {"keyid": self.gpg_fingerprint, "user_token_result": token},
            },
        )
        try:
            self._get_csrf_token()
        except requests.exceptions.HTTPError as e:
            if (
                    e.response.status_code != requests.status_codes.codes.forbidden
                    or e.response.json()["header"]["message"]
                    != "MFA authentication is required."
            ):
                logging.error(r.text)
                raise e
            if not self.config["PASSBOLT"]["OTP"]:
                raise ValueError("Missing value for OTP in config.ini")
            self.post("/mfa/verify/totp.json", {"totp": self.config["PASSBOLT"]["OTP"]})

    def _get_csrf_token(self):
        """Fetches the X-CSRF-Token header for future requests"""
        r = self.requests_session.get(self.server_url + "/users/me.json")
        r.raise_for_status()

    def _get_passphrase(self):
        if "PASSPHRASE" in self.config["PASSBOLT"]:
            passphrase = str(self.config["PASSBOLT"]["PASSPHRASE"])
        else:
            passphrase = None
        return passphrase

    def _get_resource_types(self):
        r = self.get('/resource-types.json')
        types = r["body"]
        self.resource_type_map = {}
        for resource_type in types:
            self.resource_type_map[resource_type["id"]] = PassboltResourceTypeTuple(
                id=resource_type["id"],
                name=resource_type["name"],
                slug=resource_type["slug"],
                definition=resource_type["definition"],
                created=PassboltDateTimeType(resource_type["created"]),
                modified=PassboltDateTimeType(resource_type["modified"]),
                description=resource_type.get("description", ""),
            )
        self.default_resource_type_id = next(
            (rt.id for rt in self.resource_type_map.values() if rt.slug == "v5-default"),
            None
        )

    def _get_metadata_keys(self):
        r = self.get('/metadata/keys.json',
                     params={'contain[metadata_private_keys]': 1})
        r = r["body"]
        pub_keys = []
        priv_keys = []
        for key in r:
            pub_keys.append({
                'armored_key': key['armored_key'],
                'fingerprint': key['fingerprint'],
            })
            for pkey in key["metadata_private_keys"]:
                key_data = json.loads(self.decrypt(pkey['data']))
                self.metadata_keys[pkey["metadata_key_id"]] = {
                    'key_data': key_data,
                    'user_id': pkey['user_id'],
                    'fingerprint': key['fingerprint']
                }
                priv_keys.append(key_data['armored_key'])
        return pub_keys, priv_keys

    def encrypt(self, text, recipients=None):
        res = self.gpg.encrypt(data=text, recipients=recipients or self.gpg_fingerprint, always_trust=True)
        if not res.ok:
            raise PassboltError(f"Encryption failed: {res.stderr}")
        return str(res)

    def decrypt(self, text):
        res = self.gpg.decrypt(text, always_trust=True, passphrase=self._get_passphrase())
        if not res.ok:
            raise PassboltError(f"Decryption failed: {res.stderr}")
        return str(res)

    def get_headers(self):
        return {
            "X-CSRF-Token": self.requests_session.cookies["csrfToken"]
            if "csrfToken" in self.requests_session.cookies
            else ""
        }

    def get_server_public_key(self):
        r = self.requests_session.get(self.server_url + VERIFY_URL, verify=self.ssl_verify)
        return r.json()["body"]["fingerprint"], r.json()["body"]["keydata"]

    def delete(self, url):
        r = self.requests_session.delete(self.server_url + url, headers=self.get_headers())
        try:
            r.raise_for_status()
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def get(self, url, return_response_object=False, **kwargs):
        r = self.requests_session.get(self.server_url + url, headers=self.get_headers(), verify=self.ssl_verify,
                                      **kwargs)
        try:
            r.raise_for_status()
            if return_response_object:
                return r
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def put(self, url, data, return_response_object=False, **kwargs):
        r = self.requests_session.put(self.server_url + url, json=data, headers=self.get_headers(),
                                      verify=self.ssl_verify, **kwargs)
        try:
            r.raise_for_status()
            if return_response_object:
                return r
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def post(self, url, data, return_response_object=False, **kwargs):
        r = self.requests_session.post(self.server_url + url, json=data, headers=self.get_headers(),
                                       verify=self.ssl_verify, **kwargs)
        try:
            r.raise_for_status()
            if return_response_object:
                return r
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def close_session(self):
        self.requests_session.close()


class PassboltAPI(APIClient):
    """Adding a convenience method for getting resources.

    Design Principle: All passbolt aware public methods must accept or output one of PassboltTupleTypes"""

    def _json_load_secret(self, secret: PassboltSecretTuple) -> Tuple[str, Optional[str]]:
        try:
            secret_dict = json.loads(self.decrypt(secret.data))
            return secret_dict["password"], secret_dict["description"]
        except (json.decoder.JSONDecodeError, KeyError):
            return self.decrypt(secret.data), None

    def _encrypt_secrets(self, secret_text: str, recipients: List[PassboltUserTuple]) -> List[Mapping]:
        return [
            {"user_id": user.id, "data": self.encrypt(secret_text, user.gpgkey.fingerprint)} for user in recipients
        ]

    def _get_secret(self, resource_id: PassboltResourceIdType) -> PassboltSecretTuple:
        response = self.get(f"/secrets/resource/{resource_id}.json")
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        return PassboltSecretTuple(**response["body"])

    def _update_secret(self, resource_id: PassboltResourceIdType, new_secret):
        return self.put(f"/resources/{resource_id}.json", {"secrets": new_secret}, return_response_object=True)

    def _get_secret_type(self, resource_type_id: PassboltResourceTypeIdType) -> PassboltResourceType:
        resource_type: PassboltResourceTypeTuple = self.read_resource_type(resource_type_id=resource_type_id)
        resource_definition = json.loads(resource_type.definition)
        if resource_type.slug == 'v5-password-string':
            return PassboltResourceType.PASSWORD_WITH_ENCRYPTED_METADATA
        if resource_type.slug == 'v5-default':
            return PassboltResourceType.PASSWORD_WITH_DESCRIPTION_AND_ENCRYPTED_METADATA
        if resource_definition["secret"]["type"] == "string":
            return PassboltResourceType.PASSWORD
        if resource_definition["secret"]["type"] == "object" and set(
                resource_definition["secret"]["properties"].keys()
        ) == {"password", "description"}:
            return PassboltResourceType.PASSWORD_WITH_DESCRIPTION
        raise PassboltError("The resource type definition is not valid or supported yet. ")

    def get_password_and_description(self, resource_id: PassboltResourceIdType) -> dict:
        resource: PassboltResourceTuple = self.read_resource(resource_id=resource_id)
        secret: PassboltSecretTuple = self._get_secret(resource_id=resource_id)
        secret_type = self._get_secret_type(resource_type_id=resource.resource_type_id)
        if secret_type == PassboltResourceType.PASSWORD:
            return {"password": self.decrypt(secret.data), "description": resource.description}
        elif secret_type == PassboltResourceType.PASSWORD_WITH_DESCRIPTION:
            pwd, desc = self._json_load_secret(secret=secret)
            return {"password": pwd, "description": desc}
        elif secret_type == PassboltResourceType.PASSWORD_WITH_ENCRYPTED_METADATA:
            # metadata should already be decrypted
            return {
                "password": self.decrypt(secret.data),
                "description": resource.description
            }
        elif secret_type == PassboltResourceType.PASSWORD_WITH_DESCRIPTION_AND_ENCRYPTED_METADATA:
            sc_dict = json.loads(self.decrypt(secret.data))
            return {
                "password": sc_dict["password"],
                "description": sc_dict["description"] if "description" in sc_dict else None
            }

    def get_password(self, resource_id: PassboltResourceIdType) -> str:
        return self.get_password_and_description(resource_id=resource_id)["password"]

    def get_description(self, resource_id: PassboltResourceIdType) -> str:
        return self.get_password_and_description(resource_id=resource_id)["description"]

    def iterate_resources(self, params: Optional[dict] = None):
        params = params or {}
        url_params = urllib.parse.urlencode(params)
        if url_params:
            url_params = "?" + url_params
        response = self.get("/resources.json" + url_params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        resources = response["body"]
        yield from resources

    def list_resources(self, folder_id: Optional[PassboltFolderIdType] = None):
        params = {
            **({"filter[has-id][]": folder_id} if folder_id else {}),
            "contain[children_resources]": True,
        }
        url_params = urllib.parse.urlencode(params)
        if url_params:
            url_params = "?" + url_params
        response = self.get("/folders.json" + url_params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        response = response["body"][0]
        assert "children_resources" in response.keys(), (
            f"Key 'body[].children_resources' not found in response " f"keys: {response.keys()} "
        )
        for i in range(len(response["children_resources"])):
            response["children_resources"][i] = self._decrypt_metadata_in_response(
                response=response["children_resources"][i]
            )
        return constructor(PassboltResourceTuple)(response["children_resources"])

    def list_users_with_folder_access(self, folder_id: PassboltFolderIdType) -> List[PassboltUserTuple]:
        folder_tuple = self.describe_folder(folder_id)
        # resolve users
        user_ids = set()
        # resolve users from groups
        for perm in folder_tuple.permissions:
            if perm.aro == "Group":
                group_tuple: PassboltGroupTuple = self.describe_group(perm.aro_foreign_key)
                for group_user in group_tuple.groups_users:
                    user_ids.add(group_user["user_id"])
            elif perm.aro == "User":
                user_ids.add(perm.aro_foreign_key)
        return [user for user in self.list_users() if user.id in user_ids]

    def list_users(
            self, resource_or_folder_id: Union[None, PassboltResourceIdType, PassboltFolderIdType] = None,
            force_list=True
    ) -> List[PassboltUserTuple]:
        if resource_or_folder_id is None:
            params = {}
        else:
            params = {"filter[has-access]": resource_or_folder_id, "contain[user]": 1}
        params["contain[permission]"] = True
        response = self.get(f"/users.json", params=params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        response = response["body"]
        users = constructor(
            PassboltUserTuple,
            subconstructors={
                "gpgkey": constructor(PassboltOpenPgpKeyTuple),
            },
        )(response)
        if isinstance(users, PassboltUserTuple) and force_list:
            return [users]
        return users

    def import_metadata_keys(self, trustlevel="TRUST_FULLY"):
        """Imports metadata keys from the passbolt server and sets trust level."""
        md_pub_keys, md_priv_keys = self._get_metadata_keys()
        for key in md_pub_keys:
            armored_key = key["armored_key"]
            fingerprint = key["fingerprint"]
            self.gpg.import_keys(armored_key)
            self.gpg.trust_keys(fingerprint, trustlevel)
        for key in md_priv_keys:
            self.gpg.import_keys(key)

    def import_public_keys(self, trustlevel="TRUST_FULLY"):
        # get all users
        users = self.list_users()
        for user in users:
            self.gpg.import_keys(user.gpgkey.armored_key)
            self.gpg.trust_keys(user.gpgkey.fingerprint, trustlevel)

    def _decrypt_metadata_in_response(self, response: dict) -> dict:
        """Decrypts metadata in the response if it exists."""
        if "metadata" in response:
            metadata = json.loads(self.decrypt(response["metadata"]))
            response["name"] = metadata["name"]
            response["description"] = metadata.get("description", "")
            uris = metadata.get("uris", [])
            response["uri"] = len(uris) > 0 and uris[0] or ""
            response["username"] = metadata.get("username", "")
        return response

    def read_resource(self, resource_id: PassboltResourceIdType) -> PassboltResourceTuple:
        response = self.get(f"/resources/{resource_id}.json", return_response_object=True)
        response = response.json()["body"]
        response = self._decrypt_metadata_in_response(response)
        return constructor(PassboltResourceTuple)(response)

    def read_resource_type(self, resource_type_id: PassboltResourceTypeIdType) -> PassboltResourceTypeTuple:
        response = self.get(f"/resource-types/{resource_type_id}.json", return_response_object=True)
        response = response.json()["body"]
        return constructor(PassboltResourceTypeTuple)(response)

    def read_folder(self, folder_id: PassboltFolderIdType) -> PassboltFolderTuple:
        response = self.get(
            f"/folders/{folder_id}.json", params={"contain[permissions]": True}, return_response_object=True
        )
        response = response.json()
        return constructor(PassboltFolderTuple, subconstructors={"permissions": constructor(PassboltPermissionTuple)})(
            response["body"]
        )

    def describe_folder(self, folder_id: PassboltFolderIdType):
        """Shows folder details with permissions that are needed for some downstream task."""
        response = self.get(
            f"/folders/{folder_id}.json",
            params={
                "contain[permissions]": 1,
                "contain[permissions.user.profile]": 1,
                "contain[permissions.group]": 1,
            },
        )
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        assert (
                "permissions" in response["body"].keys()
        ), f"Key 'body.permissions' not found in response: {response['body'].keys()}"
        return constructor(
            PassboltFolderTuple,
            subconstructors={
                "permissions": constructor(PassboltPermissionTuple),
            }
        )(response["body"])

    def move_resource_to_folder(self, resource_id: PassboltResourceIdType, folder_id: PassboltFolderIdType):
        r = self.post(
            f"/move/resource/{resource_id}.json", {"folder_parent_id": folder_id}, return_response_object=True
        )
        return r.json()

    def create_resource(self,
                        name: str,
                        password: str,
                        username: str = "",
                        description: str = "",
                        uri: str = "",
                        resource_type_id: Optional[PassboltResourceTypeIdType] = None,
                        folder_id: Optional[PassboltFolderIdType] = None,
                        plaintext: bool = False) -> PassboltResourceTuple:
        if plaintext:
            create_resp, payload = self._create_resource_plaintext(
                name=name,
                password=password,
                username=username,
                description=description,
                uri=uri,
                resource_type_id=resource_type_id,
            )
        else:
            create_resp, payload = self._create_resource_encrypted(
                name=name,
                password=password,
                username=username,
                description=description,
                uris=[uri] if uri else [],
                resource_type_id=resource_type_id,
            )
        resource = constructor(PassboltResourceTuple)(create_resp)
        if folder_id:
            folder = self.read_folder(folder_id)
            # get users with access to folder
            users_list = self.list_users_with_folder_access(folder_id)
            lookup_users: Mapping[PassboltUserIdType, PassboltUserTuple] = {user.id: user for user in users_list}
            self_user_id = [user.id for user in users_list if self.user_fingerprint == user.gpgkey.fingerprint]
            if self_user_id:
                self_user_id = self_user_id[0]
            else:
                raise ValueError("User not in passbolt")
            # simulate sharing with folder perms
            permissions = [
                {
                    "is_new": True,
                    **{k: v for k, v in perm._asdict().items() if k != "id"},
                }
                for perm in folder.permissions
                if (perm.aro_foreign_key != self_user_id)
            ]
            share_payload = {
                "permissions": permissions,
                "secrets": self._encrypt_secrets(payload, lookup_users.values()),
            }
            # simulate sharing with folder perms
            r_simulate = self.post(
                f"/share/simulate/resource/{resource.id}.json", share_payload, return_response_object=True
            )
            r_share = self.put(f"/share/resource/{resource.id}.json", share_payload, return_response_object=True)

            self.move_resource_to_folder(resource_id=resource.id, folder_id=folder_id)
        return resource

    def _create_resource_encrypted(self,
                                   name: str,
                                   password: str,
                                   resource_type_id: PassboltResourceTypeIdType,
                                   username: str = "",
                                   description: str = "",
                                   uris=None,
                                   ):
        if uris is None:
            uris = []
        """Creates a new resource on passbolt and shares it with the provided folder recipients"""
        if not name:
            raise PassboltValidationError(f"Name cannot be None or empty -- {name}!")
        if not password:
            raise PassboltValidationError(f"Password cannot be None or empty -- {password}!")
        if not resource_type_id:
            resource_type_id = self.default_resource_type_id

        secret_type = self._get_secret_type(resource_type_id=resource_type_id)

        # get first metadata key
        # TODO: Only supporting shared key metadata for now
        md_key_id = list(self.metadata_keys.keys())[0] if self.metadata_keys else None
        if md_key_id is None:
            raise PassboltValidationError("No metadata keys found. Please import metadata keys first.")

        metadata = {
            'object_type': 'PASSBOLT_RESOURCE_METADATA',
            'resource_type_id': resource_type_id,
            "name": name,
            "description": description,
            "uris": uris,
            "username": username,
        }

        if secret_type == PassboltResourceType.PASSWORD_WITH_DESCRIPTION_AND_ENCRYPTED_METADATA:
            secret_data = json.dumps({
                'object_type': 'PASSBOLT_SECRET_DATA',
                'password': password
            })
        elif secret_type == PassboltResourceType.PASSWORD_WITH_ENCRYPTED_METADATA:
            secret_data = password

        r_create = self.post(
            "/resources.json",
            {
                'metadata_key_id': md_key_id,
                'metadata_key_type': 'shared_key',
                'metadata': self.encrypt(json.dumps(metadata),
                                         recipients=[self.metadata_keys[md_key_id]["fingerprint"]]),
                **({"resource_type_id": resource_type_id} if resource_type_id else {}),
                "secrets": [{"data": self.encrypt(secret_data)}],
            },
            return_response_object=True,
        )
        return r_create.json()["body"], secret_data

    def _create_resource_plaintext(
            self,
            name: str,
            password: str,
            username: str = "",
            description: str = "",
            uri: str = "",
            resource_type_id: Optional[PassboltResourceTypeIdType] = None,
    ):
        """Creates a new resource on passbolt and shares it with the provided folder recipients"""
        if not name:
            raise PassboltValidationError(f"Name cannot be None or empty -- {name}!")
        if not password:
            raise PassboltValidationError(f"Password cannot be None or empty -- {password}!")

        r_create = self.post(
            "/resources.json",
            {
                "name": name,
                "username": username,
                "description": description,
                "uri": uri,
                **({"resource_type_id": resource_type_id} if resource_type_id else {}),
                "secrets": [{"data": self.encrypt(password)}],
            },
            return_response_object=True,
        )
        return r_create.json()["body"], password

    def update_resource(
            self,
            resource_id: PassboltResourceIdType,
            name: Optional[str] = None,
            username: Optional[str] = None,
            description: Optional[str] = None,
            uri: Optional[str] = None,
            resource_type_id: Optional[PassboltResourceTypeIdType] = None,
            password: Optional[str] = None,
            plaintext: bool = False,
    ):
        if plaintext:
            return self._update_resource_plaintext(
                resource_id=resource_id,
                name=name,
                username=username,
                description=description,
                uri=uri,
                resource_type_id=resource_type_id,
                password=password,
            )
        else:
            return self._update_resource_encrypted_metadata(
                resource_id=resource_id,
                name=name,
                username=username,
                description=description,
                uris=[uri] if uri else [],
                resource_type_id=resource_type_id,
                password=password,
            )

    def _update_resource_encrypted_metadata(
            self,
            resource_id: PassboltResourceIdType,
            name: Optional[str] = None,
            username: Optional[str] = None,
            description: Optional[str] = None,
            uris: List[str] = None,
            resource_type_id: Optional[PassboltResourceTypeIdType] = None,
            password: Optional[str] = None):
        if uris is None:
            uris = []

        # get first metadata key
        # TODO: Only supporting shared key metadata for now
        md_key_id = list(self.metadata_keys.keys())[0] if self.metadata_keys else None
        if md_key_id is None:
            raise PassboltValidationError("No metadata keys found. Please import metadata keys first.")

        resource: PassboltResourceTuple = self.read_resource(resource_id=resource_id)
        secret_type = self._get_secret_type(resource_type_id=resource.resource_type_id)
        if secret_type != PassboltResourceType.PASSWORD_WITH_ENCRYPTED_METADATA and secret_type != PassboltResourceType.PASSWORD_WITH_DESCRIPTION_AND_ENCRYPTED_METADATA:
            raise PassboltError(
                f"Resource type {resource.resource_type_id} is not supported for this update method (encrypted)."
            )
        resource_type_id = resource_type_id if resource_type_id else resource.resource_type_id
        payload = {
            "resource_type_id": resource_type_id,
        }

        recipients = self.list_users(resource_or_folder_id=resource_id)
        if password:
            assert isinstance(password, str), f"password has to be a string object -- {password}"
            if secret_type == PassboltResourceType.PASSWORD_WITH_DESCRIPTION_AND_ENCRYPTED_METADATA:
                secret_data = json.dumps({
                    'object_type': 'PASSBOLT_SECRET_DATA',
                    'password': password
                })
            else:
                secret_data = password
            payload["secrets"] = self._encrypt_secrets(secret_text=secret_data, recipients=recipients)

        metadata = json.loads(self.decrypt(resource.metadata))
        if name is not None:
            metadata["name"] = name
        if username is not None:
            metadata["username"] = username
        if description is not None:
            metadata["description"] = description
        for i, uri in enumerate(uris):
            if i < len(metadata["uris"]):
                metadata["uris"][i] = uri
            else:
                metadata["uris"].append(uri)
        metadata["resource_type_id"] = resource_type_id
        metadata = self.encrypt(json.dumps(metadata),
                                recipients=[self.metadata_keys[md_key_id]["fingerprint"]])
        payload["metadata"] = metadata
        payload["metadata_key_id"] = md_key_id
        payload["metadata_key_type"] = "shared_key"

        if payload:
            r = self.put(f"/resources/{resource_id}.json", payload, return_response_object=True)
            return r
        return None

    def _update_resource_plaintext(
            self,
            resource_id: PassboltResourceIdType,
            name: Optional[str] = None,
            username: Optional[str] = None,
            description: Optional[str] = None,
            uri: Optional[str] = None,
            resource_type_id: Optional[PassboltResourceTypeIdType] = None,
            password: Optional[str] = None,
    ):
        resource: PassboltResourceTuple = self.read_resource(resource_id=resource_id)
        secret = self._get_secret(resource_id=resource_id)
        secret_type = self._get_secret_type(resource_type_id=resource.resource_type_id)
        resource_type_id = resource_type_id if resource_type_id else resource.resource_type_id
        payload = {
            "name": name,
            "username": username,
            "description": description,
            "uri": uri,
            "resource_type_id": resource_type_id,
        }
        if name is None:
            payload.pop("name")
        if username is None:
            payload.pop("username")
        if description is None:
            payload.pop("description")
        if uri is None:
            payload.pop("uri")

        recipients = self.list_users(resource_or_folder_id=resource_id)
        if secret_type == PassboltResourceType.PASSWORD:
            if password is not None:
                assert isinstance(password, str), f"password has to be a string object -- {password}"
                payload["secrets"] = self._encrypt_secrets(secret_text=password, recipients=recipients)
        elif secret_type == PassboltResourceType.PASSWORD_WITH_DESCRIPTION:
            pwd, desc = self._json_load_secret(secret=secret)
            secret_dict = {}
            if description is not None or password is not None:
                secret_dict["description"] = description if description else desc
                secret_dict["password"] = password if password else pwd
            if secret_dict:
                secret_text = json.dumps(secret_dict)
                payload["secrets"] = self._encrypt_secrets(secret_text=secret_text, recipients=recipients)

        if payload:
            r = self.put(f"/resources/{resource_id}.json", payload, return_response_object=True)
            return r

    def describe_group(self, group_id: PassboltGroupIdType):
        response = self.get(f"/groups/{group_id}.json", params={"contain[groups_users]": 1})
        return constructor(PassboltGroupTuple)(response["body"])
