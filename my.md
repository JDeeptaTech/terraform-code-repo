```py
import hvac
import os

def get_approle_credentials(vault_addr, vault_token, role_name):
    """
    Uses a privileged token to fetch the RoleID and generate a new SecretID.

    Args:
        vault_addr (str): The URL of the Vault server.
        vault_token (str): A privileged token with permissions to manage AppRoles.
        role_name (str): The name of the AppRole.

    Returns:
        tuple: A tuple containing the (role_id, secret_id), or (None, None) on failure.
    """
    try:
        # Step 1: Connect to Vault using the privileged token
        print("Connecting with privileged token to generate credentials...")
        client = hvac.Client(url=vault_addr, token=vault_token)

        if not client.is_authenticated():
            print("Error: The provided privileged token is invalid or has expired.")
            return None, None

        # Step 2: Read the RoleID for the given role name
        read_role_id_response = client.auth.approle.read_role_id(role_name=role_name)
        role_id = read_role_id_response['data']['role_id']
        print(f"Successfully fetched RoleID for role '{role_name}'.")

        # Step 3: Generate a new SecretID for the role
        generate_secret_id_response = client.auth.approle.generate_secret_id(role_name=role_name)
        secret_id = generate_secret_id_response['data']['secret_id']
        print("Successfully generated a new SecretID.")

        return role_id, secret_id

    except hvac.exceptions.Forbidden:
        print(f"Error: The provided token does not have permission to manage the AppRole '{role_name}'.")
        return None, None
    except Exception as e:
        print(f"An error occurred while generating credentials: {e}")
        return None, None


def get_vault_secret(vault_addr, approle_id, approle_secret_id, secret_path, secret_key):
    """
    Authenticates to Vault using AppRole and fetches a secret. (This function is the same as before)
    """
    try:
        # Step 1: Initialize a new client for the application login
        client = hvac.Client(url=vault_addr)

        print("\nAttempting to authenticate with newly generated AppRole credentials...")

        # Step 2: Authenticate using AppRole to get an application token
        auth_response = client.auth.approle.login(
            role_id=approle_id,
            secret_id=approle_secret_id,
        )
        
        print("Successfully authenticated with AppRole.")

        # Step 3: Fetch the secret from the KVv2 store
        print(f"Fetching secret from path: {secret_path}")
        read_secret_response = client.secrets.kv.v2.read_secret_version(path=secret_path)
        secret_data = read_secret_response['data']['data']
        secret_value = secret_data.get(secret_key)

        if secret_value:
            print(f"Successfully retrieved the secret for key: '{secret_key}'")
            return secret_value
        else:
            print(f"Error: Key '{secret_key}' not found in the secret at '{secret_path}'")
            return None

    except Exception as e:
        print(f"An unexpected error occurred while fetching the secret: {e}")
        return None


# --- How to use the functions ---
if __name__ == "__main__":
    # Get configuration from environment variables
    VAULT_ADDRESS = os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200')
    # This is the privileged token needed to create the SecretID
    VAULT_PRIMARY_TOKEN = os.getenv('VAULT_TOKEN')

    # --- Variables you need to change ---
    APPROLE_ROLE_NAME = 'my-app-role'  # The name of your AppRole in Vault
    SECRET_PATH = 'myapp/config'       # The path to your secret
    SECRET_KEY_TO_FETCH = 'api_key'    # The key within the secret

    # Check for the primary token
    if not VAULT_PRIMARY_TOKEN:
        print("Error: Please set the VAULT_TOKEN environment variable with a privileged token.")
    else:
        # First, generate the AppRole credentials
        role_id, secret_id = get_approle_credentials(
            vault_addr=VAULT_ADDRESS,
            vault_token=VAULT_PRIMARY_TOKEN,
            role_name=APPROLE_ROLE_NAME
        )
        
        # If credentials were generated successfully, use them to get the secret
        if role_id and secret_id:
            retrieved_value = get_vault_secret(
                vault_addr=VAULT_ADDRESS,
                approle_id=role_id,
                approle_secret_id=secret_id,
                secret_path=SECRET_PATH,
                secret_key=SECRET_KEY_TO_FETCH,
            )

            if retrieved_value:
                print("\n---")
                print(f"✅ The value of '{SECRET_KEY_TO_FETCH}' is: {retrieved_value}")
                print("---")
```
```cfg
[defaults]
callback_plugins = ./callback_plugins
callbacks_enabled = task_logger

[callback_task_logger]
# filter
name_regex = (?i)deploy|restart
only_changed = False

# optional local file (good for debugging)
log_path = ./logs/task_logger.jsonl

# Splunk HEC
hec_endpoint = https://splunk.example.com:8088/services/collector/event
hec_token = <YOUR_HEC_TOKEN>
hec_index = my_ansible_index
hec_sourcetype = ansible:task
hec_source = ansible:callback
validate_certs = True

```
```py
# -*- coding: utf-8 -*-
from __future__ import annotations
import io, os, re, json, time, ssl
from datetime import datetime
from ansible.plugins.callback import CallbackBase
try:
    import urllib.request as urlreq, urllib.error as urlerr
except Exception:
    urlreq = urlerr = None

DOCUMENTATION = r"""
callback: task_logger
type: notification
short_description: Log selected task events and send to Splunk HEC
options:
  # FILTER
  name_regex:
    description: Regex to include tasks by name.
    env: [{name: TASK_LOGGER_NAME_REGEX}]
    ini:
      - section: callback_task_logger
        key: name_regex
    required: true
  only_changed:
    description: Only send results where changed=true (fail/unreachable always sent).
    type: bool
    env: [{name: TASK_LOGGER_ONLY_CHANGED}]
    ini:
      - section: callback_task_logger
        key: only_changed
    default: False

  # LOCAL AUDIT (optional)
  log_path:
    description: Optional JSONL file path to also write locally.
    env: [{name: TASK_LOGGER_LOG_PATH}]
    ini:
      - section: callback_task_logger
        key: log_path
    default: ""

  # SPLUNK HEC
  hec_endpoint:
    description: Splunk HEC URL, e.g. https://splunk:8088/services/collector/event
    env: [{name: SPLUNK_HEC_ENDPOINT}]
    ini:
      - section: callback_task_logger
        key: hec_endpoint
    required: true

  hec_token:
    description: Splunk HEC token
    env: [{name: SPLUNK_HEC_TOKEN}]
    ini:
      - section: callback_task_logger
        key: hec_token
    required: true

  hec_index:
    description: Splunk index to write to
    env: [{name: SPLUNK_HEC_INDEX}]
    ini:
      - section: callback_task_logger
        key: hec_index
    required: true

  hec_sourcetype:
    description: Splunk sourcetype
    env: [{name: SPLUNK_HEC_SOURCETYPE}]
    ini:
      - section: callback_task_logger
        key: hec_sourcetype
    required: true

  hec_source:
    description: Optional Splunk source (defaults to 'ansible:callback')
    env: [{name: SPLUNK_HEC_SOURCE}]
    ini:
      - section: callback_task_logger
        key: hec_source
    default: "ansible:callback"

  validate_certs:
    description: Validate HTTPS certs when calling HEC
    type: bool
    env: [{name: SPLUNK_HEC_VALIDATE_CERTS}]
    ini:
      - section: callback_task_logger
        key: validate_certs
    default: True
"""

CALLBACK_VERSION = 2.0
CALLBACK_TYPE = "notification"
CALLBACK_NAME = "task_logger"

class CallbackModule(CallbackBase):
    def __init__(self):
        super(CallbackModule, self).__init__()
        self.re_pat = None
        self.only_changed = False
        self.fp = None
        self.hec = {"endpoint": None, "token": None, "index": None, "sourcetype": None, "source": "ansible:callback", "validate": True}

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super().set_options(task_keys=task_keys, var_options=var_options, direct=direct)
        self.re_pat = re.compile(self.get_option("name_regex"))
        self.only_changed = bool(self.get_option("only_changed"))

        log_path = (self.get_option("log_path") or "").strip()
        if log_path:
            os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
            self.fp = io.open(log_path, "a", encoding="utf-8", buffering=1)

        self.hec["endpoint"] = self.get_option("hec_endpoint").rstrip("/")
        self.hec["token"] = self.get_option("hec_token")
        self.hec["index"] = self.get_option("hec_index")
        self.hec["sourcetype"] = self.get_option("hec_sourcetype")
        self.hec["source"] = self.get_option("hec_source") or "ansible:callback"
        self.hec["validate"] = bool(self.get_option("validate_certs"))

    # -------- helpers --------
    def _match(self, name: str) -> bool:
        return bool(self.re_pat.search(name or ""))

    def _jsonl(self, obj: dict):
        if self.fp:
            self.fp.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def _send_hec(self, host: str, task_name: str, status: str, result: dict):
        # Trim noisy fields
        safe = {k: result.get(k) for k in ("changed","failed","rc","stdout","stderr","msg") if k in result}
        event_payload = {
            "time": time.time(),
            "host": host,
            "source": self.hec["source"],
            "sourcetype": self.hec["sourcetype"],
            "index": self.hec["index"],
            "event": {
                "@timestamp": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
                "status": status,
                "task_name": task_name,
                "host": host,
                "result": safe,
            },
        }

        body = json.dumps(event_payload).encode("utf-8")
        req = urlreq.Request(
            url=self.hec["endpoint"],
            data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Splunk {self.hec['token']}"},
            method="POST",
        )
        ctx = None
        if not self.hec["validate"]:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urlreq.urlopen(req, context=ctx) as resp:  # noqa: SIM115
                # 200/201 expected
                pass
        except Exception as e:
            # Do not fail the play; log locally if enabled.
            self._jsonl({"hec_error": str(e), "task_name": task_name, "status": status})

    def _emit(self, event_type: str, result):
        task = result._task
        host = result._host.get_name()
        name = task.get_name().strip()

        if not self._match(name):
            return

        r = result._result or {}
        changed = bool(r.get("changed", False))

        if self.only_changed and event_type in ("ok", "skipped") and not changed:
            return

        record = {
            "@timestamp": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "event": event_type,
            "task_name": name,
            "host": host,
            "result": r,
        }
        self._jsonl(record)
        self._send_hec(host, name, event_type, r)

    # -------- Ansible hooks --------
    def v2_runner_on_ok(self, result):
        self._emit("changed" if result._result.get("changed") else "ok", result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._emit("failed", result)

    def v2_runner_on_unreachable(self, result):
        self._emit("unreachable", result)

    def v2_runner_on_skipped(self, result):
        self._emit("skipped", result)

    def __del__(self):
        try:
            if self.fp:
                self.fp.close()
        except Exception:
            pass

```
## 2

```py
# -*- coding: utf-8 -*-
from __future__ import annotations
import io, os, re, shlex, json, time, ssl
from datetime import datetime
from ansible.plugins.callback import CallbackBase
try:
    import urllib.request as urlreq
except Exception:  # pragma: no cover
    urlreq = None

DOCUMENTATION = r"""
callback: task_logger
type: notification
short_description: Send selected Ansible task results to Splunk HEC
description:
  - Sends a HEC event for any task whose name contains the marker C(| addtolog |).
  - Optional inline overrides may follow the marker as key=value pairs
    (e.g. C(| addtolog | index=my_idx sourcetype=my_type source=my_src)).
  - Defaults for index, sourcetype, and source can be set in ansible.cfg or env vars.
options:
  endpoint:
    description: Splunk HEC endpoint (event API).
    env: [{name: SPLUNK_HEC_ENDPOINT}]
    ini: [{section: callback_task_logger, key: endpoint}]
    required: true
  token:
    description: Splunk HEC token.
    env: [{name: SPLUNK_HEC_TOKEN}]
    ini: [{section: callback_task_logger, key: token}]
    required: true
  index:
    description: Default Splunk index (can be overridden per task).
    env: [{name: SPLUNK_HEC_INDEX}]
    ini: [{section: callback_task_logger, key: index}]
    required: true
  sourcetype:
    description: Default Splunk sourcetype (can be overridden per task).
    env: [{name: SPLUNK_HEC_SOURCETYPE}]
    ini: [{section: callback_task_logger, key: sourcetype}]
    required: true
  source:
    description: Default Splunk source (can be overridden per task).
    env: [{name: SPLUNK_HEC_SOURCE}]
    ini: [{section: callback_task_logger, key: source}]
    default: ansible:callback
  validate_certs:
    description: Validate TLS certs when posting to HEC.
    type: bool
    env: [{name: SPLUNK_HEC_VALIDATE_CERTS}]
    ini: [{section: callback_task_logger, key: validate_certs}]
    default: true
  log_path:
    description: Optional local JSONL file for debugging/auditing.
    env: [{name: TASK_LOGGER_LOG_PATH}]
    ini: [{section: callback_task_logger, key: log_path}]
    default: ""
"""

CALLBACK_VERSION = 2.0
CALLBACK_TYPE = "notification"
CALLBACK_NAME = "task_logger"

_MARKER = re.compile(r"^(?P<prefix>.*?)(?:\s*\|\s*addtolog\s*\|\s*(?P<kv>.*))?$", re.IGNORECASE)

class CallbackModule(CallbackBase):
    def __init__(self):
        super().__init__()
        self.endpoint = None
        self.token = None
        self.default_index = None
        self.default_sourcetype = None
        self.default_source = "ansible:callback"
        self.validate_certs = True
        self.fp = None  # optional JSONL writer

    # ---- setup options from ansible.cfg / env ----
    def set_options(self, task_keys=None, var_options=None, direct=None):
        super().set_options(task_keys=task_keys, var_options=var_options, direct=direct)
        self.endpoint = self.get_option("endpoint").rstrip("/")
        self.token = self.get_option("token")
        self.default_index = self.get_option("index")
        self.default_sourcetype = self.get_option("sourcetype")
        self.default_source = self.get_option("source") or "ansible:callback"
        self.validate_certs = bool(self.get_option("validate_certs"))
        log_path = (self.get_option("log_path") or "").strip()
        if log_path:
            os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
            self.fp = io.open(log_path, "a", encoding="utf-8", buffering=1)

    # ---- helpers ----
    def _parse_marker(self, raw_name: str):
        """
        Returns (clean_task_name, overrides_dict or None).
        overrides_dict is None when marker not present (means: do not send).
        It is {} when marker present with no overrides.
        """
        m = _MARKER.match(raw_name or "")
        if not m:
            return raw_name, None
        kv = m.group("kv")
        if kv is None:  # no marker
            return (m.group("prefix") or raw_name).strip(), None
        overrides = {}
        # parse "key=value" tokens; supports quotes
        for tok in shlex.split(kv):
            if "=" in tok:
                k, v = tok.split("=", 1)
                overrides[k.strip().lower()] = v.strip()
        return (m.group("prefix") or "").strip(), overrides

    def _local_log(self, obj: dict):
        if self.fp:
            self.fp.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def _send_hec(self, host: str, task_name: str, status: str, result: dict, overrides: dict):
        index = overrides.get("index", self.default_index)
        sourcetype = overrides.get("sourcetype", self.default_sourcetype)
        source = overrides.get("source", self.default_source)

        # Keep a compact result
        safe = {k: result.get(k) for k in ("changed", "failed", "rc", "stdout", "stderr", "msg") if k in result}

        payload = {
            "time": time.time(),
            "host": host,
            "index": index,
            "sourcetype": sourcetype,
            "source": source,
            "event": {
                "@timestamp": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
                "status": status,
                "task_name": task_name,
                "host": host,
                "result": safe,
            },
        }

        req = urlreq.Request(
            url=self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Splunk {self.token}"},
            method="POST",
        )

        ctx = None
        if not self.validate_certs:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urlreq.urlopen(req, context=ctx):  # noqa: SIM115
                pass
        except Exception as e:  # don't break the play
            self._local_log({"hec_error": str(e), "task_name": task_name, "status": status})

    def _emit(self, event_type: str, result):
        raw = result._task.get_name().strip()
        clean_name, overrides = self._parse_marker(raw)
        if overrides is None:
            return  # no marker -> do nothing

        host = result._host.get_name()
        r = result._result or {}

        # local optional audit line
        self._local_log({
            "@timestamp": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "event": event_type,
            "task_name": clean_name,
            "host": host,
            "result": {k: r.get(k) for k in ("changed","failed","rc","stdout","stderr","msg")},
            "overrides": overrides,
        })

        self._send_hec(host, clean_name, event_type, r, overrides)

    # ---- Ansible hooks ----
    def v2_runner_on_ok(self, result):
        self._emit("changed" if result._result.get("changed") else "ok", result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._emit("failed", result)

    def v2_runner_on_unreachable(self, result):
        self._emit("unreachable", result)

    def v2_runner_on_skipped(self, result):
        self._emit("skipped", result)

    def __del__(self):
        try:
            if self.fp:
                self.fp.close()
        except Exception:
            pass

```


``` cfg
[defaults]
callback_plugins = ./callback_plugins
callbacks_enabled = task_logger

[callback_task_logger]
# Splunk HEC config (defaults; can be overridden per task)
endpoint = https://splunk.example.com:8088/services/collector/event
token = <YOUR_HEC_TOKEN>
index = my_default_index
sourcetype = ansible:task
source = ansible:callback
validate_certs = true

# optional local JSONL for debugging
log_path = ./logs/task_logger.jsonl

```

``` yml
- hosts: localhost
  gather_facts: false
  tasks:
    - name: Do build step | addtolog |
      shell: "echo build"

    - name: Create VM | addtolog | index=cto_virt_infra_hub sourcetype=ansible:vm source=vm-build
      shell: "echo creating"

    - name: This will NOT be sent to Splunk
      debug: { msg: "no marker" }

```
