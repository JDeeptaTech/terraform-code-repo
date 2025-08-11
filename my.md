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
