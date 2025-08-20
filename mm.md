
```text
# terraform.j2
datacenter_name          = "{{ datacenter_name }}"
datastore_cluster_name   = "{{ datastore_cluster_name }}"
cluster_name             = "{{ cluster_name }}"
network_name             = "{{ network_name }}"
vm_template_name         = "{{ vm_template_name }}"
is_performance_vm        = {{ is_performance_vm | lower }}
folder_name              = "{{ folder_name }}"
custom_attributes        = {
  {%- for key, value in custom_attributes.items() -%}
    "{{ key }}":"{{ value }}"{% if not loop.last %},{% endif %}
  {%- endfor -%}
}
tags = [
  {%- for tag in tags -%}
  {
    name     = "{{ tag.name }}",
    category = "{{ tag.category }}"
  }{% if not loop.last %},{% endif %}
  {%- endfor -%}
]
os_family                = "{{ os_family }}"
backup                   = {{ backup | lower }}
vm_name                  = "{{ vm_name }}"
num_cpus                 = {{ num_cpus }}
memory                   = {{ memory }}
disks = [
  {%- for disk in disks -%}
  {
    label       = "{{ disk.label }}",
    size        = {{ disk.size }},
    unit_number = {{ disk.unit_number }}
  }{% if not loop.last %},{% endif %}
  {%- endfor -%}
]

----
Project layout
Copy
Edit
project/
├── ansible.cfg
├── callback_plugins/
│   └── task_logger.py
├── playbook.yml
└── inventory.ini
1) The callback plugin (callback_plugins/task_logger.py)
python
Copy
Edit
# callback_plugins/task_logger.py
# -*- coding: utf-8 -*-

from __future__ import annotations
import os
import io
import re
import json
import time
from datetime import datetime
from ansible.plugins.callback import CallbackBase

DOCUMENTATION = r"""
callback: task_logger
type: notification
short_description: Log selected task events to a JSONL file
description:
  - Logs task start/ok/changed/failed/skipped/unreachable with filtering by tag, module, or task name regex.
  - Output is JSON Lines (one JSON object per line).
options:
  log_path:
    description: File path for the JSONL log.
    ini:
      - section: callback_task_logger
        key: log_path
    env:
      - name: TASK_LOGGER_LOG_PATH
    default: ./logs/ansible_tasks.jsonl
  include_tags:
    description: Comma-separated list of tags to include. If empty, do not filter by tag.
    ini:
      - section: callback_task_logger
        key: include_tags
    env:
      - name: TASK_LOGGER_INCLUDE_TAGS
    default: ""
  include_modules:
    description: Comma-separated list of module names to include (e.g., copy,template,shell).
    ini:
      - section: callback_task_logger
        key: include_modules
    env:
      - name: TASK_LOGGER_INCLUDE_MODULES
    default: ""
  include_names_regex:
    description: Regex to include tasks by their name. If empty, do not filter by name.
    ini:
      - section: callback_task_logger
        key: include_names_regex
    env:
      - name: TASK_LOGGER_INCLUDE_NAMES_REGEX
    default: ""
  only_changed:
    description: If true, only log events where changed is true or status is failed/unreachable.
    type: bool
    ini:
      - section: callback_task_logger
        key: only_changed
    env:
      - name: TASK_LOGGER_ONLY_CHANGED
    default: False
  redact_vars:
    description: Comma-separated list of keys to redact from result/args (e.g., password,token).
    ini:
      - section: callback_task_logger
        key: redact_vars
    env:
      - name: TASK_LOGGER_REDACT_VARS
    default: "password,passwd,token,secret,apikey,api_key"
"""

CALLBACK_VERSION = 2.0
CALLBACK_TYPE = "notification"
CALLBACK_NAME = "task_logger"  # enable via callbacks_enabled=task_logger

class CallbackModule(CallbackBase):
    """
    Custom callback to log selected task events as JSON lines.
    """

    def __init__(self):
        super(CallbackModule, self).__init__()
        self._log_path = None
        self._include_tags = set()
        self._include_modules = set()
        self._name_pattern = None
        self._only_changed = False
        self._redact_keys = set()
        self._task_start_times = {}  # (host, task_uuid) -> start_time

        # ensure directory if default path is used and doesn't exist yet
        # actual path is resolved in set_options
        self._fp = None

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super(CallbackModule, self).set_options(task_keys=task_keys, var_options=var_options, direct=direct)

        self._log_path = self.get_option("log_path")
        include_tags = self.get_option("include_tags") or ""
        include_modules = self.get_option("include_modules") or ""
        name_regex = self.get_option("include_names_regex") or ""
        self._only_changed = bool(self.get_option("only_changed"))
        redact_vars = self.get_option("redact_vars") or ""

        self._include_tags = set(t.strip() for t in include_tags.split(",") if t.strip())
        self._include_modules = set(m.strip() for m in include_modules.split(",") if m.strip())
        self._name_pattern = re.compile(name_regex) if name_regex else None
        self._redact_keys = set(k.strip().lower() for k in redact_vars.split(",") if k.strip())

        # open file handle
        log_dir = os.path.dirname(os.path.abspath(self._log_path)) or "."
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        # buffered text writer with utf-8
        self._fp = io.open(self._log_path, "a", encoding="utf-8", buffering=1)

    def _should_log_task(self, task, result=None, status=None) -> bool:
        """
        Decide whether to log based on tag/module/name regex and only_changed flag.
        """
        # tags
        if self._include_tags:
            task_tags = set(getattr(task, "tags", []) or [])
            if not (task_tags & self._include_tags):
                return False

        # module/action
        if self._include_modules:
            action = getattr(task, "action", None) or getattr(task, "_action", "")
            if action not in self._include_modules:
                return False

        # name regex
        if self._name_pattern:
            name = getattr(task, "name", "") or task.get_name().strip()
            if not self._name_pattern.search(name):
                return False

        # only_changed option (still log failures/unreachable)
        if self._only_changed and result is not None and status in ("ok", "skipped"):
            r = getattr(result, "_result", {}) or {}
            changed = bool(r.get("changed", False))
            if not changed:
                return False

        return True

    def _redact(self, obj):
        # recursively redact specified keys
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k.lower() in self._redact_keys:
                    out[k] = "***REDACTED***"
                else:
                    out[k] = self._redact(v)
            return out
        elif isinstance(obj, list):
            return [self._redact(v) for v in obj]
        return obj

    def _write_event(self, payload: dict):
        payload["@timestamp"] = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
        self._fp.write(json.dumps(payload, ensure_ascii=False) + "\n")

    # ---- Task lifecycle ----

    def v2_playbook_on_task_start(self, task, is_conditional):
        if not self._should_log_task(task):
            return
        # mark task start for duration metrics per host later
        for host in getattr(task, "_play", {}).get_hosts() if hasattr(task, "_play") else []:
            key = (str(host), task._uuid)
            self._task_start_times[key] = time.time()

        self._write_event({
            "event": "task_start",
            "play": getattr(getattr(task, "_block", None), "_play", None).get_name() if hasattr(getattr(task, "_block", None), "_play") else None,
            "task_name": task.get_name().strip(),
            "task_uuid": task._uuid,
            "action": getattr(task, "action", None) or getattr(task, "_action", ""),
            "tags": list(getattr(task, "tags", []) or []),
            "is_conditional": bool(is_conditional),
            "path": getattr(task, "get_path", lambda: None)(),
        })

    def _on_any_result(self, result, status: str):
        task = result._task
        if not self._should_log_task(task, result=result, status=status):
            return

        host = result._host.get_name()
        key = (host, task._uuid)
        start_t = self._task_start_times.pop(key, None)
        duration_ms = int((time.time() - start_t) * 1000) if start_t else None

        r = getattr(result, "_result", {}) or {}
        payload = {
            "event": "task_result",
            "status": status,  # ok/changed/failed/skipped/unreachable
            "changed": bool(r.get("changed", False)),
            "host": host,
            "play": getattr(getattr(task, "_block", None), "_play", None).get_name() if hasattr(getattr(task, "_block", None), "_play") else None,
            "task_name": task.get_name().strip(),
            "task_uuid": task._uuid,
            "action": getattr(task, "action", None) or getattr(task, "_action", ""),
            "tags": list(getattr(task, "tags", []) or []),
            "path": getattr(task, "get_path", lambda: None)(),
            "duration_ms": duration_ms,
            # safe subset of fields commonly useful
            "rc": r.get("rc"),
            "stdout": r.get("stdout"),
            "stderr": r.get("stderr"),
            "msg": r.get("msg"),
            "invocation": self._redact((r.get("invocation") or {}).get("module_args", {})),
        }

        # redact entire result (optional, here we keep a minimal 'result' field)
        minimal = {k: v for k, v in r.items() if k in ("rc", "stdout", "stderr", "msg", "changed", "failed")}
        payload["result"] = self._redact(minimal)

        self._write_event(payload)

    def v2_runner_on_ok(self, result):
        self._on_any_result(result, status="changed" if result._result.get("changed") else "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._on_any_result(result, status="failed")

    def v2_runner_on_unreachable(self, result):
        self._on_any_result(result, status="unreachable")

    def v2_runner_on_skipped(self, result):
        self._on_any_result(result, status="skipped")

    def __del__(self):
        try:
            if self._fp:
                self._fp.close()
        except Exception:
            pass
What it captures

task_start events and task_result events with status (ok/changed/failed/skipped/unreachable), host, duration_ms, rc/stdout/stderr/msg, module args (redacted), tags, task path, etc.

How it filters

include_tags, include_modules, include_names_regex

only_changed=true to keep the log signal-heavy

2) Enable the plugin (ansible.cfg)
ini
Copy
Edit
[defaults]
# Where Ansible should look for your custom callbacks
callback_plugins = ./callback_plugins

# Enable this callback (space/comma separated if enabling multiple)
callbacks_enabled = task_logger

# (For older Ansible) the old name is:
# callback_whitelist = task_logger

[callback_task_logger]
# Plugin options
log_path = ./logs/tasks.jsonl
include_tags = deploy,db
include_modules = shell,command,template,copy
include_names_regex = .*
only_changed = False
redact_vars = password,passwd,token,secret,apikey,api_key
Tip: You can override any of these with environment variables like TASK_LOGGER_LOG_PATH=/tmp/x.jsonl.

3) Minimal example (playbook.yml)
yaml
Copy
Edit
- name: Demo play
  hosts: all
  gather_facts: false

  tasks:
    - name: Template a config (logged if tag matches)
      ansible.builtin.template:
        src: config.j2
        dest: /tmp/config.conf
      tags: ["deploy"]

    - name: Run a health check (logged if module/tag matches)
      ansible.builtin.shell: "echo healthy && exit 0"
      register: health
      tags: ["db"]

    - name: This task will be ignored by the logger if it doesn't match filters
      ansible.builtin.debug:
        msg: "Noise"
      tags: ["misc"]
inventory.ini (example):

ini
Copy
Edit
[all]
localhost ansible_connection=local
Run:

bash
Copy
Edit
ansible-playbook -i inventory.ini playbook.yml
You’ll get ./logs/tasks.jsonl with entries like:

json
Copy
Edit
{"@timestamp":"2025-08-10T13:05:21.123Z","event":"task_start","task_name":"Template a config", ...}
{"@timestamp":"2025-08-10T13:05:21.567Z","event":"task_result","status":"changed","host":"localhost","action":"template","duration_ms":142,"rc":0,...}
{"@timestamp":"2025-08-10T13:05:21.890Z","event":"task_result","status":"ok","host":"localhost","action":"shell","stdout":"healthy\n",...}
Variations & enhancements
Ship to HTTP: replace _write_event to POST to an internal log collector.

Size rotation: before append, check file size and rotate (e.g., rename with timestamp).

Per-run correlation: add a run_id env var (TASK_LOGGER_RUN_ID) and include in each event.

Performance: buffer to memory and flush every N events; or use a background thread (but keep it simple first).

When a different approach is better
You need to transform/validate inputs before module execution: consider an action plugin (intercepts module invocation).

One task’s output should feed an external system immediately and only for that task: a custom module might be simpler.

Reactive automation from Ansible events: consider EDA (Event-Driven Ansible) with the controller or rulebooks.

For generic, audit-style, cross-play logging, the callback plugin above is the sweet spot.

If you tell me your exact filters (tags/modules/task name patterns) and where you want the data to go (file, HTTP, syslog, ELK), I can tailor the plugin snippet to your setup.
```

```py
def find_max_closest(numbers, target):
  """
  Finds the closest number in a list to a target.
  In case of a tie, it returns the larger number.

  Args:
    numbers: A list of numbers.
    target: The target number.

  Returns:
    The number in the list that is closest to the target,
    preferring the maximum in a tie.
  """
  return min(numbers, key=lambda x: (abs(x - target), -x))

# Your list of numbers
my_list = [8, 16, 18, 20]
target_number = 24

# Find the closest number, getting the max in a tie
closest_number = find_max_closest(my_list, target_number)


# Print the result
print(f"The list of numbers is: {my_list}")
print(f"The target number is: {target_number}")
print(f"The max closest number is: {closest_number}")
```

``` py
import ssl
from vmware.vapi.lib.connect import get_requests_connector
from vmware.vapi.stdlib.client.factories import StubConfigurationFactory
from vmware.vapi.vsphere.client import create_vsphere_client

def get_resources_with_multiple_tags(vcenter_host, username, password, tag_category_pairs, disable_ssl_verification=True):
    """
    Connects to vCenter and retrieves a list of VMs with any of the specified tags.

    Args:
        vcenter_host (str): The IP address or FQDN of the vCenter Server.
        username (str): The vCenter username.
        password (str): The vCenter password.
        tag_category_pairs (list): A list of dictionaries, where each dictionary
                                   has 'tag_name' and 'category_name' keys.
                                   Example: [{'tag_name': 'WebTier', 'category_name': 'Application'},
                                             {'tag_name': 'Prod', 'category_name': 'Environment'}]
        disable_ssl_verification (bool): If True, disables SSL certificate verification.
                                          Use with caution in production.

    Returns:
        list: A list of dictionaries, where each dictionary contains
              'name', 'id', 'type', and 'matching_tags' (a list of
              'category:tag_name' strings that matched the input criteria).
              Returns an empty list if no resources are found or an error occurs.
    """

    session = None
    if disable_ssl_verification:
        # Disable SSL certificate verification (use only for testing/development)
        context = ssl._create_unverified_context()
        session = get_requests_connector(ssl_context=context)._requests_session

    try:
        # Create a vSphere client
        vsphere_client = create_vsphere_client(
            server=vcenter_host,
            username=username,
            password=password,
            session=session
        )

        print(f"Successfully connected to vCenter: {vcenter_host}")

        # 1. Get all Categories and Tags once to build lookup maps
        category_svc = vsphere_client.tagging.Category
        all_categories = category_svc.list()
        category_name_to_id = {cat.name: cat.id for cat in all_categories}
        category_id_to_name = {cat.id: cat.name for cat in all_categories}

        tag_svc = vsphere_client.tagging.Tag
        all_tags = tag_svc.list()
        # Map tag_name and category_id to tag_id for quick lookup
        tag_lookup_map = {}
        tag_id_to_full_name = {} # For formatting output tags
        for tag in all_tags:
            if tag.category_id in category_id_to_name: # Ensure category exists
                cat_name = category_id_to_name[tag.category_id]
                tag_lookup_map[(tag.name, cat_name)] = tag.id
                tag_id_to_full_name[tag.id] = f"{cat_name}:{tag.name}"

        # 2. Identify the specific Tag IDs based on input tag_category_pairs
        target_tag_ids = set()
        for pair in tag_category_pairs:
            tag_name = pair['tag_name']
            category_name = pair['category_name']
            
            tag_id = tag_lookup_map.get((tag_name, category_name))
            if tag_id:
                target_tag_ids.add(tag_id)
            else:
                print(f"Warning: Tag '{tag_name}' in category '{category_name}' not found.")

        if not target_tag_ids:
            print("No valid tag IDs found from the provided input list. Exiting.")
            return []
        
        print(f"Searching for resources associated with {len(target_tag_ids)} specified tags.")

        # 3. List objects attached to ANY of these specific tag IDs
        tag_association_svc = vsphere_client.tagging.TagAssociation
        
        # Use list_attached_objects_on_tags for efficiency with multiple tags
        # This method returns a list of com.vmware.cis.tagging.TagAssociation.ObjectAttachedToTag
        # Each item in the list represents an object and the tags from the input list that are attached to it.
        attached_objects_info = tag_association_svc.list_attached_objects_on_tags(list(target_tag_ids))
        
        if not attached_objects_info:
            print("No resources found with any of the specified tags.")
            return []

        # 4. Process results and retrieve VM details, avoiding duplicates
        # Use a dictionary to store unique VMs by their ID
        unique_vms_found = {}
        vm_svc = vsphere_client.vcenter.VM
        all_vms = vm_svc.list()
        vm_id_to_name_map = {vm.vm: vm.name for vm in all_vms}

        for obj_info in attached_objects_info:
            obj_id = obj_info.object_id.id
            obj_type = obj_info.object_id.type
            
            # Filter for Virtual Machines (or other types as needed)
            if obj_type == 'VirtualMachine':
                vm_name = vm_id_to_name_map.get(obj_id)
                if vm_name:
                    if obj_id not in unique_vms_found:
                        unique_vms_found[obj_id] = {
                            'name': vm_name,
                            'id': obj_id,
                            'type': obj_type,
                            'matching_tags': []
                        }
                    
                    # Add all matching tags for this VM from the input list
                    for tag_id_matched in obj_info.tag_ids:
                        full_tag_name = tag_id_to_full_name.get(tag_id_matched)
                        if full_tag_name and full_tag_name not in unique_vms_found[obj_id]['matching_tags']:
                            unique_vms_found[obj_id]['matching_tags'].append(full_tag_name)
                else:
                    print(f"Warning: Could not find details for VM ID: {obj_id}")

        return list(unique_vms_found.values())

    except Exception as e:
        print(f"An error occurred: {e}")
        return []

# --- Configuration ---
VCENTER_HOST = "your_vcenter_ip_or_fqdn" # 👈 Replace with your vCenter IP or FQDN
VCENTER_USERNAME = "your_vcenter_username" # 👈 Replace with your vCenter username
VCENTER_PASSWORD = "your_vcenter_password" # 👈 Replace with your vCenter password
DISABLE_SSL_VERIFICATION = True # 👈 Set to False for production environments with valid SSL certificates

# --- Inputs for Tag Names and Categories (as a list of dictionaries) ---
TARGET_TAG_CATEGORY_PAIRS = [ # 👈 Customize this list
    {'tag_name': 'WebTier', 'category_name': 'Application'},
    {'tag_name': 'Database', 'category_name': 'Application'},
    {'tag_name': 'Production', 'category_name': 'Environment'},
    {'tag_name': 'Linux', 'category_name': 'OS'}
]

# --- Run the script ---
if __name__ == "__main__":
    
    print(f"\nSearching for resources with any of the following tag/category combinations:")
    for pair in TARGET_TAG_CATEGORY_PAIRS:
        print(f"  - Tag: '{pair['tag_name']}', Category: '{pair['category_name']}'")

    resources_found = get_resources_with_multiple_tags(
        VCENTER_HOST,
        VCENTER_USERNAME,
        VCENTER_PASSWORD,
        TARGET_TAG_CATEGORY_PAIRS,
        DISABLE_SSL_VERIFICATION
    )

    if resources_found:
        print("\n--- Resources Found ---")
        for resource in resources_found:
            print(f"Name: {resource['name']}")
            print(f"  ID: {resource['id']}")
            print(f"  Type: {resource['type']}")
            if resource['matching_tags']:
                print(f"  Matching Tags: {', '.join(resource['matching_tags'])}")
            print("-" * 30)
    else:
        print("No resources found matching the specified tags and categories, or an error occurred.")
```

```py
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl
import atexit

# --- Configuration ---
VCENTER_HOST = "your_vcenter_ip_or_hostname"
VCENTER_USER = "your_vcenter_username"
VCENTER_PASSWORD = "your_vcenter_password"

# The name of the cluster you want to get details for (from your image)
TARGET_CLUSTER_NAME = "GB-WGDCLAB-CL04-TL-HP-SANDPIT"

# --- Helper Functions ---

def get_obj_by_name(content, vimtype, name):
    """
    Helper to find a Managed Object by its type and name.
    """
    obj = None
    container = content.viewManager.CreateContainerView(
        content.rootFolder, [vimtype], True
    )
    for c in container.view:
        if c.name == name:
            obj = c
            break
    container.Destroy()
    return obj

def convert_bytes_to_gb(bytes_value):
    """
    Converts bytes to gigabytes.
    """
    if bytes_value is None:
        return 0
    return bytes_value / (1024**3)

def convert_bytes_to_mb(bytes_value):
    """
    Converts bytes to megabytes.
    """
    if bytes_value is None:
        return 0
    return bytes_value / (1024**2)

# --- Main Script ---

def main():
    # Disable SSL certificate verification (for lab environments, use with caution in production)
    s_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    s_context.check_hostname = False
    s_context.verify_mode = ssl.CERT_NONE

    si = None
    try:
        si = SmartConnect(
            host=VCENTER_HOST,
            user=VCENTER_USER,
            pwd=VCENTER_PASSWORD,
            sslContext=s_context
        )
        atexit.register(Disconnect, si)

        content = si.RetrieveContent()

        print(f"Connecting to vCenter: {VCENTER_HOST}\n")
        print(f"Searching for cluster: '{TARGET_CLUSTER_NAME}'")

        cluster = get_obj_by_name(content, vim.ClusterComputeResource, TARGET_CLUSTER_NAME)

        if cluster:
            print(f"\n--- Cluster: {cluster.name} (MoRef ID: {cluster._moId}) ---")

            # Get Cluster Capacity and Usage
            # ClusterComputeResource has a 'summary' property for aggregated data
            cluster_summary = cluster.summary
            
            # For Cluster, overall CPU/Memory usage are directly on the summary, not quickStats
            cluster_total_cpu_mhz = cluster_summary.totalCpu
            cluster_total_mem_mb = cluster_summary.totalMemory / (1024 * 1024) # Convert bytes to MB
            
            # Correct access for current usage
            cluster_current_cpu_usage = cluster_summary.currentCpuUsage
            cluster_current_memory_usage = cluster_summary.currentMemoryUsage

            print("\n  Cluster Capacity and Usage:")
            print("    CPU:")
            print(f"      Total Capacity: {cluster_total_cpu_mhz:.2f} MHz")
            print(f"      Current Usage: {cluster_current_cpu_usage:.2f} MHz")
            cpu_usage_percent = (cluster_current_cpu_usage / cluster_total_cpu_mhz) * 100 if cluster_total_cpu_mhz > 0 else 0
            print(f"      Usage Percentage: {cpu_usage_percent:.2f}%")

            print("    Memory:")
            print(f"      Total Capacity: {cluster_total_mem_mb:.2f} MB")
            print(f"      Current Usage: {cluster_current_memory_usage:.2f} MB")
            mem_usage_percent = (cluster_current_memory_usage / cluster_total_mem_mb) * 100 if cluster_total_mem_mb > 0 else 0
            print(f"      Usage Percentage: {mem_usage_percent:.2f}%")

            # For Storage, we need to aggregate from datastores attached to the cluster
            total_storage_capacity_gb = 0
            total_storage_free_gb = 0
            total_storage_provisioned_gb = 0 # This represents provisioned space across all VMs
            total_storage_used_gb = 0 # This is actual used space on datastores

            for datastore in cluster.datastore:
                ds_summary = datastore.summary
                total_storage_capacity_gb += convert_bytes_to_gb(ds_summary.capacity)
                total_storage_free_gb += convert_bytes_to_gb(ds_summary.freeSpace)
                total_storage_used_gb += convert_bytes_to_gb(ds_summary.capacity - ds_summary.freeSpace)

                if hasattr(ds_summary, 'uncommitted'):
                    total_storage_provisioned_gb += convert_bytes_to_gb(ds_summary.capacity - ds_summary.freeSpace + ds_summary.uncommitted)
                else:
                    total_storage_provisioned_gb += convert_bytes_to_gb(ds_summary.capacity - ds_summary.freeSpace)


            storage_usage_percent = (total_storage_used_gb / total_storage_capacity_gb) * 100 if total_storage_capacity_gb > 0 else 0

            print("    Storage (Aggregated from shared Datastores):")
            print(f"      Total Capacity: {total_storage_capacity_gb:.2f} GB")
            print(f"      Used: {total_storage_used_gb:.2f} GB")
            print(f"      Free: {total_storage_free_gb:.2f} GB")
            print(f"      Usage Percentage: {storage_usage_percent:.2f}%")
            print(f"      Provisioned: {total_storage_provisioned_gb:.2f} GB (may exceed capacity with thin provisioning)")


            # Get Host Capacity and Usage for each host in the cluster
            print("\n  --- Individual Host Details within the Cluster ---")
            if not cluster.host:
                print("    No hosts found in this cluster.")
            else:
                for host in cluster.host:
                    print(f"\n    Host: {host.name} (MoRef ID: {host._moId})")

                    host_summary = host.summary
                    host_hardware = host.hardware
                    host_quick_stats = host_summary.quickStats # This is correct for HostSystem.Summary

                    # CPU
                    host_cpu_capacity_mhz = host_hardware.cpuInfo.numCpuCores * host_hardware.cpuInfo.hz / 1000000
                    host_cpu_usage_mhz = host_quick_stats.overallCpuUsage
                    host_cpu_usage_percent = (host_cpu_usage_mhz / host_cpu_capacity_mhz) * 100 if host_cpu_capacity_mhz > 0 else 0

                    print("      CPU:")
                    print(f"        Total Capacity: {host_cpu_capacity_mhz:.2f} MHz")
                    print(f"        Current Usage: {host_cpu_usage_mhz:.2f} MHz")
                    print(f"        Usage Percentage: {host_cpu_usage_percent:.2f}%")

                    # Memory
                    host_mem_capacity_mb = host_hardware.memorySize / (1024 * 1024) # Convert bytes to MB
                    host_mem_usage_mb = host_quick_stats.overallMemoryUsage
                    host_mem_usage_percent = (host_mem_usage_mb / host_mem_capacity_mb) * 100 if host_mem_capacity_mb > 0 else 0

                    print("      Memory:")
                    print(f"        Total Capacity: {host_mem_capacity_mb:.2f} MB")
                    print(f"        Current Usage: {host_mem_usage_mb:.2f} MB")
                    print(f"        Usage Percentage: {host_mem_usage_percent:.2f}%")

                    # Storage for Host (Local Datastores + shared datastores accessible by this host)
                    host_total_storage_capacity_gb = 0
                    host_total_storage_free_gb = 0
                    host_total_storage_used_gb = 0

                    for ds in host.datastore:
                        ds_summary = ds.summary
                        host_total_storage_capacity_gb += convert_bytes_to_gb(ds_summary.capacity)
                        host_total_storage_free_gb += convert_bytes_to_gb(ds_summary.freeSpace)
                        host_total_storage_used_gb += convert_bytes_to_gb(ds_summary.capacity - ds_summary.freeSpace)

                    host_storage_usage_percent = (host_total_storage_used_gb / host_total_storage_capacity_gb) * 100 if host_total_storage_capacity_gb > 0 else 0

                    print("      Storage (Accessible Datastores):")
                    print(f"        Total Capacity: {host_total_storage_capacity_gb:.2f} GB")
                    print(f"        Used: {host_total_storage_used_gb:.2f} GB")
                    print(f"        Free: {host_total_storage_free_gb:.2f} GB")
                    print(f"        Usage Percentage: {host_storage_usage_percent:.2f}%")

        else:
            print(f"Cluster '{TARGET_CLUSTER_NAME}' not found.")

    except vim.fault.InvalidLogin as e:
        print(f"Authentication error: {e.msg}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if si:
            Disconnect(si)

if __name__ == "__main__":
    main()
```

```py
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl
import atexit

# --- Configuration ---
VCENTER_HOST = "your_vcenter_ip_or_hostname"
VCENTER_USER = "your_vcenter_username"
VCENTER_PASSWORD = "your_vcenter_password"

# The name of the datastore you want to check (from your image)
TARGET_DATASTORE_NAME = "GB-WGDCLAB-CL04-TL-HP-SANDPIT-DS"

# --- Helper Function ---

def get_obj_by_name(content, vimtype, name):
    """
    Helper to find a Managed Object by its type and name.
    """
    obj = None
    container = content.viewManager.CreateContainerView(
        content.rootFolder, [vimtype], True
    )
    for c in container.view:
        if c.name == name:
            obj = c
            break
    container.Destroy()
    return obj

# --- Main Script ---

def main():
    # Disable SSL certificate verification (for lab environments, use with caution in production)
    s_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    s_context.check_hostname = False
    s_context.verify_mode = ssl.CERT_NONE

    si = None
    try:
        si = SmartConnect(
            host=VCENTER_HOST,
            user=VCENTER_USER,
            pwd=VCENTER_PASSWORD,
            sslContext=s_context
        )
        atexit.register(Disconnect, si)

        content = si.RetrieveContent()

        print(f"Connecting to vCenter: {VCENTER_HOST}\n")
        print(f"Searching for datastore: '{TARGET_DATASTORE_NAME}'")

        datastore = get_obj_by_name(content, vim.Datastore, TARGET_DATASTORE_NAME)

        if datastore:
            print(f"Found datastore: '{datastore.name}' (MoRef ID: {datastore._moId})")

            # Check if the datastore is part of a Datastore Cluster
            # A datastore's parent is its Datacenter unless it's in a Datastore Cluster.
            # The more robust way to check for a Datastore Cluster association
            # is through its parent property, which would be the DatastoreCluster object itself.
            # However, for datastores, the folder structure is often like:
            # Datacenter -> DatastoreFolder -> Datastore OR DatastoreCluster -> Datastore

            # The 'parent' property of a Datastore object refers to its immediate parent
            # in the inventory hierarchy. If it's directly under a DatastoreFolder
            # then its parent will be that folder.
            # If it's part of a Datastore Cluster, its immediate parent *in the inventory view*
            # is often the Datastore Cluster object itself.

            # Let's verify the parent type
            if datastore.parent:
                if isinstance(datastore.parent, vim.StoragePod):
                    print(f"  This datastore is part of a Datastore Cluster (StoragePod): '{datastore.parent.name}'")
                elif isinstance(datastore.parent, vim.Folder):
                    print(f"  This datastore is in folder: '{datastore.parent.name}'. Checking for association via StorageResourceManager...")
                    # Even if the direct parent is a folder, it might still be associated
                    # with a StoragePod through StorageResourceManager.
                    # This is the most reliable way to find which StoragePod owns a Datastore.

                    # Iterate through all StoragePods (Datastore Clusters)
                    # and check their child datastores.
                    storage_pods = content.viewManager.CreateContainerView(
                        content.rootFolder, [vim.StoragePod], True
                    ).view

                    found_in_cluster = False
                    for pod in storage_pods:
                        if datastore in pod.childEntity:
                            print(f"  This datastore is associated with Datastore Cluster: '{pod.name}'")
                            found_in_cluster = True
                            break
                    if not found_in_cluster:
                        print("  This datastore is not found within any Datastore Cluster.")
                else:
                    print(f"  This datastore's parent is of type: {type(datastore.parent)}")
            else:
                print("  This datastore has no parent (unlikely in typical setups).")

        else:
            print(f"Datastore '{TARGET_DATASTORE_NAME}' not found.")

    except vim.fault.InvalidLogin as e:
        print(f"Authentication error: {e.msg}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if si:
            Disconnect(si)

if __name__ == "__main__":
    main()
```

```py
from pyVim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim
import atexit
import ssl
import requests
import json

# --- Configuration ---
VCENTER_HOST = "your_vcenter_ip_or_hostname"
VCENTER_USERNAME = "your_vcenter_username"
VCENTER_PASSWORD = "your_vcenter_password"

# --- REST API Helper Functions (from previous examples) ---
def get_session_id(vcenter_host, username, password):
    """Authenticates with vCenter REST API and returns a session ID."""
    auth_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"Accept": "application/json"}
    try:
        response = requests.post(auth_url, auth=(username, password), headers=headers, verify=False) # verify=False for dev/test
        response.raise_for_status()
        session_id = response.json().get("value")
        # print("✅ Successfully obtained vCenter REST API session ID.")
        return session_id
    except requests.exceptions.RequestException as e:
        print(f"❌ Error during REST API authentication: {e}")
        return None

def logout_rest_api(vcenter_host, session_id):
    """Logs out from the vCenter REST API session."""
    logout_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"vmware-api-session-id": session_id}
    try:
        requests.delete(logout_url, headers=headers, verify=False) # verify=False for dev/test
        # print("👋 Successfully logged out from vCenter REST API session.")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error during REST API logout: {e}")

def get_tags_for_object_rest(vcenter_host, session_id, object_id):
    """Retrieves tag IDs associated with a specific vCenter object using REST API."""
    tag_association_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/tag-association?object_id={object_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(tag_association_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value", []) # Returns a list of tag_ids
    except requests.exceptions.RequestException as e:
        # print(f"Warning: Could not retrieve tags for object ID {object_id} via REST: {e}")
        return []

def get_tag_details_rest(vcenter_host, session_id, tag_id):
    """Retrieves details of a specific tag using REST API."""
    tag_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/tag/{tag_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(tag_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value")
    except requests.exceptions.RequestException as e:
        # print(f"Warning: Could not retrieve details for tag ID {tag_id} via REST: {e}")
        return None

def get_category_details_rest(vcenter_host, session_id, category_id):
    """Retrieves details of a specific tag category using REST API."""
    category_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/category/{category_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(category_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value")
    except requests.exceptions.RequestException as e:
        # print(f"Warning: Could not retrieve details for category ID {category_id} via REST: {e}")
        return None

# --- Main PyVmomi Logic ---
def get_vcenter_networks_clusters_and_tags(host, user, pwd):
    # PyVmomi SSL context (unverified for development)
    context = None
    if hasattr(ssl, '_create_unverified_context'):
        context = ssl._create_unverified_context()

    si = None
    rest_session_id = None
    try:
        # Connect to PyVmomi
        print("🚀 Connecting to vCenter via PyVmomi...")
        si = SmartConnectNoSSL(host=host, user=user, pwd=pwd, port=443, sslContext=context)
        atexit.register(Disconnect, si) # Ensure PyVmomi session disconnects on exit
        print("✅ PyVmomi connection established.")

        content = si.RetrieveContent()

        # Connect to REST API for Tags
        print("🌐 Obtaining REST API session for Tagging data...")
        rest_session_id = get_session_id(host, user, pwd)
        if not rest_session_id:
            return # Exit if REST auth fails
        print("✅ REST API session obtained.")

        # Dictionary to store Network MOR -> {Network Name, Type, Associated Clusters, Tags, etc.}
        networks_info = {}
        
        # --- Step 1: Get all Networks (Standard and Distributed Port Groups) using PyVmomi ---
        # We need this to map network MORs to names and initial details
        network_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.Network, vim.dvs.DistributedVirtualPortgroup], True)
        all_networks_objects = network_view.view
        network_view.Destroy() # Destroy the view to free resources

        # Populate initial networks_info with basic details and placeholder for tags/clusters
        for network_obj in all_networks_objects:
            networks_info[network_obj._moId] = {
                "name": network_obj.name,
                "id": network_obj._moId,
                "type": "Distributed Port Group" if isinstance(network_obj, vim.dvs.DistributedVirtualPortgroup) else "Standard Port Group",
                "associated_clusters": set(), # Use a set to avoid duplicate cluster names
                "tags": [], # To be populated by REST API later
                "custom_attributes": {} # Placeholder, generally better with PyVmomi but complex for Networks
            }
            if isinstance(network_obj, vim.dvs.DistributedVirtualPortgroup):
                if hasattr(network_obj.config.distributedVirtualSwitch, 'name'): # Check if DVS name is accessible
                    networks_info[network_obj._moId]['distributed_switch_name'] = network_obj.config.distributedVirtualSwitch.name
                networks_info[network_obj._moId]['distributed_switch_id'] = network_obj.config.distributedVirtualSwitch._moId


        # --- Step 2: Get Clusters, Hosts, and infer Network-to-Cluster mapping using PyVmomi ---
        print("\n🔎 Discovering Network-to-Cluster Associations via Host Network Config...")
        cluster_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.ClusterComputeResource], True)
        clusters = cluster_view.view
        cluster_view.Destroy()

        cluster_details_output = []
        for cluster in clusters:
            cluster_name = cluster.name
            cluster_id = cluster._moId
            cluster_details_output.append({"name": cluster_name, "id": cluster_id})

            # Retrieve only 'host' property for cluster to get HostSystem MORs efficiently
            cluster_props = content.propertyCollector.RetrieveContents(
                [vim.PropertyCollector.FilterSpec(
                    objectSet=[vim.PropertyCollector.ObjectSpec(obj=cluster, skip=False)],
                    propSet=[vim.PropertyCollector.PropertySpec(type=vim.ClusterComputeResource, pathSet=['host'])]
                )]
            )
            
            host_mors_in_cluster = []
            if cluster_props:
                for obj_cont in cluster_props:
                    for prop in obj_cont.propSet:
                        if prop.name == 'host' and prop.val:
                            host_mors_in_cluster.extend(prop.val)
                            break
            
            # For each host in the cluster, get its network configuration
            for host_mor in host_mors_in_cluster:
                # Retrieve only 'config.network' property for each host efficiently
                host_network_props = content.propertyCollector.RetrieveContents(
                    [vim.PropertyCollector.FilterSpec(
                        objectSet=[vim.PropertyCollector.ObjectSpec(obj=host_mor, skip=False)],
                        propSet=[vim.PropertyCollector.PropertySpec(type=vim.HostSystem, pathSet=['config.network'])]
                    )]
                )
                
                host_network_config = None
                if host_network_props:
                    for obj_cont in host_network_props:
                        for prop in obj_cont.propSet:
                            if prop.name == 'config.network':
                                host_network_config = prop.val
                                break
                        if host_network_config:
                            break

                if host_network_config:
                    # Check Standard Virtual Switches (Standard Port Groups)
                    for vswitch in host_network_config.vswitch:
                        for pg in vswitch.portgroup:
                            network_mor = pg.network
                            if network_mor and network_mor._moId in networks_info:
                                networks_info[network_mor._moId]["associated_clusters"].add(cluster_name)
                    
                    # Check all HostPortGroup objects (covers both standard and distributed)
                    # The 'network' property on HostPortGroup points to vim.Network or vim.dvs.DistributedVirtualPortgroup
                    for pg in host_network_config.portgroup:
                        if hasattr(pg, 'network') and pg.network and pg.network._moId in networks_info:
                            networks_info[pg.network._moId]["associated_clusters"].add(cluster_name)
        
        # --- Step 3: Populate Tags and Category Details using REST API ---
        print("\n🏷️ Retrieving Tag and Category details via REST API...")
        category_cache = {} # Cache for category details to avoid redundant API calls

        for net_id, net_data in networks_info.items():
            # Get tags associated with this network's MOR using REST API
            associated_tag_ids = get_tags_for_object_rest(host, rest_session_id, net_id)
            
            for tag_id in associated_tag_ids:
                tag_details = get_tag_details_rest(host, rest_session_id, tag_id)
                if tag_details:
                    tag_name = tag_details.get('name')
                    tag_description = tag_details.get('description', 'N/A')
                    category_id = tag_details.get('category_id')

                    category_name = "N/A"
                    category_cardinality = "N/A"

                    if category_id:
                        if category_id not in category_cache:
                            cat_details = get_category_details_rest(host, rest_session_id, category_id)
                            if cat_details:
                                category_cache[category_id] = {
                                    "name": cat_details.get('name'),
                                    "cardinality": cat_details.get('cardinality')
                                }
                            else:
                                category_cache[category_id] = {"name": "Unknown", "cardinality": "Unknown"}
                        
                        category_info = category_cache.get(category_id)
                        if category_info:
                            category_name = category_info['name']
                            category_cardinality = category_info['cardinality']

                    net_data["tags"].append({
                        "name": tag_name,
                        "description": tag_description,
                        "category": {
                            "name": category_name,
                            "id": category_id,
                            "cardinality": category_cardinality
                        }
                    })
        
        # --- Final Output ---
        print("\n--- Final Summary of Networks, Clusters, and Tags ---")

        print("\n## Clusters:")
        if cluster_details_output:
            for cluster in cluster_details_output:
                print(f"- **Name**: {cluster['name']}, **ID**: {cluster['id']}")
        else:
            print("No clusters found.")

        print("\n## Networks:")
        if networks_info:
            sorted_networks = sorted(networks_info.values(), key=lambda x: x['name'])
            
            networks_by_type_and_association = {}
            for net_data in sorted_networks:
                net_type = net_data['type']
                associated_clusters_list = sorted(list(net_data['associated_clusters']))
                cluster_key = ", ".join(associated_clusters_list) if associated_clusters_list else "Unassociated/Global"
                
                if net_type not in networks_by_type_and_association:
                    networks_by_type_and_association[net_type] = {}
                if cluster_key not in networks_by_type_and_association[net_type]:
                    networks_by_type_and_association[net_type][cluster_key] = []
                
                networks_by_type_and_association[net_type][cluster_key].append(net_data)

            for net_type, cluster_groups in networks_by_type_and_association.items():
                print(f"\n### {net_type.replace('_', ' ').title()} Networks:")
                for cluster_key, nets_list in cluster_groups.items():
                    print(f"\n  Associated With: {cluster_key}")
                    for net_data in nets_list:
                        print(f"    - **Name**: {net_data['name']}, **ID**: {net_data['id']}")
                        if net_data.get('distributed_switch_name'):
                            print(f"      (Belongs to Distributed Switch: {net_data['distributed_switch_name']} / {net_data['distributed_switch_id']})")
                        
                        if net_data['tags']:
                            print("      **Tags**:")
                            for tag in net_data['tags']:
                                print(f"        - **Tag**: {tag['name']}")
                                print(f"          Description: {tag['description']}")
                                print(f"          **Category**: {tag['category']['name']} (Cardinality: {tag['category']['cardinality']})")
                        else:
                            print("      No tags associated.")

                        if net_data['custom_attributes']:
                            print("      **Custom Attributes**:")
                            for key, value in net_data['custom_attributes'].items():
                                print(f"        - {key}: {value}")
                        else:
                            print("      No custom attributes found (Requires more specific PyVmomi calls or may not be available on Networks).")
        else:
            print("No networks found.")

    except vim.fault.InvalidLogin as e:
        print(f"❌ Login failed: {e.msg}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Network or REST API error: {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
    finally:
        if si:
            Disconnect(si)
        if rest_session_id:
            logout_rest_api(host, rest_session_id)

# --- Execute the script ---
if __name__ == "__main__":
    # !!! IMPORTANT: Replace with your actual vCenter details !!!
    VCENTER_HOST = "your_vcenter_ip_or_hostname"
    VCENTER_USERNAME = "your_vcenter_username"
    VCENTER_PASSWORD = "your_vcenter_password"
    
    if VCENTER_HOST == "your_vcenter_ip_or_hostname":
        print("Please update VCENTER_HOST, VCENTER_USERNAME, and VCENTER_PASSWORD with your vCenter details.")
    else:
        get_vcenter_networks_clusters_and_tags(VCENTER_HOST, VCENTER_USERNAME, VCENTER_PASSWORD)
```

You've hit upon one of the more challenging aspects of retrieving network topology with the vCenter REST API directly: there isn't a single, straightforward API endpoint that directly links a network object (like a port group) to a specific cluster.

This is because of the way vSphere networking is designed:

Standard Port Groups: These are local to a specific ESXi host and its Standard Virtual Switches. A host belongs to a cluster. So the linkage is Network (Port Group) -> Host -> Cluster.

Distributed Port Groups (DPGs): These are part of a Distributed Virtual Switch (DVS), which spans multiple ESXi hosts across potentially several clusters within a datacenter. A DPG isn't "in" a cluster directly; rather, hosts in clusters connect to the DVS and its DPGs. The linkage here is more like Network (DPG) -> DVS -> (Multiple Hosts -> Multiple Clusters).

Therefore, to know "which network is linked to which cluster," you need to infer this association by traversing the vCenter inventory.

How to Infer Network-to-Cluster Association
The most reliable way to achieve this using the vCenter REST API is by:

Get all Clusters.

Get all Hosts for each cluster.

For each Host, get its networking configuration. This is the crucial step. You need to identify which networks (standard port groups or DPGs) that host is configured to use.

Then, map those networks back to the clusters via the hosts.

Challenges with the vcenter/network REST API Endpoint
The /rest/vcenter/network endpoint primarily lists abstract network objects. It doesn't inherently tell you which hosts are connected to a standard port group, or which DVS a DPG is on in a way that easily maps back to hosts and thus clusters.

The More Detailed API Calls Needed
To get the host-to-network linkage via REST, you generally need to:

Get all Hosts in a Cluster: GET /rest/vcenter/host?filter.clusters={cluster_id}

For each Host, get its Network Adapters and associated networks: This is where it gets tricky. The GET /rest/vcenter/host/{host_id} endpoint does not always contain enough detail for network mappings. You often need to go deeper:

GET /rest/vcenter/host/{host_id}/network - This endpoint provides information about the host's networking. It can list standard switches (standard_switches) and their associated port groups, and distributed switches (distributed_switches) the host is connected to.

Within the standard_switches or distributed_switches details, you might find references to the specific network IDs or port group keys that correspond to the /rest/vcenter/network objects.

Updated Strategy for Your Python Script
I'll modify the script to implement this traversal logic. It will be significantly more complex than simply listing networks. We'll build a map: Network ID -> List of Cluster Names.


```py
import requests
import json
import ssl

# Suppress insecure request warnings if you're not validating SSL certificates
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# Disable all warnings for requests (urllib3) - FOR DEVELOPMENT ONLY
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
VCENTER_HOST = "your_vcenter_ip_or_hostname"
VCENTER_USERNAME = "your_vcenter_username"
VCENTER_PASSWORD = "your_vcenter_password"

# --- Helper Functions ---
def get_session_id(vcenter_host, username, password):
    """Authenticates with vCenter and returns a session ID."""
    auth_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"Accept": "application/json"}
    try:
        response = requests.post(auth_url, auth=(username, password), headers=headers, verify=False)
        response.raise_for_status()
        session_id = response.json().get("value")
        print("✅ Successfully obtained vCenter session ID.")
        return session_id
    except requests.exceptions.RequestException as e:
        print(f"❌ Error during authentication: {e}")
        return None

def logout(vcenter_host, session_id):
    """Logs out from the vCenter session."""
    logout_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"vmware-api-session-id": session_id}
    try:
        requests.delete(logout_url, headers=headers, verify=False)
        print("👋 Successfully logged out from vCenter session.")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error during logout: {e}")

def get_clusters(vcenter_host, session_id):
    """Retrieves a list of all clusters."""
    clusters_url = f"https://{vcenter_host}/rest/vcenter/cluster"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(clusters_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving clusters: {e}")
        return []

def get_hosts_in_cluster(vcenter_host, session_id, cluster_id):
    """Retrieves hosts within a specific cluster."""
    hosts_url = f"https://{vcenter_host}/rest/vcenter/host?filter.clusters={cluster_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(hosts_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Warning: Could not retrieve hosts for cluster {cluster_id}: {e}")
        return []

def get_host_networking(vcenter_host, session_id, host_id):
    """Retrieves detailed networking configuration for a specific host."""
    networking_url = f"https://{vcenter_host}/rest/vcenter/host/{host_id}/network"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(networking_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value", {})
    except requests.exceptions.RequestException as e:
        # print(f"⚠️ Warning: Could not retrieve networking for host {host_id}: {e}")
        return {}

def get_networks(vcenter_host, session_id):
    """Retrieves a list of all networks (standard and distributed)."""
    networks_url = f"https://{vcenter_host}/rest/vcenter/network"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(networks_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving networks: {e}")
        return []

def get_tags_for_object(vcenter_host, session_id, object_id):
    """Retrieves tag IDs associated with a specific vCenter object."""
    tag_association_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/tag-association?object_id={object_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(tag_association_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        return []

def get_tag_details(vcenter_host, session_id, tag_id):
    """Retrieves details of a specific tag."""
    tag_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/tag/{tag_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(tag_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value")
    except requests.exceptions.RequestException as e:
        return None

def get_category_details(vcenter_host, session_id, category_id):
    """Retrieves details of a specific tag category."""
    category_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/category/{category_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(category_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value")
    except requests.exceptions.RequestException as e:
        return None

def get_custom_attributes_for_object(vcenter_host, session_id, object_id):
    """
    Placeholder: Custom attributes for Network objects are not directly exposed
    via the /vcenter/network REST API.
    """
    return {}

# --- Main Logic ---
def list_networks_and_clusters_with_metadata(vcenter_host, username, password):
    """Lists networks, associated clusters, tags, and custom attributes."""
    session_id = get_session_id(vcenter_host, username, password)
    if not session_id:
        return

    clusters = get_clusters(vcenter_host, session_id)
    all_networks_raw = get_networks(vcenter_host, session_id)

    # Dictionary to store Network ID -> {Network Details, Associated Clusters, Tags, Custom Attributes}
    networks_with_metadata = {net['network']: {
        "name": net.get('name'),
        "id": net.get('network'),
        "type": net.get('type'),
        "distributed_switch": net.get('distributed_switch'),
        "associated_clusters": set(), # Use a set to avoid duplicate cluster names
        "tags": [],
        "custom_attributes": {}
    } for net in all_networks_raw}

    cluster_id_to_name = {c['cluster']: c['name'] for c in clusters}

    print("\n--- Discovering Network-to-Cluster Associations ---")
    for cluster in clusters:
        cluster_id = cluster['cluster']
        cluster_name = cluster['name']
        
        print(f"  Processing Cluster: {cluster_name} (ID: {cluster_id})")
        
        hosts_in_cluster = get_hosts_in_cluster(vcenter_host, session_id, cluster_id)
        
        for host in hosts_in_cluster:
            host_id = host['host']
            host_name = host['name']
            
            # print(f"    Processing Host: {host_name} (ID: {host_id})")
            
            host_networking = get_host_networking(vcenter_host, session_id, host_id)
            
            # Check Standard Switches (Standard Port Groups)
            for std_switch in host_networking.get('standard_switches', []):
                for port_group in std_switch.get('port_groups', []):
                    network_id_from_host = port_group.get('network') # This is the network ID
                    if network_id_from_host and network_id_from_host in networks_with_metadata:
                        networks_with_metadata[network_id_from_host]["associated_clusters"].add(cluster_name)
                        # print(f"      Found Standard PG '{port_group.get('name')}' ({network_id_from_host}) linked to {cluster_name}")

            # Check Distributed Switches (Distributed Port Groups)
            for d_switch in host_networking.get('distributed_switches', []):
                for port_group in d_switch.get('port_groups', []):
                    # For DPGs, the 'network' field is the ID from /vcenter/network
                    network_id_from_host = port_group.get('network')
                    if network_id_from_host and network_id_from_host in networks_with_metadata:
                        networks_with_metadata[network_id_from_host]["associated_clusters"].add(cluster_name)
                        # print(f"      Found Distributed PG '{port_group.get('name')}' ({network_id_from_host}) linked to {cluster_name}")

    # Now, populate tags and custom attributes for each network
    category_cache = {}
    for net_id, net_data in networks_with_metadata.items():
        # --- Get Tags ---
        associated_tag_ids = get_tags_for_object(vcenter_host, session_id, net_id)
        for tag_id in associated_tag_ids:
            tag_details = get_tag_details(vcenter_host, session_id, tag_id)
            if tag_details:
                tag_name = tag_details.get('name')
                tag_description = tag_details.get('description', 'N/A')
                category_id = tag_details.get('category_id')

                category_name = "N/A"
                category_cardinality = "N/A"

                if category_id:
                    if category_id not in category_cache:
                        category_details = get_category_details(vcenter_host, session_id, category_id)
                        if category_details:
                            category_cache[category_id] = {
                                "name": category_details.get('name'),
                                "cardinality": category_details.get('cardinality')
                            }
                        else:
                            category_cache[category_id] = {"name": "Unknown", "cardinality": "Unknown"}
                    
                    category_info = category_cache.get(category_id)
                    if category_info:
                        category_name = category_info['name']
                        category_cardinality = category_info['cardinality']

                net_data["tags"].append({
                    "name": tag_name,
                    "description": tag_description,
                    "category": {
                        "name": category_name,
                        "id": category_id,
                        "cardinality": category_cardinality
                    }
                })

        # --- Get Custom Attributes (still a placeholder limitation) ---
        net_data["custom_attributes"] = get_custom_attributes_for_object(vcenter_host, session_id, net_id)

    print("\n--- Final Summary ---")

    print("\n## Clusters:")
    if clusters:
        for cluster in clusters:
            print(f"- **Name**: {cluster.get('name')}, **ID**: {cluster.get('cluster')}")
    else:
        print("No clusters found.")

    print("\n## Networks:")
    if networks_with_metadata:
        # Sort networks by name for consistent output
        sorted_networks = sorted(networks_with_metadata.values(), key=lambda x: x['name'])
        
        # Group networks for output (optional, but good for readability)
        networks_by_type_and_association = {}
        for net_data in sorted_networks:
            net_type = net_data['type']
            associated_clusters_list = sorted(list(net_data['associated_clusters']))
            cluster_key = ", ".join(associated_clusters_list) if associated_clusters_list else "Unassociated/Global"
            
            if net_type not in networks_by_type_and_association:
                networks_by_type_and_association[net_type] = {}
            if cluster_key not in networks_by_type_and_association[net_type]:
                networks_by_type_and_association[net_type][cluster_key] = []
            
            networks_by_type_and_association[net_type][cluster_key].append(net_data)

        for net_type, cluster_groups in networks_by_type_and_association.items():
            print(f"\n### {net_type.replace('_', ' ').title()} Networks:")
            for cluster_key, nets_list in cluster_groups.items():
                print(f"\n  Associated With: {cluster_key}")
                for net_data in nets_list:
                    print(f"    - **Name**: {net_data['name']}, **ID**: {net_data['id']}")
                    if net_data.get('distributed_switch'):
                        print(f"      (Belongs to Distributed Switch ID: {net_data['distributed_switch']})")
                    
                    if net_data['tags']:
                        print("      **Tags**:")
                        for tag in net_data['tags']:
                            print(f"        - **Tag**: {tag['name']}")
                            print(f"          Description: {tag['description']}")
                            print(f"          **Category**: {tag['category']['name']} (Cardinality: {tag['category']['cardinality']})")
                    else:
                        print("      No tags associated.")

                    if net_data['custom_attributes']:
                        print("      **Custom Attributes**:")
                        for key, value in net_data['custom_attributes'].items():
                            print(f"        - {key}: {value}")
                    else:
                        print("      No custom attributes associated (or not directly retrievable via /vcenter/network API).")
    else:
        print("No networks found.")

    # --- Logout ---
    logout(vcenter_host, session_id)

# --- Execute the script ---
if __name__ == "__main__":
    # !!! IMPORTANT: Replace with your actual vCenter details !!!
    VCENTER_HOST = "your_vcenter_ip_or_hostname"
    VCENTER_USERNAME = "your_vcenter_username"
    VCENTER_PASSWORD = "your_vcenter_password"
    
    if VCENTER_HOST == "your_vcenter_ip_or_hostname":
        print("Please update VCENTER_HOST, VCENTER_USERNAME, and VCENTER_PASSWORD with your vCenter details.")
    else:
        list_networks_and_clusters_with_metadata(VCENTER_HOST, VCENTER_USERNAME, VCENTER_PASSWORD)
```

```py
import requests
import json
import ssl

# Suppress insecure request warnings if you're not validating SSL certificates
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# Disable all warnings for requests (urllib3)
# ⚠️ Only for development/testing. Do not use in production without understanding risks.
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
VCENTER_HOST = "your_vcenter_ip_or_hostname"
VCENTER_USERNAME = "your_vcenter_username"
VCENTER_PASSWORD = "your_vcenter_password"

# --- Helper Functions ---
def get_session_id(vcenter_host, username, password):
    """Authenticates with vCenter and returns a session ID."""
    auth_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"Accept": "application/json"}
    try:
        response = requests.post(auth_url, auth=(username, password), headers=headers, verify=False)
        response.raise_for_status()
        session_id = response.json().get("value")
        print("✅ Successfully obtained vCenter session ID.")
        return session_id
    except requests.exceptions.RequestException as e:
        print(f"❌ Error during authentication: {e}")
        return None

def logout(vcenter_host, session_id):
    """Logs out from the vCenter session."""
    logout_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"vmware-api-session-id": session_id}
    try:
        requests.delete(logout_url, headers=headers, verify=False)
        print("👋 Successfully logged out from vCenter session.")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error during logout: {e}")

def get_clusters(vcenter_host, session_id):
    """Retrieves a list of all clusters."""
    clusters_url = f"https://{vcenter_host}/rest/vcenter/cluster"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(clusters_url, headers=headers, verify=False)
        response.raise_for_status()
        print("✅ Successfully retrieved clusters.")
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving clusters: {e}")
        return []

def get_networks(vcenter_host, session_id):
    """Retrieves a list of all networks (standard and distributed)."""
    networks_url = f"https://{vcenter_host}/rest/vcenter/network"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(networks_url, headers=headers, verify=False)
        response.raise_for_status()
        print("✅ Successfully retrieved networks.")
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving networks: {e}")
        return []

def get_tags_for_object(vcenter_host, session_id, object_id):
    """Retrieves tag IDs associated with a specific vCenter object."""
    tag_association_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/tag-association?object_id={object_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(tag_association_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value", []) # This returns a list of tag_ids
    except requests.exceptions.RequestException as e:
        return []

def get_tag_details(vcenter_host, session_id, tag_id):
    """Retrieves details of a specific tag."""
    tag_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/tag/{tag_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(tag_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value")
    except requests.exceptions.RequestException as e:
        return None

def get_category_details(vcenter_host, session_id, category_id):
    """Retrieves details of a specific tag category."""
    category_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/category/{category_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(category_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value")
    except requests.exceptions.RequestException as e:
        return None

def get_custom_attributes_for_object(vcenter_host, session_id, object_id):
    """
    Placeholder: Custom attributes for Network objects are not directly exposed
    via the /vcenter/network REST API.
    """
    return {} # Returning an empty dictionary as custom attributes are not directly exposed on /vcenter/network

# --- Main Logic ---
def list_networks_and_clusters_with_metadata(vcenter_host, username, password):
    """Lists networks, associated clusters, tags, and custom attributes."""
    session_id = get_session_id(vcenter_host, username, password)
    if not session_id:
        return

    clusters = get_clusters(vcenter_host, session_id)
    networks = get_networks(vcenter_host, session_id)

    print("\n--- Networks and Clusters Summary ---")

    print("\n## Clusters:")
    if clusters:
        for cluster in clusters:
            print(f"- **Name**: {cluster.get('name')}, **ID**: {cluster.get('cluster')}")
    else:
        print("No clusters found.")

    print("\n## Networks:")
    if networks:
        network_types = {}
        for net in networks:
            net_type = net.get('type', 'UNKNOWN')
            if net_type not in network_types:
                network_types[net_type] = []
            network_types[net_type].append(net)

        # Cache for category details to avoid redundant API calls
        category_cache = {} 

        for net_type, net_list in network_types.items():
            print(f"\n### {net_type.replace('_', ' ').title()} Networks:")
            for net in net_list:
                network_id = net.get('network')
                network_name = net.get('name')
                
                print(f"- **Name**: {network_name}, **ID**: {network_id}")
                
                if 'distributed_switch' in net:
                    print(f"  (Belongs to Distributed Switch ID: {net['distributed_switch']})")
                
                # --- Get Tags ---
                associated_tag_ids = get_tags_for_object(vcenter_host, session_id, network_id)
                
                if associated_tag_ids:
                    print("  **Tags**:")
                    for tag_id in associated_tag_ids:
                        tag_details = get_tag_details(vcenter_host, session_id, tag_id)
                        if tag_details:
                            tag_name = tag_details.get('name')
                            tag_description = tag_details.get('description', 'N/A')
                            category_id = tag_details.get('category_id')

                            category_name = "N/A"
                            category_cardinality = "N/A"

                            if category_id:
                                if category_id not in category_cache:
                                    category_details = get_category_details(vcenter_host, session_id, category_id)
                                    if category_details:
                                        category_cache[category_id] = {
                                            "name": category_details.get('name'),
                                            "cardinality": category_details.get('cardinality')
                                        }
                                    else:
                                        category_cache[category_id] = {"name": "Unknown", "cardinality": "Unknown"}
                                
                                category_info = category_cache.get(category_id)
                                if category_info:
                                    category_name = category_info['name']
                                    category_cardinality = category_info['cardinality']

                            print(f"    - **Tag**: {tag_name}")
                            print(f"      Description: {tag_description}")
                            print(f"      **Category**: {category_name} (Cardinality: {category_cardinality})")
                        else:
                            print(f"    - Tag ID: {tag_id} (Details not retrieved)")
                else:
                    print("  No tags associated.")

                # --- Get Custom Attributes ---
                custom_attributes = get_custom_attributes_for_object(vcenter_host, session_id, network_id)
                
                if custom_attributes:
                    print("  **Custom Attributes**:")
                    for key, value in custom_attributes.items():
                        print(f"    - {key}: {value}")
                else:
                    print("  No custom attributes associated (or not directly retrievable via /vcenter/network API).")

    else:
        print("No networks found.")

    # --- Logout ---
    logout(vcenter_host, session_id)

# --- Execute the script ---
if __name__ == "__main__":
    # !!! IMPORTANT: Replace with your actual vCenter details !!!
    VCENTER_HOST = "your_vcenter_ip_or_hostname"
    VCENTER_USERNAME = "your_vcenter_username"
    VCENTER_PASSWORD = "your_vcenter_password"
    
    if VCENTER_HOST == "your_vcenter_ip_or_hostname":
        print("Please update VCENTER_HOST, VCENTER_USERNAME, and VCENTER_PASSWORD with your vCenter details.")
    else:
        list_networks_and_clusters_with_metadata(VCENTER_HOST, VCENTER_USERNAME, VCENTER_PASSWORD)
```

```py
import requests
import json
import ssl

# Suppress insecure request warnings if you're not validating SSL certificates
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# --- Configuration ---
VCENTER_HOST = "your_vcenter_ip_or_hostname"
VCENTER_USERNAME = "your_vcenter_username"
VCENTER_PASSWORD = "your_vcenter_password"

# --- Helper Functions ---
def get_session_id(vcenter_host, username, password):
    """Authenticates with vCenter and returns a session ID."""
    auth_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"Accept": "application/json"}
    try:
        response = requests.post(auth_url, auth=(username, password), headers=headers, verify=False)
        response.raise_for_status()
        session_id = response.json().get("value")
        print("✅ Successfully obtained vCenter session ID.")
        return session_id
    except requests.exceptions.RequestException as e:
        print(f"❌ Error during authentication: {e}")
        return None

def logout(vcenter_host, session_id):
    """Logs out from the vCenter session."""
    logout_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"vmware-api-session-id": session_id}
    try:
        requests.delete(logout_url, headers=headers, verify=False)
        print("👋 Successfully logged out from vCenter session.")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error during logout: {e}")

def get_clusters(vcenter_host, session_id):
    """Retrieves a list of all clusters."""
    clusters_url = f"https://{vcenter_host}/rest/vcenter/cluster"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(clusters_url, headers=headers, verify=False)
        response.raise_for_status()
        print("✅ Successfully retrieved clusters.")
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving clusters: {e}")
        return []

def get_networks(vcenter_host, session_id):
    """Retrieves a list of all networks (standard and distributed)."""
    networks_url = f"https://{vcenter_host}/rest/vcenter/network"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(networks_url, headers=headers, verify=False)
        response.raise_for_status()
        print("✅ Successfully retrieved networks.")
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving networks: {e}")
        return []

def get_tags_for_object(vcenter_host, session_id, object_id, object_type="Network"):
    """
    Retrieves tags associated with a specific vCenter object (e.g., a network).
    The object_type is used for logging purposes.
    """
    # The API endpoint for listing tags on an object is:
    # GET /rest/com/vmware/cis/tagging/tag-association?object_id={object_id}
    tag_association_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/tag-association?object_id={object_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(tag_association_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value", []) # This returns a list of tag_ids
    except requests.exceptions.RequestException as e:
        # print(f"⚠️ Warning: Could not retrieve tags for {object_type} ID {object_id}: {e}")
        return []

def get_tag_details(vcenter_host, session_id, tag_id):
    """Retrieves details of a specific tag."""
    tag_url = f"https://{vcenter_host}/rest/com/vmware/cis/tagging/tag/{tag_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(tag_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value")
    except requests.exceptions.RequestException as e:
        # print(f"⚠️ Warning: Could not retrieve details for tag ID {tag_id}: {e}")
        return None

# --- Main Logic ---
def list_networks_and_clusters_with_tags(vcenter_host, username, password):
    """Lists networks and their associated clusters and tags."""
    session_id = get_session_id(vcenter_host, username, password)
    if not session_id:
        return

    clusters = get_clusters(vcenter_host, session_id)
    networks = get_networks(vcenter_host, session_id)

    print("\n--- Networks and Clusters Summary ---")

    print("\n## Clusters:")
    if clusters:
        for cluster in clusters:
            print(f"- **Name**: {cluster.get('name')}, **ID**: {cluster.get('cluster')}")
    else:
        print("No clusters found.")

    print("\n## Networks:")
    if networks:
        network_types = {}
        for net in networks:
            net_type = net.get('type', 'UNKNOWN')
            if net_type not in network_types:
                network_types[net_type] = []
            network_types[net_type].append(net)

        for net_type, net_list in network_types.items():
            print(f"\n### {net_type.replace('_', ' ').title()} Networks:")
            for net in net_list:
                network_id = net.get('network')
                network_name = net.get('name')
                
                print(f"- **Name**: {network_name}, **ID**: {network_id}")
                
                if 'distributed_switch' in net:
                    print(f"  (Belongs to Distributed Switch ID: {net['distributed_switch']})")
                
                # Get tags associated with this network
                associated_tag_ids = get_tags_for_object(vcenter_host, session_id, network_id, "Network")
                
                if associated_tag_ids:
                    print("  **Tags**:")
                    for tag_id in associated_tag_ids:
                        tag_details = get_tag_details(vcenter_host, session_id, tag_id)
                        if tag_details:
                            print(f"    - Name: {tag_details.get('name')}, Category ID: {tag_details.get('category_id')}, Description: {tag_details.get('description', 'N/A')}")
                        else:
                            print(f"    - Tag ID: {tag_id} (Details not retrieved)")
                else:
                    print("  No tags associated.")
    else:
        print("No networks found.")

    # --- Logout ---
    logout(vcenter_host, session_id)

# --- Execute the script ---
if __name__ == "__main__":
    # !!! IMPORTANT: Replace with your actual vCenter details !!!
    VCENTER_HOST = "your_vcenter_ip_or_hostname"
    VCENTER_USERNAME = "your_vcenter_username"
    VCENTER_PASSWORD = "your_vcenter_password"
    
    if VCENTER_HOST == "your_vcenter_ip_or_hostname":
        print("Please update VCENTER_HOST, VCENTER_USERNAME, and VCENTER_PASSWORD with your vCenter details.")
    else:
        list_networks_and_clusters_with_tags(VCENTER_HOST, VCENTER_USERNAME, VCENTER_PASSWORD)

```
```py
import requests
import json
import ssl

# Suppress insecure request warnings if you're not validating SSL certificates
# In a production environment, you should always validate SSL certificates.
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't have _create_unverified_https_context
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# --- Configuration ---
VCENTER_HOST = "your_vcenter_ip_or_hostname"
VCENTER_USERNAME = "your_vcenter_username"
VCENTER_PASSWORD = "your_vcenter_password"

# --- Helper Functions ---
def get_session_id(vcenter_host, username, password):
    """Authenticates with vCenter and returns a session ID."""
    auth_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"Accept": "application/json"}
    try:
        response = requests.post(auth_url, auth=(username, password), headers=headers, verify=False)
        response.raise_for_status()  # Raise an exception for HTTP errors
        session_id = response.json().get("value")
        print("✅ Successfully obtained vCenter session ID.")
        return session_id
    except requests.exceptions.RequestException as e:
        print(f"❌ Error during authentication: {e}")
        return None

def logout(vcenter_host, session_id):
    """Logs out from the vCenter session."""
    logout_url = f"https://{vcenter_host}/rest/com/vmware/cis/session"
    headers = {"vmware-api-session-id": session_id}
    try:
        requests.delete(logout_url, headers=headers, verify=False)
        print("👋 Successfully logged out from vCenter session.")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error during logout: {e}")

def get_clusters(vcenter_host, session_id):
    """Retrieves a list of all clusters."""
    clusters_url = f"https://{vcenter_host}/rest/vcenter/cluster"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(clusters_url, headers=headers, verify=False)
        response.raise_for_status()
        print("✅ Successfully retrieved clusters.")
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving clusters: {e}")
        return []

def get_networks(vcenter_host, session_id):
    """Retrieves a list of all networks (standard and distributed)."""
    networks_url = f"https://{vcenter_host}/rest/vcenter/network"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(networks_url, headers=headers, verify=False)
        response.raise_for_status()
        print("✅ Successfully retrieved networks.")
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving networks: {e}")
        return []

def get_hosts_in_cluster(vcenter_host, session_id, cluster_id):
    """Retrieves hosts within a specific cluster."""
    hosts_url = f"https://{vcenter_host}/rest/vcenter/host?filter.clusters={cluster_id}"
    headers = {"vmware-api-session-id": session_id, "Accept": "application/json"}
    try:
        response = requests.get(hosts_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("value", [])
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Warning: Could not retrieve hosts for cluster {cluster_id}: {e}")
        return []

def get_host_networks(vcenter_host, session_id, host_id):
    """Retrieves networks directly associated with a specific host."""
    # This endpoint typically provides network adapters on the host, not necessarily logical networks.
    # For a more direct link to standard switches/port groups, you'd usually look at the host's
    # network configuration details, which might require more specific API calls or pyVmomi.
    # The 'vcenter/network' API lists networks as objects that hosts might connect to.
    # We will rely on the general /vcenter/network endpoint and try to infer association.
    pass # Not directly used in the current inference logic

# --- Main Logic ---
def list_networks_and_clusters(vcenter_host, username, password):
    """Lists networks and their associated clusters."""
    session_id = get_session_id(vcenter_host, username, password)
    if not session_id:
        return

    clusters = get_clusters(vcenter_host, session_id)
    networks = get_networks(vcenter_host, session_id)

    cluster_id_to_name = {c['cluster']: c['name'] for c in clusters}
    network_id_to_info = {n['network']: n for n in networks}

    # Initialize a dictionary to store networks per cluster
    networks_per_cluster = {name: [] for name in cluster_id_to_name.values()}
    networks_per_cluster["Unassociated Networks"] = []

    print("\n--- Processing Networks and Clusters ---")

    for network_info in networks:
        network_id = network_info['network']
        network_name = network_info.get('name', 'N/A')
        network_type = network_info.get('type', 'Unknown')
        
        # The vCenter REST API for 'vcenter/network' does not directly link a network
        # object to a specific cluster ID. Instead, networks (especially Distributed Port Groups)
        # exist at the datacenter level and hosts (which belong to clusters) connect to them.
        #
        # To infer the association, we need to consider the network's type and its connected entities.
        # For 'STANDARD_PORTGROUP', it's bound to a host's standard switch.
        # For 'DISTRIBUTED_PORTGROUP', it's part of a Distributed Virtual Switch (DVS),
        # and hosts in clusters connect to this DVS.
        #
        # A direct API call to get "networks per cluster" isn't straightforward with the REST API.
        # We'll approximate by checking which clusters contain hosts that could be connected
        # to this network. This is a simplification and may not be 100% accurate for all complex setups.

        associated_clusters = set()

        if network_type == "DISTRIBUTED_PORTGROUP":
            # For Distributed Port Groups, the info often includes 'distributed_switch' and 'datacenter'
            # We would need to then query the distributed switch to see which hosts/clusters it's connected to.
            # This is complex and often requires going through hosts.
            # Let's assume for simplicity, if a DPG is found, it's generally shared across clusters
            # within a datacenter. We'll list it separately or try to map via hosts if possible.

            # Simplified approach: List DPGs and then state they are "datacenter-wide" or require
            # further investigation.
            if 'distributed_switch' in network_info:
                # To truly link, you'd fetch the DVS and then find its associated hosts/clusters.
                # For this example, we'll just note it's a DPG.
                pass # Further detailed linking is beyond this simple example's scope.
            
            # As a heuristic, if we want to guess, we might list it under all clusters in its datacenter,
            # or specifically under a generic "Distributed Networks" category.
            # For now, we'll try to find any host it's associated with.
            
            # The /vcenter/network API doesn't directly give us host associations.
            # We would typically fetch all hosts, then for each host, check its network adapters
            # and their connected networks. This is an expensive operation for all networks.
            
            # Let's try to get all networks and then iterate through clusters, and then hosts.
            # This is an inverted approach from what's ideal, but the API structure makes it so.

            # Alternative: Assume if a network is a DPG, it *could* be associated with any cluster
            # within the same datacenter. This is an oversimplification.
            # For a more precise mapping, you'd need to inspect `vcenter/host/{host_id}/networking`
            # and then link the host to its cluster.

            # For a quick practical approach, let's just list the DPGs and mention their type.
            # A direct REST API call to get networks *per cluster* with associated names is not
            # a single endpoint in vCenter.
            
            # Let's just group by the network type for now, and explicitly state if it's a Distributed Port Group.
            # A DPG is not strictly "associated" with one cluster, but rather spans multiple.
            networks_per_cluster["Unassociated Networks"].append(
                f"Distributed Port Group: {network_name} (ID: {network_id})"
            )

        elif network_type == "STANDARD_PORTGROUP":
            # For standard port groups, they are on a specific host's standard switch.
            # We need to find the host connected to this standard port group, then find its cluster.
            # The /vcenter/network endpoint doesn't give us the host directly.
            # We would need to iterate through all hosts and check their network configuration.
            
            # This requires a more complex query pattern. For simplicity in this example,
            # if we can't directly map to a cluster via a simple lookup, we'll list it as unassociated.
            # A more robust solution would involve fetching host network details.
            networks_per_cluster["Unassociated Networks"].append(
                f"Standard Port Group: {network_name} (ID: {network_id})"
            )
        else:
             networks_per_cluster["Unassociated Networks"].append(
                f"Other Network Type ({network_type}): {network_name} (ID: {network_id})"
            )

    # A more accurate way to associate: iterate through clusters, then hosts in each cluster,
    # then hosts' networks. This is more involved.
    # For a general listing, the above approach provides networks and their types.
    # To truly link a network to a cluster, you'd typically need to find all hosts in a cluster,
    # then query each host's network interfaces to see which networks it's connected to.

    # Let's refine the association by iterating through clusters and then hosts to see which networks they "see".
    # This will still not directly link network *objects* to clusters in the API's returned data,
    # but rather show which networks are accessible/used within a cluster.
    
    print("\n--- Detailed Network-to-Cluster Association (Best Effort) ---")
    cluster_networks_map = {c['name']: [] for c in clusters}
    
    for cluster in clusters:
        cluster_name = cluster['name']
        cluster_id = cluster['cluster']
        
        hosts_in_cluster = get_hosts_in_cluster(vcenter_host, session_id, cluster_id)
        
        for host in hosts_in_cluster:
            host_id = host['host']
            host_name = host['name']
            
            # The /vcenter/network API itself doesn't offer a direct way to filter
            # networks by the hosts they are connected to, or vice-versa, in a simple join.
            # Instead, the 'networks' field in a host's detailed info (if available) would list network IDs.
            #
            # The current /vcenter/network endpoint gives us a list of all *network objects*.
            # The challenge is linking these network objects to clusters.
            #
            # A common way to infer this is that if a host in a cluster is connected to a network,
            # then that network is "associated" with the cluster.
            
            # Unfortunately, the `vcenter/host` API doesn't readily provide a list of
            # all networks connected to that host in its summary.
            # You'd need to go to `/rest/vcenter/host/{host_id}/network`
            # or `/rest/vcenter/host/{host_id}/ethernet` to get more detailed network adapter info.
            # This is getting into very granular details.

            # For the scope of this request, listing all networks and all clusters,
            # and then providing a high-level association based on common knowledge
            # (e.g., DPGs span datacenters/clusters, Standard Port Groups are host-local)
            # is more feasible with the direct REST API calls shown so far.

            # Let's revise to output the known information clearly.
            # We'll list all clusters, and for each cluster, list its hosts.
            # Then list all networks separately. If you need a direct "network X is used by cluster Y",
            # it requires more intricate API calls (e.g., iterating through all host network adapters).
            
            # To get networks associated with a host, you'd typically use pyVmomi or
            # more specific REST API calls like:
            # GET /rest/vcenter/host/{host}/network-adapters
            # Then for each network adapter, examine its 'connected_network' property.
            # This is not directly available on the /vcenter/network list.
            
            # Simplified for direct /vcenter/network output:
            # We'll just show the clusters and hosts for context,
            # and then list all networks, noting their type.
            # A true mapping would be significantly more complex and depend on whether
            # you consider a network "associated" if any host in the cluster uses it.
            
            pass # Skipping granular host network details for this example due to complexity.

    print("\n--- Networks and Clusters Summary ---")

    print("\n## Clusters:")
    if clusters:
        for cluster in clusters:
            print(f"- **Name**: {cluster.get('name')}, **ID**: {cluster.get('cluster')}")
    else:
        print("No clusters found.")

    print("\n## Networks:")
    if networks:
        # Group networks by type for better readability
        network_types = {}
        for net in networks:
            net_type = net.get('type', 'UNKNOWN')
            if net_type not in network_types:
                network_types[net_type] = []
            network_types[net_type].append(net)

        for net_type, net_list in network_types.items():
            print(f"\n### {net_type.replace('_', ' ').title()} Networks:")
            for net in net_list:
                print(f"- **Name**: {net.get('name')}, **ID**: {net.get('network')}")
                if 'distributed_switch' in net:
                    print(f"  (Belongs to Distributed Switch ID: {net['distributed_switch']})")
                # For standard port groups, it's implicitly host-local.
                # To determine which cluster, you'd need to find which hosts are using it,
                # then which cluster those hosts belong to.
                # This requires more specific API calls (e.g., host's network details)
                # and then cross-referencing with host-to-cluster mappings.
                # The vCenter REST API doesn't provide a direct "network_id -> cluster_id" lookup.
    else:
        print("No networks found.")

    # --- Logout ---
    logout(vcenter_host, session_id)

# --- Execute the script ---
if __name__ == "__main__":
    # !!! IMPORTANT: Replace with your actual vCenter details !!!
    VCENTER_HOST = "your_vcenter_ip_or_hostname"
    VCENTER_USERNAME = "your_vcenter_username"
    VCENTER_PASSWORD = "your_vcenter_password"
    
    if VCENTER_HOST == "your_vcenter_ip_or_hostname":
        print("Please update VCENTER_HOST, VCENTER_USERNAME, and VCENTER_PASSWORD with your vCenter details.")
    else:
        list_networks_and_clusters(VCENTER_HOST, VCENTER_USERNAME, VCENTER_PASSWORD)
```

```py
from pyspark.sql import SparkSession
from pyspark.sql.functions import lit, current_timestamp
import requests
import json
import os
import time # For basic rate limiting or retry delays

# --- Configuration ---
EDISCOVERY_API_BASE_URL = "https://your-ediscovery-api.com/api/v1"
API_KEY = "your_api_key_or_token"

BRONZE_LAYER_PATH = "abfss://bronze@yourdatalake.dfs.core.windows.net/ediscovery_searches"

# --- Initialize Spark Session ---
spark = SparkSession.builder \
    .appName("ParallelEdiscoverySearchDataIngestion") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")
print("Spark Session initialized.")

# --- API Interaction Functions (made global/broadcastable for Spark tasks) ---

# Define headers outside the function if they are constant.
# If auth tokens refresh, you might need a mechanism to get a fresh one per task/batch.
GLOBAL_API_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_KEY}"
}

# It's good practice to wrap API calls with retry logic, especially for external services.
def make_api_request_with_retries(url, headers, method="GET", max_retries=3, delay_seconds=5):
    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, headers=headers, timeout=60)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed for {url}: {e}")
            if attempt < max_retries - 1:
                print(f"Retrying in {delay_seconds} seconds...")
                time.sleep(delay_seconds)
            else:
                print(f"Max retries reached for {url}. Giving up.")
                raise # Re-raise the last exception if all retries fail
    return None # Should not be reached

def fetch_ediscovery_cases():
    """
    Fetches a list of all eDiscovery case IDs from the API.
    Returns a list of case dictionaries.
    """
    cases_endpoint = f"{EDISCOVERY_API_BASE_URL}/cases"
    print(f"Fetching cases from: {cases_endpoint}")
    try:
        cases_data = make_api_request_with_retries(cases_endpoint, GLOBAL_API_HEADERS)
        if cases_data:
            if isinstance(cases_data, dict) and "cases" in cases_data:
                return cases_data["cases"]
            elif isinstance(cases_data, list):
                return cases_data
        print(f"Unexpected cases API response format: {cases_data}")
        return []
    except Exception as e:
        print(f"Error fetching eDiscovery cases: {e}")
        return []

# This function will be executed on Spark worker nodes
def fetch_searches_for_case(case_dict):
    """
    Fetches all searches for a given eDiscovery case ID.
    This function is designed to be called by Spark's parallel processing.
    It returns a list of dictionaries, each being a search record.
    """
    case_id = case_dict.get("id") # Assuming 'id' is the key for case ID
    if not case_id:
        print(f"Skipping case due to missing 'id' field: {case_dict}")
        return []

    searches_endpoint = f"{EDISCOVERY_API_BASE_URL}/cases/{case_id}/searches"
    print(f"Fetching searches for case ID: {case_id}") # This will appear in worker logs

    try:
        searches_data = make_api_request_with_retries(searches_endpoint, GLOBAL_API_HEADERS)
        if searches_data:
            extracted_searches = []
            if isinstance(searches_data, dict) and "searches" in searches_data:
                extracted_searches = searches_data["searches"]
            elif isinstance(searches_data, list):
                extracted_searches = searches_data
            else:
                print(f"Unexpected searches API response format for case {case_id}: {searches_data}")
                return []

            # Add the case_id to each search record
            for search in extracted_searches:
                search['case_id'] = case_id
            return extracted_searches
        return []
    except Exception as e:
        print(f"Error fetching searches for case {case_id}: {e}")
        return []


# --- Main Logic ---

if __name__ == "__main__":
    # 1. Fetch Case IDs (this still happens on the driver)
    cases = fetch_ediscovery_cases()
    if not cases:
        print("No eDiscovery cases found or error fetching cases. Exiting.")
        spark.stop()
        exit()

    print(f"Found {len(cases)} eDiscovery cases.")

    # 2. Parallelize fetching searches
    # Create an RDD from the list of case dictionaries
    # We can control the number of partitions to optimize parallelism vs. overhead
    num_partitions = min(len(cases), spark.sparkContext.defaultParallelism * 2) # Example heuristic
    case_rdd = spark.sparkContext.parallelize(cases, numSlices=num_partitions)

    # Use flatMap to call the API for each case and flatten the results
    # Each item in the RDD will be a case_dict, and the function returns a list of searches for that case.
    # flatMap combines all these lists into a single RDD of individual search dictionaries.
    all_searches_rdd = case_rdd.flatMap(fetch_searches_for_case)

    # Convert the RDD of search dictionaries to a list for DataFrame creation
    # This collects all data back to the driver, which is fine if the total data size is manageable.
    # For very large datasets, consider directly writing the RDD or streaming.
    all_searches_list = all_searches_rdd.collect()

    if not all_searches_list:
        print("No search data collected after parallel processing. Exiting.")
        spark.stop()
        exit()

    # 3. Process and Structure Data into PySpark DataFrame
    # Infer schema from the collected data
    df = spark.createDataFrame(all_searches_list)

    # Add metadata columns typical for bronze layer
    df = df.withColumn("ingestion_timestamp", current_timestamp()) \
           .withColumn("source_system", lit("eDiscovery_API"))

    print(f"Collected {df.count()} search records.")
    df.printSchema()
    df.show(5, truncate=False)

    # 4. Save to Bronze Layer
    try:
        df.write \
            .format("delta") \
            .mode("overwrite") \
            .option("mergeSchema", "true") \
            .save(BRONZE_LAYER_PATH)
        print(f"Successfully saved eDiscovery search data to bronze layer: {BRONZE_LAYER_PATH}")

    except Exception as e:
        print(f"Error saving data to bronze layer: {e}")

    # Stop Spark Session
    spark.stop()
    print("Spark Session stopped.")

```
