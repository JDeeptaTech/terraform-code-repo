```py
# main_app.py

import httpx
from fastapi import FastAPI, Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import MutableHeaders
import uvicorn

# --- Custom Middleware ---

class TokenInjectorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # URL of the external token provider service
        token_provider_url = "http://127.0.0.1:8001/get-token"

        try:
            # Use httpx.AsyncClient for async requests
            async with httpx.AsyncClient() as client:
                # Call the external API to get a token
                response = await client.post(token_provider_url)
                response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
                
                token_data = response.json()
                token = f"{token_data['token_type']} {token_data['access_token']}"

        except (httpx.RequestError, KeyError) as e:
            # Handle cases where the token service is down or returns an unexpected format
            print(f"Error fetching token: {e}")
            raise HTTPException(
                status_code=503, 
                detail="Service unavailable: Could not fetch authentication token."
            )

        # FastAPI/Starlette request headers are immutable.
        # To modify them, we need to create a new MutableHeaders object.
        new_headers = MutableHeaders(request.scope)
        
        # Add the new Authorization header from the fetched token
        new_headers["Authorization"] = token
        
        # Update the request's scope with the new headers
        request.scope['headers'] = new_headers.raw

        # Proceed to the actual endpoint with the modified request
        response = await call_next(request)
        return response

# --- FastAPI App ---

app = FastAPI()

# Add the middleware to the application
app.add_middleware(TokenInjectorMiddleware)


@app.get("/items/{item_id}")
async def read_item(item_id: int, request: Request):
    """
    A test endpoint to check if the Authorization header was added.
    """
    # Get the authorization header that the middleware should have added
    authorization_header = request.headers.get("Authorization")
    
    return {
        "item_id": item_id,
        "injected_authorization_header": authorization_header
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
````

```py
# In callback_plugins/postgres_vm_logger.py

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import datetime
import json
import getpass # To get the current username

try:
    import psycopg2
    from psycopg2.extras import Json
except ImportError:
    raise ImportError("This callback requires the 'psycopg2-binary' library. Please install it with 'pip install psycopg2-binary'")

from ansible.plugins.callback import CallbackBase
from ansible.executor.task_queue_manager import TaskQueueManager

DOCUMENTATION = r'''
    callback: postgres_vm_logger
    short_description: Logs the final status of each host in a play to a PostgreSQL `vm_table`.
    description:
        - This callback plugin connects to PostgreSQL and logs one record per host at the
          conclusion of a playbook run. It assumes the target table already exists.
        - It uses an "upsert" command (INSERT ON CONFLICT) to create or update records
          based on the `vm_name`.
    requirements:
      - Add `postgres_vm_logger` to `callback_whitelist` in ansible.cfg.
      - Set database connection details as environment variables.
'''

class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'postgres_vm_logger'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self):
        super(CallbackModule, self).__init__()
        
        # --- Database Connection Details (from environment variables for security) ---
        self.db_host = os.getenv('ANSIBLE_POSTGRES_HOST', 'localhost')
        self.db_port = os.getenv('ANSIBLE_POSTGRES_PORT', '5432')
        self.db_name = os.getenv('ANSIBLE_POSTGRES_DB', 'ansible_logs')
        self.db_user = os.getenv('ANSIBLE_POSTGRES_USER')
        self.db_password = os.getenv('ANSIBLE_POSTGRES_PASSWORD')
        self.table_name = "vm_table"

        self.playbook_vars = {}
        
        # Disable the plugin if credentials are not set
        if not self.db_user or not self.db_password:
            self._display.warning("Postgres VM Logger is disabled. Set ANSIBLE_POSTGRES_USER and ANSIBLE_POSTGRES_PASSWORD.")
            self.disabled = True
            return

    def _get_db_connection(self):
        """Establishes and returns a database connection."""
        if self.disabled:
            return None
        try:
            return psycopg2.connect(
                dbname=self.db_name,
                user=self.db_user,
                password=self.db_password,
                host=self.db_host,
                port=self.db_port
            )
        except Exception as e:
            self._display.error(f"Postgres VM Logger: Could not connect to PostgreSQL database: {e}")
            self.disabled = True
            return None

    def v2_playbook_on_start(self, playbook):
        """Captures extra variables passed on the command line at the start of the play."""
        if hasattr(playbook, '_loader'):
             tqm = TaskQueueManager(
                inventory=playbook._inventory,
                variable_manager=playbook._variable_manager,
                loader=playbook._loader,
                passwords=None,
             )
             self.playbook_vars = tqm._variable_manager.get_vars(play=playbook)
        else:
             self.playbook_vars = playbook.extra_vars

    def v2_playbook_on_stats(self, stats):
        """This hook runs at the end of the playbook to log host statuses."""
        conn = self._get_db_connection()
        if not conn:
            return

        try:
            run_by_user = getpass.getuser()
        except Exception:
            run_by_user = 'unknown'

        environment = self.playbook_vars.get('environment', 'N/A')
        service_type = self.playbook_vars.get('service_type', 'N/A')
        build_version = self.playbook_vars.get('build_version', 'N/A')
        data_type = self.playbook_vars.get('data_type', 'N/A')
        
        upsert_sql = f"""
        INSERT INTO {self.table_name} (
            vm_name, environment, service_type, build_version, data_type, 
            created_at, updated_at, created_by, updated_by, 
            lifecycle_status, status_message
        ) VALUES (
            %(vm_name)s, %(environment)s, %(service_type)s, %(build_version)s, %(data_type)s,
            NOW(), NOW(), %(created_by)s, %(updated_by)s, 
            %(lifecycle_status)s, %(status_message)s
        )
        ON CONFLICT (vm_name) DO UPDATE SET
            environment = EXCLUDED.environment,
            service_type = EXCLUDED.service_type,
            build_version = EXCLUDED.build_version,
            data_type = EXCLUDED.data_type,
            updated_at = EXCLUDED.updated_at,
            updated_by = EXCLUDED.updated_by,
            lifecycle_status = EXCLUDED.lifecycle_status,
            status_message = EXCLUDED.status_message;
        """

        for host_name in stats.processed.keys():
            summary = stats.summarize(host_name)
            
            if summary['failures'] > 0 or summary['unreachable'] > 0:
                lifecycle_status = 'failed'
            else:
                lifecycle_status = 'success'

            host_data = {
                "vm_name": host_name,
                "environment": environment,
                "service_type": service_type,
                "build_version": build_version,
                "data_type": data_type,
                "created_by": run_by_user,
                "updated_by": run_by_user,
                "lifecycle_status": lifecycle_status,
                "status_message": Json(summary)
            }
            
            try:
                with conn.cursor() as cur:
                    cur.execute(upsert_sql, host_data)
                self._display.v(f"Postgres VM Logger: Logged status for host {host_name}")
            except Exception as e:
                self._display.error(f"Postgres VM Logger: Failed to log status for {host_name}: {e}")
        
        conn.commit()
        conn.close()
```
