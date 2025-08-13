```py
# -*- coding: utf-8 -*-

# In callback_plugins/postgres_logger.py

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import datetime
import json
try:
    import psycopg2
except ImportError:
    # Handle the case where the psycopg2 library is not installed
    raise ImportError("The psycopg2 library is required for this callback. Please install it with 'pip install psycopg2-binary'")

from ansible.plugins.callback import CallbackBase

DOCUMENTATION = r'''
    callback: postgres_logger
    short_description: Logs playbook start and end events to a PostgreSQL database.
    description:
      - This callback plugin connects to a PostgreSQL database and logs an entry
        when a playbook starts and updates that entry when the playbook finishes.
      - It requires the `psycopg2-binary` library to be installed.
      - Database connection details are configured via environment variables.
    requirements:
      - whitelist in ansible.cfg
      - psycopg2-binary python library
    options:
      table_name:
        description: The name of the table to log to.
        default: 'ansible_playbook_runs'
        env:
          - name: ANSIBLE_POSTGRES_TABLE
        ini:
          - section: callback_postgres_logger
            key: table_name
'''

class CallbackModule(CallbackBase):
    """
    Logs playbook execution statistics to a PostgreSQL database.
    """
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'postgres_logger'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self):
        super(CallbackModule, self).__init__()
        self.playbook_run_id = None
        self.playbook_name = "N/A"

        # --- Database Connection Details from Environment Variables ---
        self.db_host = os.getenv('ANSIBLE_POSTGRES_HOST', 'localhost')
        self.db_port = os.getenv('ANSIBLE_POSTGRES_PORT', '5432')
        self.db_name = os.getenv('ANSIBLE_POSTGRES_DB', 'ansible_logs')
        self.db_user = os.getenv('ANSIBLE_POSTGRES_USER')
        self.db_password = os.getenv('ANSIBLE_POSTGRES_PASSWORD')
        
        # Check for required credentials
        if not self.db_user or not self.db_password:
            self._display.warning("Postgres callback is disabled. Set ANSIBLE_POSTGRES_USER and ANSIBLE_POSTGRES_PASSWORD env vars.")
            self.disabled = True
            return

        # Attempt to connect to create the table if it doesn't exist
        self._create_table_if_not_exists()

    def _get_db_connection(self):
        """Establishes a connection to the PostgreSQL database."""
        if self.disabled:
            return None
        try:
            conn = psycopg2.connect(
                dbname=self.db_name,
                user=self.db_user,
                password=self.db_password,
                host=self.db_host,
                port=self.db_port
            )
            return conn
        except Exception as e:
            self._display.error(f"Could not connect to PostgreSQL database: {e}")
            self.disabled = True
            return None

    def _create_table_if_not_exists(self):
        """Creates the logging table if it's not already present."""
        conn = self._get_db_connection()
        if not conn:
            return
        
        table_name = self.get_option('table_name')
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            playbook_name VARCHAR(255) NOT NULL,
            start_time TIMESTAMP WITH TIME ZONE NOT NULL,
            end_time TIMESTAMP WITH TIME ZONE,
            duration_seconds INTEGER,
            status VARCHAR(50),
            stats JSONB
        );
        """
        try:
            with conn.cursor() as cur:
                cur.execute(create_table_sql)
            conn.commit()
        except Exception as e:
            self._display.error(f"Failed to create table '{table_name}': {e}")
            self.disabled = True
        finally:
            if conn:
                conn.close()

    def v2_playbook_on_start(self, playbook):
        """This method is called at the start of the playbook run."""
        conn = self._get_db_connection()
        if not conn:
            return
            
        self.playbook_name = os.path.basename(playbook.get_path())
        start_time = datetime.datetime.now(datetime.timezone.utc)

        sql = f"INSERT INTO {self.get_option('table_name')} (playbook_name, start_time, status) VALUES (%s, %s, %s) RETURNING id;"
        
        try:
            with conn.cursor() as cur:
                cur.execute(sql, (self.playbook_name, start_time, 'in_progress'))
                self.playbook_run_id = cur.fetchone()[0] # Get the ID of the new row
            conn.commit()
            self._display.v(f"Logged playbook start to PostgreSQL with run ID: {self.playbook_run_id}")
        except Exception as e:
            self._display.error(f"Failed to log playbook start: {e}")
        finally:
            if conn:
                conn.close()

    def v2_playbook_on_stats(self, stats):
        """This method is called at the end of the playbook run."""
        conn = self._get_db_connection()
        if not conn or not self.playbook_run_id:
            return

        end_time = datetime.datetime.now(datetime.timezone.utc)

        # Summarize the host stats
        hosts_summary = {}
        total_hosts = 0
        overall_status = 'success'

        for host in stats.processed.keys():
            host_stats = stats.summarize(host)
            hosts_summary[host] = host_stats
            if host_stats['unreachable'] > 0 or host_stats['failures'] > 0:
                overall_status = 'failed'
            total_hosts += 1

        # Calculate duration
        start_time_sql = f"SELECT start_time FROM {self.get_option('table_name')} WHERE id = %s;"
        duration = -1
        try:
             with conn.cursor() as cur:
                cur.execute(start_time_sql, (self.playbook_run_id,))
                start_time_result = cur.fetchone()
                if start_time_result:
                    duration = (end_time - start_time_result[0]).total_seconds()
        except Exception as e:
            self._display.v(f"Could not calculate duration: {e}")


        sql = f"""
        UPDATE {self.get_option('table_name')}
        SET end_time = %s, duration_seconds = %s, status = %s, stats = %s
        WHERE id = %s;
        """

        try:
            with conn.cursor() as cur:
                cur.execute(sql, (end_time, int(duration), overall_status, json.dumps(hosts_summary), self.playbook_run_id))
            conn.commit()
            self._display.v(f"Updated playbook run ID {self.playbook_run_id} in PostgreSQL with final status.")
        except Exception as e:
            self._display.error(f"Failed to log playbook end: {e}")
        finally:
            if conn:
                conn.close()
```
