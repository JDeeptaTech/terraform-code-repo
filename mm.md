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
