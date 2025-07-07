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
