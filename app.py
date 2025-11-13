import os
import requests
import time
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

# 1. NEW IMPORT
from flask_caching import Cache

from s1c_api import SecondaryAPIClient 

app = Flask(__name__)

# 2. CONFIGURE CACHE
# We set the cache type to FileSystemCache, which requires no external services.
app.config["CACHE_TYPE"] = "FileSystemCache"
# This directory will be created in your project's root to store cache files
app.config["CACHE_DIR"] = os.path.join(os.getcwd(), 'app_cache') 
# Default cache time: 24 hours (in seconds)
app.config["CACHE_DEFAULT_TIMEOUT"] = 86400 
cache = Cache(app)
# -----------------------------

# Load environment variables from .env file
load_dotenv()

# --- Global Token Storage ---
TOKEN_INFO = {
    'token': None,
    'expires_in': 0,
    'fetch_time': 0  
}

# --- Configuration (Primary API - NOW OPTIONAL) ---
BASE_URL = os.getenv("IP_REMOTE_URL")
CLIENT_ID = os.getenv("IP_CLIENT_ID")
ACCESS_ID = os.getenv("IP_ACCESS_ID")
PRIMARY_CONFIGURED = BASE_URL is not None and CLIENT_ID is not None and ACCESS_ID is not None

# --- Configuration (Secondary API - Check for *any* config) ---
SECONDARY_CONFIGURED = os.getenv("S1C_URL") is not None


## ---------------------------------
## AUTH FUNCTIONS
## ---------------------------------

def _perform_login(force_new=False):
    """
    Internal function to perform the actual login to the remote service.
    Returns False immediately if primary config is missing.
    """
    global TOKEN_INFO
    
    if not PRIMARY_CONFIGURED:
        return False, {"error": "Primary service configuration is incomplete."}

    # 2. Make the remote API call
    try:
        login_url = f"{BASE_URL}/auth/external"
        payload = {"clientId": CLIENT_ID, "accessKey": ACCESS_ID}
        
        response = requests.post(login_url, json=payload, timeout=5)
        response.raise_for_status()
        response_data = response.json()

        # 3. Validate and store the new token
        if response_data.get("success") is True and "token" in response_data.get("data", {}):
            TOKEN_INFO['token'] = response_data["data"]["token"]
            TOKEN_INFO['expires_in'] = response_data["data"].get("expiresIn", 1800)
            TOKEN_INFO['fetch_time'] = time.time()
            app.logger.info("Successfully fetched new primary token.")
            return True, TOKEN_INFO
        else:
            app.logger.error(f"Remote primary login failed: {response_data}")
            return False, {"error": "Remote primary login failed.", "details": response_data}

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Remote primary connection error: {e}")
        return False, {"error": "Failed to connect to primary auth service.", "details": str(e)}

## Internal Token Helper (NOW WITH EXPIRY CHECK)
def get_active_token():
    """
    Retrieves the currently stored primary token.
    If the primary service is not configured, returns None immediately.
    """
    if not PRIMARY_CONFIGURED:
        return None
        
    global TOKEN_INFO
    
    if not TOKEN_INFO['token']:
        app.logger.info("No primary token found. Performing initial login.")
        success, _ = _perform_login()
        return TOKEN_INFO['token'] if success else None

    current_time = time.time()
    token_age = current_time - TOKEN_INFO['fetch_time']
    
    if token_age > (TOKEN_INFO['expires_in'] - 60):
        app.logger.info("Primary token expired. Performing automatic re-login.")
        success, _ = _perform_login(force_new=True)
        return TOKEN_INFO['token'] if success else None
        
    return TOKEN_INFO['token']


## ---------------------------------
## FLASK ROUTES
## ---------------------------------

## 1. Homepage Route 
@app.route('/')
def index():
    """
    Serves the main HTML page. Checks if *any* service is configured.
    """
    
    if not PRIMARY_CONFIGURED and not SECONDARY_CONFIGURED:
        return "Error: No API service (Primary or Secondary) is configured in the .env file.", 500

    if PRIMARY_CONFIGURED:
        get_active_token()
    
    return render_template('index.html') 


## 2. Login Route (Only primary)
@app.route('/login', methods=['GET', 'POST'])
def remote_login():
    """
    Manually triggers a new login to the primary service.
    """
    if not PRIMARY_CONFIGURED:
        return jsonify({"error": "Primary service configuration is incomplete."}), 404

    success, data = _perform_login(force_new=True)
    
    if success:
        return jsonify({"status": "Primary login successful and token stored internally."}), 200
    else:
        return jsonify(data), 500

## 3. Consolidated API Status Check
@app.route('/api_status', methods=['GET'])
def get_api_status():
    """
    Retrieves the status for both Primary (Publications) and Secondary (S1C IPS) APIs.
    """
    status_response = {
        "primary_status": "Not Configured",
        "secondary_status": "Not Configured",
        "publications": None,
        "ips_status": None,
        "primary_enabled": PRIMARY_CONFIGURED,
        "secondary_enabled": SECONDARY_CONFIGURED
    }

    # --- 1. Get Primary Publications Status ---
    if PRIMARY_CONFIGURED:
        auth_token = get_active_token()
        if auth_token:
            try:
                url = f"{BASE_URL}/app/ipsinfoapp/get_latest_publications/"
                headers = {'Authorization': f'Bearer {auth_token}'}
                response = requests.get(url, headers=headers, timeout=5)
                response.raise_for_status() 
                
                # Safely extract publications data (fixed logic)
                json_data = response.json()
                
                if isinstance(json_data, dict) and "publications" in json_data:
                    status_response["publications"] = json_data["publications"]
                elif isinstance(json_data, list):
                    status_response["publications"] = json_data
                else:
                    status_response["publications"] = [] 

                status_response["primary_status"] = "Success"

            except requests.exceptions.RequestException as e:
                status_response["primary_status"] = "Failed"
                app.logger.error(f"Primary Publications Error: {e}")
        else:
            status_response["primary_status"] = "Auth Failed"

    # --- 2. Get Secondary IPS Status ---
    if SECONDARY_CONFIGURED:
        try:
            secondary_client = SecondaryAPIClient(app.logger)
            status_data = secondary_client.get_ips_status()
            
            if "error" in status_data:
                status_response["secondary_status"] = "Failed"
            else:
                status_response["ips_status"] = status_data
                status_response["secondary_status"] = "Success"
                
        except Exception as e:
            status_response["secondary_status"] = "Internal Error"
            app.logger.error(f"Secondary Status Error: {e}")

    return jsonify(status_response), 200


# 🚨 3. NEW CACHED FUNCTION for Primary API
@cache.memoize(timeout=86400) # 24 hours
def fetch_primary_protection(cve_id, auth_token):
    """
    This function's result will be cached for 24 hours.
    It ONLY queries the primary API.
    The cache key is based on the function name and its arguments (cve_id, auth_token).
    """
    app.logger.info(f"CACHE MISS: Fetching {cve_id} from Primary API.")
    try:
        url = f"{BASE_URL}/app/ipsinfoapp/protections/by-cve/"
        headers = {'Authorization': f'Bearer {auth_token}'}
        params = {'cve_id': cve_id}
        
        response = requests.get(url, headers=headers, params=params, timeout=5)
        response.raise_for_status()
        
        primary_results = response.json()
        
        if primary_results and isinstance(primary_results, list):
            # Rule 2: Cache the result if found
            return primary_results
        else:
            # Rule 1: Do not cache if not found
            # We return a special marker to indicate "not found" vs "error"
            return None 

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Primary API error for {cve_id}: {e}.")
        # Raise exception to prevent caching a failure
        raise


## 4. Get Protections by CVE Route (MODIFIED TO USE CACHE)
@app.route('/protections', methods=['POST'])
def get_protections():
    """ 
    Fetches protection info for a list of CVEs.
    NOW CHECKS CACHE FIRST.
    """
    
    data = request.get_json()
    cve_ids = data.get('cve_ids')
    
    if not cve_ids or not isinstance(cve_ids, list):
        return jsonify({"error": "Missing 'cve_ids' list in JSON body"}), 400

    found_protections = {} 
    cves_needing_fallback = set()
    
    auth_token = get_active_token()
    primary_available = auth_token is not None

    # --- 2. Try Primary API (using the cache) ---
    if primary_available:
        app.logger.info(f"Primary search for {len(cve_ids)} CVEs.")
        for cve_id in cve_ids:
            try:
                # 🚨 5. CALL THE CACHED FUNCTION
                # If cached, this is instant (from file). If not, it runs the function.
                primary_results = fetch_primary_protection(cve_id, auth_token)
                
                if primary_results:
                    # On a cache hit, the function doesn't run, so we don't see "CACHE MISS"
                    app.logger.info(f"Primary API found {len(primary_results)} results for {cve_id}.")
                    for item in primary_results:
                        item["source_label"] = "IPS Protections Database - Infinity Portal"
                        found_protections[item['protection_name']] = item
                else:
                    # Result was 'None', meaning "not found" (Rule 1)
                    cves_needing_fallback.add(cve_id)

            except Exception as e:
                # Function failed (e.g., API was down), mark for fallback
                app.logger.error(f"Primary function failed for {cve_id}: {e}. Marking for fallback.")
                cves_needing_fallback.add(cve_id)
    else:
        app.logger.info("Primary API skipped (missing config or token). All CVEs sent to fallback.")
        cves_needing_fallback.update(cve_ids)

    # --- 3. FALLBACK TO SECONDARY API (S1C) ---
    # (This section remains unchanged for Batch 1. S1C is not yet cached)
    if SECONDARY_CONFIGURED and cves_needing_fallback:
        app.logger.info(f"Secondary fallback search for {len(cves_needing_fallback)} CVEs.")
        secondary_client = SecondaryAPIClient(app.logger)
        
        for cve_id in cves_needing_fallback:
            try:
                secondary_results = secondary_client.search_threat_protections(cve_id)
                
                if secondary_results and isinstance(secondary_results, list):
                    app.logger.info(f"Secondary API found {len(secondary_results)} results for {cve_id}.")
                    for item in secondary_results:
                        item["source_label"] = "Smart-1 Cloud Threat Protection Lookup"
                        if item['protection_name'] not in found_protections:
                            found_protections[item['protection_name']] = item
                            
            except Exception as e:
                app.logger.error(f"Secondary client search failed for {cve_id}: {e}")
                continue

    # --- 4. Final Results ---
    final_results = list(found_protections.values())
    app.logger.info(f"Total unique protections found: {len(final_results)}")
    
    return jsonify(final_results), 200


# --- Run the Flask App ---
if __name__ == '__main__':
    # Note: This block is for development only. Use Gunicorn for production.
    app.run(host='0.0.0.0', port=8080, debug=False)
