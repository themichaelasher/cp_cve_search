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
app.config["CACHE_TYPE"] = "FileSystemCache"
app.config["CACHE_DIR"] = os.path.join(os.getcwd(), 'app_cache') 
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
    global TOKEN_INFO
    if not PRIMARY_CONFIGURED:
        return False, {"error": "Primary service configuration is incomplete."}
    try:
        login_url = f"{BASE_URL}/auth/external"
        payload = {"clientId": CLIENT_ID, "accessKey": ACCESS_ID}
        response = requests.post(login_url, json=payload, timeout=5)
        response.raise_for_status()
        response_data = response.json()
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

def get_active_token():
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
@app.route('/')
def index():
    if not PRIMARY_CONFIGURED and not SECONDARY_CONFIGURED:
        return "Error: No API service (Primary or Secondary) is configured in the .env file.", 500
    if PRIMARY_CONFIGURED:
        get_active_token()
    return render_template('index.html') 

@app.route('/login', methods=['GET', 'POST'])
def remote_login():
    if not PRIMARY_CONFIGURED:
        return jsonify({"error": "Primary service configuration is incomplete."}), 404
    success, data = _perform_login(force_new=True)
    if success:
        return jsonify({"status": "Primary login successful and token stored internally."}), 200
    else:
        return jsonify(data), 500

@app.route('/api_status', methods=['GET'])
def get_api_status():
    status_response = {
        "primary_status": "Not Configured",
        "secondary_status": "Not Configured",
        "publications": None,
        "ips_status": None,
        "primary_enabled": PRIMARY_CONFIGURED,
        "secondary_enabled": SECONDARY_CONFIGURED
    }
    if PRIMARY_CONFIGURED:
        auth_token = get_active_token()
        if auth_token:
            try:
                url = f"{BASE_URL}/app/ipsinfoapp/get_latest_publications/"
                headers = {'Authorization': f'Bearer {auth_token}'}
                response = requests.get(url, headers=headers, timeout=5)
                response.raise_for_status() 
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


# 🚨 --- CACHED HELPER FUNCTIONS --- 🚨

@cache.memoize(timeout=86400) # 24 hours
def fetch_primary_protection(cve_id, auth_token):
    """
    This function's result will be cached for 24 hours.
    It ONLY queries the primary API.
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
            for item in primary_results:
                item["source_label"] = "IPS Protections Database - Infinity Portal"
            return primary_results
        else:
            return None 
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Primary API error for {cve_id}: {e}.")
        raise 


@cache.memoize(timeout=3600) # 1 hour
def fetch_secondary_protection(cve_id):
    """
    This function's result will be cached for 1 HOUR.
    It ONLY queries the secondary (S1C) API.
    """
    app.logger.info(f"CACHE MISS: Fetching {cve_id} from Secondary API (S1C).")
    secondary_client = SecondaryAPIClient(app.logger)
    
    try:
        secondary_results = secondary_client.search_threat_protections(cve_id)
        
        if secondary_results and isinstance(secondary_results, list):
            app.logger.info(f"Secondary API found {len(secondary_results)} results for {cve_id}.")
            for item in secondary_results:
                item["source_label"] = "Smart-1 Cloud Threat Protection Lookup"
            return secondary_results
        else:
            return None
    except Exception as e:
        app.logger.error(f"Secondary client search failed for {cve_id}: {e}")
        raise


## 4. Get Protections by CVE Route (MODIFIED TO RETURN UNFOUND CVES)
@app.route('/protections', methods=['POST'])
def get_protections():
    """ 
    Fetches protection info for a list of CVEs.
    Returns an object: { "found_protections": [...], "unfound_cves": [...] }
    """
    
    data = request.get_json()
    cve_ids = data.get('cve_ids')
    
    if not cve_ids or not isinstance(cve_ids, list):
        return jsonify({"error": "Missing 'cve_ids' list in JSON body"}), 400

    # 🚨 --- NEW LOGIC TO TRACK FOUND/UNFOUND ---
    # Normalize input to uppercase for comparison
    input_cve_set = set(cve.upper() for cve in cve_ids)
    # This set will track which *input* CVEs successfully return a result
    found_cve_inputs = set()
    # -------------------------------------------

    found_protections = {} 
    cves_needing_fallback = set()
    
    auth_token = get_active_token()
    primary_available = auth_token is not None

    # --- 2. Try Primary API (using the cache) ---
    if primary_available:
        app.logger.info(f"Primary search for {len(cve_ids)} CVEs.")
        for cve_id in cve_ids:
            try:
                primary_results = fetch_primary_protection(cve_id, auth_token)
                
                if primary_results:
                    app.logger.info(f"Primary API (Cache/Live) found {len(primary_results)} results for {cve_id}.")
                    found_cve_inputs.add(cve_id.upper()) # 🚨 Mark this input CVE as found
                    for item in primary_results:
                        found_protections[item['protection_name']] = item
                else:
                    cves_needing_fallback.add(cve_id) # Not found, mark for fallback

            except Exception as e:
                app.logger.error(f"Primary function failed for {cve_id}: {e}. Marking for fallback.")
                cves_needing_fallback.add(cve_id)
    else:
        app.logger.info("Primary API skipped (missing config or token). All CVEs sent to fallback.")
        cves_needing_fallback.update(cve_ids)

    # --- 3. FALLBACK TO SECONDARY API (S1C) (NOW CACHED) ---
    if SECONDARY_CONFIGURED and cves_needing_fallback:
        app.logger.info(f"Secondary fallback search for {len(cves_needing_fallback)} CVEs.")
        
        for cve_id in cves_needing_fallback:
            try:
                secondary_results = fetch_secondary_protection(cve_id)
                
                if secondary_results:
                    app.logger.info(f"S1C (Cache/Live) found {len(secondary_results)} results for {cve_id}.")
                    found_cve_inputs.add(cve_id.upper()) # 🚨 Mark this input CVE as found
                    for item in secondary_results:
                        if item['protection_name'] not in found_protections:
                            found_protections[item['protection_name']] = item
                            
            except Exception as e:
                app.logger.error(f"Secondary function failed for {cve_id}: {e}")
                continue # Let it be marked as "unfound"

    # --- 4. Final Results ---
    final_results = list(found_protections.values())
    
    # 🚨 Calculate unfound CVEs by comparing the original input set with the set we found
    unfound_cves = list(input_cve_set - found_cve_inputs)
    
    app.logger.info(f"Total unique protections found: {len(final_results)}. Unfound CVEs: {len(unfound_cves)}")
    
    # 🚨 Return the new object structure
    return jsonify({
        "found_protections": final_results,
        "unfound_cves": unfound_cves
    }), 200


# --- Run the Flask App ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
