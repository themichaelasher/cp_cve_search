import os
import requests
import time # For tracking token age
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv, find_dotenv 
from s1c_api import SecondaryAPIClient

# Accomodate stack.env if using portainer. 
env_file = find_dotenv(filename='stack.env', usecwd=True, raise_error_if_not_found=False)

if env_file:
    load_dotenv(env_file)
    ## app.logger.info(f"Loaded environment variables from: {env_file}")
else:
    ## app.logger.warning("Configuration file (.env or stack.env) not found.")
    load_dotenv() # Fallback to load from default location just in case

app = Flask(__name__)

# --- Global Token Storage ---
# We now also store the time the token was fetched
TOKEN_INFO = {
    'token': None,
    'expires_in': 0,
    'fetch_time': 0  # Timestamp of when the token was acquired
}

# --- Configuration ---
BASE_URL = os.getenv("IP_REMOTE_URL")
CLIENT_ID = os.getenv("IP_CLIENT_ID")
ACCESS_ID = os.getenv("IP_ACCESS_ID")

if not BASE_URL:
    raise EnvironmentError("IP_REMOTE_URL not set in .env file.")

def _perform_login(force_new=False):
    """
    Internal function to perform the actual login to the remote service.
    'force_new=True' will force a new login even if token seems valid.
    """
    global TOKEN_INFO
    
    # 1. Prepare credentials (using .env as the source)
    if not CLIENT_ID or not ACCESS_ID:
        app.logger.error("Missing IP_CLIENT_ID or IP_ACCESS_ID in .env")
        return False, {"error": "Server credentials not configured."}

    # 2. Make the remote API call
    try:
        login_url = f"{BASE_URL}/auth/external"
        payload = {"clientId": CLIENT_ID, "accessKey": ACCESS_ID}
        
        response = requests.post(login_url, json=payload)
        response.raise_for_status()
        response_data = response.json()

        # 3. Validate and store the new token
        if response_data.get("success") is True and "token" in response_data.get("data", {}):
            TOKEN_INFO['token'] = response_data["data"]["token"]
            TOKEN_INFO['expires_in'] = response_data["data"].get("expiresIn", 1800) # Default to 30 mins
            TOKEN_INFO['fetch_time'] = time.time() # Store the *current* time
            app.logger.info("Successfully fetched new token.")
            return True, TOKEN_INFO
        else:
            app.logger.error(f"Remote login failed: {response_data}")
            return False, {"error": "Remote login failed.", "details": response_data}

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Remote login connection error: {e}")
        return False, {"error": "Failed to connect to remote auth service.", "details": str(e)}

## Internal Token Helper (NOW WITH EXPIRY CHECK)
def get_active_token():
    """
    Retrieves the currently stored token.
    If the token is expired or missing, it triggers a new login.
    """
    global TOKEN_INFO
    
    if not TOKEN_INFO['token']:
        app.logger.info("No token found. Performing initial login.")
        success, _ = _perform_login()
        return TOKEN_INFO['token'] if success else None

    # Check expiration. Add a 60-second buffer to be safe.
    current_time = time.time()
    token_age = current_time - TOKEN_INFO['fetch_time']
    
    if token_age > (TOKEN_INFO['expires_in'] - 60):
        app.logger.info("Token expired. Performing automatic re-login.")
        success, _ = _perform_login(force_new=True)
        return TOKEN_INFO['token'] if success else None
        
    # Token is valid and not expired
    return TOKEN_INFO['token']


## ---------------------------------
## FLASK ROUTES
## ---------------------------------

## 1. NEW Homepage Route
@app.route('/')
def index():
    """
    Serves the main HTML page.
    It implicitly triggers a login via get_active_token() if needed.
    """
    # This check ensures we have a valid token *before* loading the page
    if not get_active_token():
        return "Error: Could not authenticate with primary remote service. Check server logs and .env file.", 500
        
    # Render the index.html file from the 'templates' folder
    return render_template('index.html')


## 2. Login Route (Now simplified)
@app.route('/login', methods=['GET', 'POST'])
def remote_login():
    """
    Manually triggers a new login to the primary service.
    """
    success, data = _perform_login(force_new=True)
    
    if success:
        return jsonify({"status": "Primary login successful and token stored internally."}), 200
    else:
        return jsonify(data), 500


## 3. Get Latest Publications Route
@app.route('/publications', methods=['GET'])
def get_publications():
    """ Fetches publications using the internal token. """
    auth_token = get_active_token()
    if not auth_token:
        # This will return a 401 if the token is missing
        return jsonify({"error": "No active authentication token."}), 401

    try:
        url = f"{BASE_URL}/app/ipsinfoapp/get_latest_publications/"
        headers = {'Authorization': f'Bearer {auth_token}'}
        
        # Make the remote call
        response = requests.get(url, headers=headers)
        
        # This line will raise an HTTPError if the remote server sent a 4xx or 5xx
        response.raise_for_status() 
        
        # Success!
        return jsonify(response.json()), 200

    except requests.exceptions.HTTPError as e:
        app.logger.error(f"REMOTE HTTP Error on /publications: {e}")
        status_code = e.response.status_code if e.response is not None else 500
        
        # Pass the remote error and status code back to the browser
        return jsonify({
            "error": "Remote service returned an error for publications", 
            "details": str(e), 
            "status_code": status_code
        }), status_code

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Connection Error on /publications: {e}")
        
        # This is a true 503 (we couldn't connect)
        return jsonify({
            "error": "Failed to fetch publications (Connection Error)", 
            "details": str(e)
        }), 503


## 4. Get Protections by CVE Route (MODIFIED FOR FALLBACK & SOURCE)
@app.route('/protections', methods=['GET', 'POST'])
def get_protections():
    """ 
    Fetches protection info for a CVE using the primary service. 
    If no results are found, it falls back to the secondary service (S1C),
    and adds a 'source_label' field to the results.
    """
    auth_token = get_active_token()
    if not auth_token:
        return jsonify({"error": "No active authentication token for primary service."}), 401

    cve_id = None
    if request.method == 'POST':
        cve_id = request.get_json().get('cve_id')
    elif request.method == 'GET':
        cve_id = request.args.get('cve_id')
    
    if not cve_id:
        return jsonify({"error": "Missing 'cve_id' in JSON body or query parameters"}), 400

    # --- 1. Try Primary API ---
    primary_error = None
    try:
        url = f"{BASE_URL}/app/ipsinfoapp/protections/by-cve/"
        headers = {'Authorization': f'Bearer {auth_token}'}
        params = {'cve_id': cve_id}
        
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        primary_results = response.json()
        
        # Check if the primary API returned results
        if primary_results and isinstance(primary_results, list) and len(primary_results) > 0:
            app.logger.info(f"Primary API found {len(primary_results)} results for {cve_id}.")
            
            # --- NEW: ADD PRIMARY SOURCE LABEL ---
            for item in primary_results:
                item["source_label"] = "IPS Protections Database - Infinity Portal"
            # ------------------------------------
            
            return jsonify(primary_results), 200
        
        # If no results, proceed to fallback
        app.logger.info(f"Primary API returned no results for {cve_id}. Attempting Secondary API fallback.")

    except requests.exceptions.RequestException as e:
        primary_error = e # Store the error, but continue to fallback
        app.logger.error(f"Primary API error for {cve_id}: {e}. Falling back to Secondary API.")

    # --- 2. FALLBACK TO SECONDARY API (S1C) ---
    try:
        secondary_client = SecondaryAPIClient(app.logger)
        secondary_results = secondary_client.search_threat_protections(cve_id)
        
        if secondary_results and isinstance(secondary_results, list) and len(secondary_results) > 0:
            app.logger.info(f"Secondary API found {len(secondary_results)} results for {cve_id}.")
            
            # --- NEW: ADD SECONDARY SOURCE LABEL ---
            for item in secondary_results:
                item["source_label"] = "Smart-1 Cloud Threat Protection Lookup"
            # ---------------------------------------
            
            return jsonify(secondary_results), 200
        
        # --- 3. Final Failure / No Results ---
        app.logger.info(f"Both APIs found no results for {cve_id}.")
        
        # If the primary service had an error, report that error
        if primary_error:
            status_code = getattr(primary_error.response, 'status_code', 503) 
            return jsonify({
                "error": "Failed to connect to primary service, and secondary found no results.", 
                "primary_details": str(primary_error),
                "status_code": status_code
            }), status_code

        # If primary service worked but returned empty list, and secondary also returned empty list.
        return jsonify([]), 200 

    except Exception as secondary_error:
        # Catch any unexpected error during secondary API process (e.g., config error, bad login)
        app.logger.error(f"Unexpected error during Secondary API process: {secondary_error}")
        
        # Prioritize the primary API's error if one occurred
        if primary_error:
            status_code = getattr(primary_error.response, 'status_code', 503) 
            return jsonify({
                "error": "Failed to connect to primary service, and secondary service failed too.", 
                "primary_details": str(primary_error),
                "secondary_error": str(secondary_error)
            }), status_code
        
        # If primary was just empty, and secondary failed, return 500 for the secondary failure
        return jsonify({
            "error": "Primary API returned no results, and secondary service failed.",
            "secondary_error": str(secondary_error)
        }), 500


# --- Run the Flask App ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)

