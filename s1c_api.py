import os
import requests
import time
from dotenv import load_dotenv

# Load environment variables (needed for configuration)
load_dotenv()

# --- Configuration for Secondary Service ---
S1C_FULL_LOGIN_URL = os.getenv("S1C_URL")
S1C_API_KEY = os.getenv("S1C_APIKEY")

# Safety checks
if not S1C_FULL_LOGIN_URL or not S1C_API_KEY:
    pass

# Calculate the base URL
# If S1C_URL is https://base/path/web_api/v2/login, we want https://base/path
try:
    # Use a generic split based on the common structure
    base_parts = S1C_FULL_LOGIN_URL.split('/web_api/', 1)
    S1C_BASE_URL = base_parts[0] if len(base_parts) > 0 else ""
except AttributeError:
    S1C_BASE_URL = "" 

# Paths as provided by the user
S1C_LOGIN_PATH = "/web_api/v2/login"
S1C_QUERY_PATH = "/web_api/v2/show-threat-protections"
S1C_LOGOUT_PATH = "/web_api/v2/logout"

class SecondaryAPIClient:
    """
    Client for the Secondary API (S1C), handling login, querying, and required logout.
    Uses 'sid' from the JSON response as the session ID in the X-chkp-sid header.
    """
    def __init__(self, logger):
        self.logger = logger
        self.base_url = S1C_BASE_URL
        self.api_key = S1C_API_KEY
        # session_id is initialized to None and set after successful login
        self.session_id = None 
        # Flag to help track if logout is necessary
        self.login_successful = False

    def _login(self):
        """ 
        Performs the login, extracts the 'sid' from the JSON response, 
        and stores it as self.session_id.
        """
        if not self.base_url or not self.api_key:
            self.logger.error("Secondary API credentials missing. Check .env file.")
            return False

        self.logger.info("Attempting login to Secondary API...")
        login_url = self.base_url + S1C_LOGIN_PATH
        
        payload = {
            "api-key": self.api_key,
            "session-timeout": 600 
        }
        
        try:
            response = requests.post(login_url, json=payload, headers={'Content-Type': 'application/json'})
            response.raise_for_status()
            data = response.json()
            
            # 🚨 FINAL FIX: Extracting the 'sid' from the JSON body
            session_id_from_body = data.get("sid")

            if session_id_from_body:
                self.session_id = session_id_from_body
                self.login_successful = True # Set flag for successful login
                self.logger.info("Secondary API login successful. 'sid' obtained from JSON.")
                return True
            else:
                self.logger.error(f"Secondary API login failed: 'sid' not found in response: {data}")
                return False

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Secondary API login connection/validation error: {e}")
            return False

    def _logout(self):
        """ 
        Performs the required logout using the extracted 'sid' as the X-chkp-sid header.
        """
        if not self.login_successful:
            return True 
            
        self.logger.info("Performing required logout from Secondary API.")
        logout_url = self.base_url + S1C_LOGOUT_PATH
        
        headers = {
            'Content-Type': 'application/json',
            'X-chkp-sid': str(self.session_id) # Ensure the session ID is explicitly a string
        }
        
        try:
            requests.post(logout_url, json={}, headers=headers)
            self.logger.info("Secondary API logout attempted.")

        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Error during Secondary API logout: {e}")
        finally:
            self.session_id = None
            self.login_successful = False # Clear flag

    def _query_api(self, cve_id):
        """
        Performs the search for threat-protections using the X-chkp-sid header.
        """
        if not self.session_id:
            self.logger.error("Cannot query secondary API: No active session.")
            return [] 

        query_url = self.base_url + S1C_QUERY_PATH
        
        headers = {
            'Content-Type': 'application/json',
            'X-chkp-sid': str(self.session_id) # Use the extracted SID for authorization
        }

        payload = {
            "filter": cve_id,
            "details-level": "full" 
        }

        try:
            response = requests.post(query_url, json=payload, headers=headers)
            response.raise_for_status() 

            data = response.json()
            # Extract the list from the 'protections' key
            raw_objects = data.get('protections', []) 
            
            self.logger.info(f"Secondary API search returned {len(raw_objects)} results.")
            return raw_objects 

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Secondary API query error: {e}")
            return [] 

    def _normalize_data(self, item):
        """
        Converts the S1C JSON format into the Primary API's expected format.
        """
        return {
            "protection_name": item.get("name", "N/A"), 
            "protection_description": item.get("comments", "No detailed description available from secondary source."), 
            "severity_level": item.get("severity", "N/A"), 
            "confidence_level": item.get("confidence-level", "N/A"), 
            "protection_advisory_url": "N/A", 
            "cve": item.get("industry-reference", []), 
            "vulnerable_systems": "Information not explicitly provided by this endpoint."
        }

    def search_threat_protections(self, cve_id):
        """
        Main entry point. Performs login, search, data normalization, and logout.
        """
        if not self._login():
            return [] 

        try:
            raw_objects = self._query_api(cve_id)
            
            # Data is normalized only if raw_objects is not empty
            normalized_results = [self._normalize_data(obj) for obj in raw_objects]
            
            return normalized_results

        finally:
            self._logout()

        return []

    def get_ips_status(self):
        """
        Retrieves the installed IPS database version from the secondary API.
        Performs login, status query, and mandatory logout.
        """
        if not self._login():
            return {"error": "Failed to log in to Secondary API for status check."}

        try:
            status_url = self.base_url + "/web_api/v2/show-ips-status"

            headers = {
                'Content-Type': 'application/json',
                'X-chkp-sid': str(self.session_id)
            }

            self.logger.info("Querying Secondary API for IPS status.")
            response = requests.post(status_url, json={}, headers=headers)
            response.raise_for_status()

            data = response.json()

            # Extract and normalize the relevant fields
            return {
                "installed_version": data.get("installed-version"),
                "last_updated_time": data.get("last-updated", {}).get("iso-8601"),
                "update_available": data.get("update-available", False)
            }

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Secondary API IPS status query error: {e}")
            return {"error": f"Failed to fetch IPS status: {e}"}

        finally:
            self.logger.info("Ensuring logout after IPS status check.")
            self._logout()
