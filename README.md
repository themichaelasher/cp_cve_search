# Check Point CVE Search

This is a simple demo to search IPS Protections via the Infinity Portal using the IPS publications API. 
More information can be found in the following documentation:

* https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Infinity-Portal-Admin-Guide/Content/Topics-Infinity-Portal/API-Keys.htm
* https://support.checkpoint.com/results/sk/sk184153

> **Warning:** A lot of help came from Google's Gemini, so your mileage may vary. 

---

## 🔧 Configuration

This application is configured entirely through environment variables. Before running the application, you **must** create a `.env` file in the root of the project.

1.  Create a file named `.env`:
    ```bash
    touch .env
    ```
2.  Add the following variables to the file, filling in your specific credentials:

    ```ini
    # --- .env file ---
    
    # The base URL of the remote API you are connecting to
    REMOTE_API_BASE_URL=[https://api.example.com](https://api.example.com)
    
    # Your credentials for the remote API
    INITIAL_CLIENT_ID=your-client-id-goes-here
    INITIAL_ACCESS_ID=your-access-key-goes-here
    ```

> **Warning:** The `.env` file contains secrets. Ensure it is listed in your `.gitignore` file and **never** committed to source control.
---

## 🏃‍♀️ Running the Application

There are two primary ways to run this application. The recommended method for production is using Docker Compose.

### Method 1: Using Docker Compose (Recommended)

This is the simplest way to get the application and all its dependencies running.

1.  **Build the image:**
    *(This uses the `image: cp_cve_search` name defined in your `docker-compose.yml`)*
    ```bash
    docker-compose build
    ```

2.  **Run the container:**
    *(This will automatically load the `.env` file and map port 8080)*
    ```bash
    docker-compose up -d
    ```

The application will now be running and accessible at `http://localhost:8080`.

To stop the application, run:
```bash
docker-compose down