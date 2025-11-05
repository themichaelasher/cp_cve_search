# [Your Project Name Here, e.g., Remote API Proxy]

This is a simple Flask application that acts as a secure proxy for a remote API. It is designed to be run in a Docker container.

Its primary purpose is to handle all authentication, token caching, and token renewal, providing a stable and simple set of internal endpoints for a frontend application to consume.

## 🚀 Features

* **Automatic Authentication:** Securely logs into the remote API using credentials provided via environment variables.
* **Token Caching & Renewal:** Stores the session token and automatically refreshes it before it expires, preventing frontend authentication errors.
* **Simplified API:** Exposes clean endpoints (`/publications`, `/protections`) for the frontend to use without worrying about authentication.
* **Frontend Hosting:** Serves the main `index.html` page from the `templates` folder.
* **Container-Ready:** Includes a `Dockerfile` and `docker-compose.yml` for easy, reproducible builds and deployment.

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
    *(This uses the `image: my-api-app` name defined in your `docker-compose.yml`)*
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