# Step 1: Start from a lightweight official Python image based on Alpine
FROM python:3-alpine

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy the requirements file first (for better cache utilization)
COPY requirements.txt .

# Step 4: Install the Python dependencies
# --no-cache-dir reduces the image size
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy the rest of your application code into the container
# This includes app.py and your 'templates' folder
COPY . .

# Step 6: Expose the port your app runs on (from app.py)
EXPOSE 8080

# Step 7: Define the command to run your application
# This runs 'python app.py' when the container starts
CMD ["python", "app.py"]