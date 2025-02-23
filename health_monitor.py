import requests
import time
from datetime import datetime

# Health check endpoint
HEALTH_URL = "https://sqlpremierleague-backend.onrender.com/health"

# Time interval (in seconds)
CHECK_INTERVAL = 30  

def log_status(message):
    """Log the message with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    
    # Print log to console
    print(log_message)

    # Append log to file
    with open("health_log.txt", "a") as log_file:
        log_file.write(log_message + "\n")

def check_health():
    """Ping the health endpoint and log the status."""
    try:
        start_time = time.time()  # Track response time
        response = requests.get(HEALTH_URL, timeout=5)
        response_time = round(time.time() - start_time, 2)

        if response.status_code == 200:
            log_status(f"✅ Service is UP | Response Time: {response_time}s")
        else:
            log_status(f"⚠️ Service returned status {response.status_code} | Response: {response.text}")

    except requests.exceptions.RequestException as e:
        log_status(f"❌ Service is DOWN | Error: {e}")

if __name__ == "__main__":
    log_status("🚀 Starting Health Monitor...")

    while True:
        check_health()
        time.sleep(CHECK_INTERVAL)  # Wait before next check
