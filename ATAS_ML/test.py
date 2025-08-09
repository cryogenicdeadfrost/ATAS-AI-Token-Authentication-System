import requests

# URL of the deployed FastAPI endpoint
url = "https://anomali.onrender.com/predict"

# Define the payload with test values
payload = {
    "request_interval": 15,
    "token_length": 7000,
    "model_number": 2
}

# Send a POST request with the JSON payload
response = requests.post(url, json=payload)

# Print the JSON response from the API
if response.status_code == 200:
    print("Response from API:")
    print(response.json())
else:
    print(f"Request failed with status code {response.status_code}")
