from flask import Flask, request, jsonify, render_template_string, g
from flask_cors import CORS
import requests
from datetime import datetime, timedelta, UTC
import jwt
import secrets
import string
import time
import uuid
import json
import random
import os
import sqlite3
import secrets

app = Flask(__name__)
# Fix CORS to ensure frontend can communicate with backend
CORS(app, resources={r"/*": {"origins": "*"}})

# Replace with your actual IPQS API key
IPQS_API_KEY = "3ArtTqAVJMTuGsxug552RBtU8rzrRmdU"

# JWT Configuration
# Change this to a strong secret key
JWT_SECRET = secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 60  # Token expiry in minutes

# Anomaly detection API endpoint
ANOMALY_API_ENDPOINT = "https://anomali.onrender.com/predict"

# Database file path
DATABASE_PATH = "atas.db"

# Dictionary to store IP request tracking (temporary in-memory tracking)
ip_request_tracking = {}

#----------------------------
# Database Functions
#----------------------------

def get_db():
    """
    Get a database connection. The connection is unique for each request and will
    be reused if this is called again during the same request.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        # Enable foreign key support
        g.db.execute("PRAGMA foreign_keys = ON")
        # Return rows as dictionaries
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """
    Close the database connection at the end of the request.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.teardown_appcontext
def close_database_connection(exception):
    """Close database connection at the end of each request"""
    close_db()

def init_db():
    """
    Initialize the database by creating all required tables if they don't exist.
    """
    # Create a connection outside the application context
    conn = sqlite3.connect(DATABASE_PATH)
    
    # Create tables
    conn.executescript('''
    -- IP Addresses Table
    CREATE TABLE IF NOT EXISTS ip_addresses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        first_seen TIMESTAMP NOT NULL,
        last_seen TIMESTAMP NOT NULL,
        is_revoked BOOLEAN NOT NULL DEFAULT 0,
        revoked_at TIMESTAMP,
        revocation_reason TEXT,
        total_requests INTEGER NOT NULL DEFAULT 0,
        is_proxy BOOLEAN NOT NULL DEFAULT 0,
        is_vpn BOOLEAN NOT NULL DEFAULT 0,
        fraud_score INTEGER DEFAULT 0
    );
    
    -- API Keys Table
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key TEXT NOT NULL UNIQUE,
        ip_address_id INTEGER NOT NULL,
        created_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT 1,
        model TEXT NOT NULL,
        tokens INTEGER NOT NULL,
        purpose TEXT NOT NULL,
        FOREIGN KEY (ip_address_id) REFERENCES ip_addresses (id)
    );
    
    -- JWT Tokens Table
    CREATE TABLE IF NOT EXISTS jwt_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        jwt_token TEXT NOT NULL UNIQUE,
        api_key_id INTEGER NOT NULL,
        created_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        FOREIGN KEY (api_key_id) REFERENCES api_keys (id)
    );
    
    -- Request Log Table
    CREATE TABLE IF NOT EXISTS request_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address_id INTEGER NOT NULL,
        api_key_id INTEGER,
        timestamp TIMESTAMP NOT NULL,
        request_type TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        success BOOLEAN NOT NULL,
        response_code INTEGER,
        request_data TEXT,
        response_data TEXT,
        FOREIGN KEY (ip_address_id) REFERENCES ip_addresses (id),
        FOREIGN KEY (api_key_id) REFERENCES api_keys (id)
    );
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully!")

# Initialize the database when the file is loaded
init_db()

def add_ip_address(ip, is_proxy=False, is_vpn=False, fraud_score=0):
    """
    Add or update an IP address in the database.
    """
    db = get_db()
    now = datetime.now().isoformat()
    
    # Check if IP already exists
    ip_record = db.execute(
        'SELECT id, total_requests FROM ip_addresses WHERE ip_address = ?',
        (ip,)
    ).fetchone()
    
    if ip_record:
        # Update existing IP
        db.execute(
            '''UPDATE ip_addresses 
               SET last_seen = ?, 
                   total_requests = total_requests + 1,
                   is_proxy = ?,
                   is_vpn = ?,
                   fraud_score = ?
               WHERE id = ?''',
            (now, is_proxy, is_vpn, fraud_score, ip_record['id'])
        )
        ip_id = ip_record['id']
    else:
        # Insert new IP
        cursor = db.execute(
            '''INSERT INTO ip_addresses 
               (ip_address, first_seen, last_seen, total_requests, is_proxy, is_vpn, fraud_score)
               VALUES (?, ?, ?, 1, ?, ?, ?)''',
            (ip, now, now, is_proxy, is_vpn, fraud_score)
        )
        ip_id = cursor.lastrowid
    
    db.commit()
    return ip_id

def revoke_ip(ip_address, reason="Administrative action"):
    """
    Revoke an IP address and deactivate all its API keys.
    """
    db = get_db()
    now = datetime.now().isoformat()
    
    # Update IP record
    db.execute(
        '''UPDATE ip_addresses 
           SET is_revoked = 1, 
               revoked_at = ?, 
               revocation_reason = ?
           WHERE ip_address = ?''',
        (now, reason, ip_address)
    )
    
    # Get the IP ID
    ip_record = db.execute(
        'SELECT id FROM ip_addresses WHERE ip_address = ?',
        (ip_address,)
    ).fetchone()
    
    if ip_record:
        # Deactivate all API keys for this IP
        db.execute(
            'UPDATE api_keys SET is_active = 0 WHERE ip_address_id = ?',
            (ip_record['id'],)
        )
    
    db.commit()
    return True

def add_api_key(api_key, ip_address, model, tokens, purpose, expires_at):
    """
    Add a new API key to the database.
    """
    db = get_db()
    now = datetime.now().isoformat()
    
    # Get the IP ID (create if not exists)
    ip_id = add_ip_address(ip_address)
    
    # Check if IP is revoked
    ip_record = db.execute(
        'SELECT is_revoked FROM ip_addresses WHERE id = ?',
        (ip_id,)
    ).fetchone()
    
    # If IP is revoked, don't create a key
    if ip_record['is_revoked']:
        return None
    
    # Insert API key
    cursor = db.execute(
        '''INSERT INTO api_keys 
           (api_key, ip_address_id, created_at, expires_at, model, tokens, purpose)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (api_key, ip_id, now, expires_at, model, tokens, purpose)
    )
    
    db.commit()
    return cursor.lastrowid

def add_jwt_token(jwt_token, api_key, expires_at):
    """
    Add a new JWT token to the database.
    """
    db = get_db()
    now = datetime.now().isoformat()
    
    # Get the API key ID
    api_key_record = db.execute(
        'SELECT id FROM api_keys WHERE api_key = ?',
        (api_key,)
    ).fetchone()
    
    if not api_key_record:
        return None
    
    # Insert JWT token
    cursor = db.execute(
        '''INSERT INTO jwt_tokens 
           (jwt_token, api_key_id, created_at, expires_at)
           VALUES (?, ?, ?, ?)''',
        (jwt_token, api_key_record['id'], now, expires_at)
    )
    
    db.commit()
    return cursor.lastrowid

def log_request(ip_address, api_key, endpoint, request_type, success, response_code, request_data=None, response_data=None):
    """
    Log a request to the database.
    """
    db = get_db()
    now = datetime.now().isoformat()
    
    # Get the IP ID (create if not exists)
    ip_id = add_ip_address(ip_address)
    
    # Get the API key ID (if provided)
    api_key_id = None
    if api_key and api_key != "access_denied" and api_key != "REVOKED":
        api_key_record = db.execute(
            'SELECT id FROM api_keys WHERE api_key = ?',
            (api_key,)
        ).fetchone()
        if api_key_record:
            api_key_id = api_key_record['id']
    
    # Insert request log
    cursor = db.execute(
        '''INSERT INTO request_log 
           (ip_address_id, api_key_id, timestamp, endpoint, request_type, success, response_code, request_data, response_data)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (ip_id, api_key_id, now, endpoint, request_type, success, response_code, 
         request_data, response_data)
    )
    
    db.commit()
    return cursor.lastrowid

def verify_api_key(api_key):
    """
    Verify if an API key is valid and active.
    """
    db = get_db()
    now = datetime.now().isoformat()
    
    # Get the API key record
    api_key_record = db.execute(
        '''SELECT a.*, i.is_revoked, i.ip_address 
           FROM api_keys a
           JOIN ip_addresses i ON a.ip_address_id = i.id
           WHERE a.api_key = ?''',
        (api_key,)
    ).fetchone()
    
    if not api_key_record:
        return False, {"message": "Invalid API key"}
    
    # Check if IP is revoked
    if api_key_record['is_revoked']:
        return False, {"message": f"Access from IP {api_key_record['ip_address']} has been revoked"}
    
    # Check if key is active
    if not api_key_record['is_active']:
        return False, {"message": "API key is not active"}
    
    # Check if key is expired
    if api_key_record['expires_at'] < now:
        return False, {"message": "API key has expired"}
    
    return True, {
        "type": "api_key",
        "model": api_key_record['model'],
        "tokens": api_key_record['tokens'],
        "purpose": api_key_record['purpose'],
        "expires_at": api_key_record['expires_at']
    }

def get_all_revoked_ips():
    """
    Get a list of all revoked IP addresses.
    """
    db = get_db()
    
    revoked_ips = db.execute(
        'SELECT ip_address FROM ip_addresses WHERE is_revoked = 1'
    ).fetchall()
    
    return [ip['ip_address'] for ip in revoked_ips]

def get_all_requests():
    """
    Get a list of all requests with IP and API key information for the dashboard.
    """
    db = get_db()
    
    requests = db.execute(
        '''SELECT r.id, r.timestamp, r.endpoint, r.success, r.response_code, r.response_data,
                 i.ip_address, i.is_proxy, i.is_vpn, i.fraud_score, i.is_revoked,
                 a.api_key, a.model, a.purpose, a.tokens, a.is_active
          FROM request_log r
          JOIN ip_addresses i ON r.ip_address_id = i.id
          LEFT JOIN api_keys a ON r.api_key_id = a.id
          ORDER BY r.timestamp DESC
          LIMIT 100'''
    ).fetchall()
    
    # Convert to format expected by frontend
    result = []
    for r in requests:
        # Convert SQLite Row to dictionary
        item = dict(r)
        
        # Try to extract anomaly score from the response_data JSON if exists
        anomaly_score = "N/A"
        try:
            if item["response_data"]:
                response_data = json.loads(item["response_data"])
                if isinstance(response_data, dict) and "anomaly_check" in response_data:
                    anomaly_percentage = response_data["anomaly_check"].get("anomaly_percentage", "N/A")
                    anomaly_score = anomaly_percentage
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
        
        # Format for dashboard display
        dashboard_item = {
            "timestamp": item["timestamp"],
            "ip_address": item["ip_address"],
            "model": item.get("model", "N/A"),
            "purpose": item.get("purpose", "N/A"),
            "fraud_score": item["fraud_score"],
            "anomaly_score": anomaly_score,
            "api_key": item.get("api_key", "N/A"),
            "is_proxy": item["is_proxy"],
            "is_vpn": item["is_vpn"],
            "is_revoked": item["is_revoked"]
        }
        
        # Add status field
        if item["is_revoked"]:
            dashboard_item["status"] = "Revoked"
        elif not item["success"]:
            dashboard_item["status"] = "Denied"
        else:
            dashboard_item["status"] = "Active"
            
        result.append(dashboard_item)
    
    return result

#----------------------------
# Utility Functions
#----------------------------

def check_ip_reputation(ip):
    """
    Check IP reputation using IPQS API
    """
    print(f"Checking IP reputation for: {ip}")
    
    url = f"https://www.ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}"
    try:
        response = requests.get(url)
        data = response.json()
        
        print(f"IPQS response: {data}")

        # Extract relevant data
        is_proxy = data.get("proxy", False)
        is_vpn = data.get("vpn", False)
        fraud_score = data.get("fraud_score", 0)

        # Store in database
        add_ip_address(ip, is_proxy, is_vpn, fraud_score)

        return {
            "is_proxy": is_proxy,
            "is_vpn": is_vpn,
            "fraud_score": fraud_score
        }
    except Exception as e:
        print(f"IPQS API error: {str(e)}")
        # Return default values if API call fails
        return {
            "is_proxy": False,
            "is_vpn": False,
            "fraud_score": 0,
            "error": str(e)
        }

def check_anomaly(model_number, token_length, request_interval):
    """
    Check if the request is anomalous using the Anomali API
    """
    print(f"Checking anomaly for model: {model_number}, tokens: {token_length}, interval: {request_interval}")
    
    # Using seconds_since_last_request (stored in request_interval) for the API
    payload = {
        "request_interval": request_interval,  # This is seconds_since_last_request
        "token_length": token_length,
        "model_number": model_number
    }
    
    try:
        response = requests.post(ANOMALY_API_ENDPOINT, json=payload)
        data = response.json()
        
        print(f"Anomali API response: {data}")

        # Extract prediction - checking for 'result' field with a value of 'Anomalous'
        result = data.get("result", "")
        is_anomalous = result == "Anomalous"
        
        # Extract anomaly percentage, removing the % sign and converting to float if possible
        anomaly_percentage_str = data.get("anomaly_percentage", "0%")
        try:
            anomaly_percentage = float(anomaly_percentage_str.replace("%", ""))
        except ValueError:
            anomaly_percentage = 0
        
        return {
            "is_anomalous": is_anomalous,
            "result": result,
            "anomaly_percentage": anomaly_percentage_str
        }
    except Exception as e:
        print(f"Anomali API error: {str(e)}")
        # Return default values if API call fails
        return {
            "is_anomalous": False,
            "result": "Unknown",
            "error": str(e)
        }

def analyze_ip_request_pattern(ip):
    """
    Analyze request patterns for a specific IP address
    Focus on the time since the last request from the same IP
    """
    print(f"Analyzing request pattern for IP: {ip}")
    
    # Get the tracking data for this IP
    ip_data = ip_request_tracking.get(ip, [])
    current_time = datetime.now()

    # Compute request statistics
    stats = {
        "total_requests": len(ip_data),
        "last_request_time": None,
        "seconds_since_last_request": None,
        "time_between_requests": []
    }
    
    # Calculate time between all requests (for historical purposes)
    if len(ip_data) > 1:
        for i in range(1, len(ip_data)):
            time_diff = ip_data[i] - ip_data[i-1]
            stats["time_between_requests"].append(time_diff.total_seconds())
    
    # Get time since the most recent request (before the current one)
    # The current request is already added to ip_data at this point
    if len(ip_data) > 1:
        # Get the previous request time (second to last in the list)
        previous_request_time = ip_data[-2]  # The last one (-1) is the current request
        stats["last_request_time"] = previous_request_time
        
        # Calculate time difference in seconds
        time_diff = current_time - previous_request_time
        stats["seconds_since_last_request"] = time_diff.total_seconds()
    else:
        # This is the first request from this IP
        stats["seconds_since_last_request"] = 60  # Default value for first-time requests
    
    # Also include average for reference
    if stats["time_between_requests"]:
        stats["avg_time_between_requests"] = sum(
            stats["time_between_requests"]) / len(stats["time_between_requests"])
    else:
        stats["avg_time_between_requests"] = 60  # Default for first-time
        
    print(f"Request pattern stats: {stats}")

    return stats


def get_model_number(model_name):
    """
    Convert model name to its numeric representation (1, 2, 3, or 4)
    """
    # Define mapping of model names to numbers
    model_mapping = {
        "Model 1": "1",
        "Model One": "1",
        "model1": "1",
        "Model 2": "2",
        "Model Two": "2",
        "model2": "2",
        "Model 3": "3",
        "Model Three": "3",
        "model3": "3",
        "Model 4": "4",
        "Model Four": "4",
        "model4": "4"
    }

    # Return the mapped number or the original if not in mapping
    return model_mapping.get(model_name, model_name)


def get_fixed_time_allocation():
    """
    Return a fixed time allocation of 60 minutes
    """
    return 60


def generate_api_key():
    """
    Generate a new API key
    """
    print("Generating API key")
    
    new_key = "atk_" + uuid.uuid4().hex[:20]
    print(f"Generated new API key: {new_key}")
    
    return new_key


def generate_jwt_token(api_key, model, token_value, ip_address, purpose):
    """
    Generate a JWT token with API key and metadata in the payload
    """
    print(f"Generating JWT token for API key: {api_key}")
    
    # Set expiration time - Fixed: using datetime.now(UTC) instead of datetime.utcnow()
    expires_at = datetime.now(UTC) + timedelta(minutes=JWT_EXPIRATION)
    
    payload = {
        "api_key": api_key,
        "model": model,
        "token_value": token_value,
        "ip_address": ip_address,
        "purpose": purpose,
        "iat": datetime.now(UTC),  # Fixed: using datetime.now(UTC) instead of datetime.utcnow()
        "exp": expires_at
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Store in database
    add_jwt_token(token, api_key, expires_at.isoformat())
    
    print(f"Generated JWT token: {token[:20]}...")
    
    return token


def verify_jwt_token(token):
    """
    Verify a JWT token and return its payload if valid
    """
    print(f"Verifying JWT token: {token[:20]}...")
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Check if the IP in the payload has been revoked
        if "ip_address" in payload:
            revoked_ips = get_all_revoked_ips()
            if payload["ip_address"] in revoked_ips:
                print("JWT token from revoked IP")
                return False, {"error": f"Access from IP {payload['ip_address']} has been revoked"}
            
        print("JWT token is valid")
        return True, payload
    except jwt.ExpiredSignatureError:
        print("JWT token has expired")
        return False, {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        print("Invalid JWT token")
        return False, {"error": "Invalid token"}

#----------------------------
# Route Handlers
#----------------------------

@app.route('/clear-data', methods=['POST'])
def clear_database():
    """Clear all data from the database tables"""
    try:
        db = get_db()
        
        # Clear tables in reverse order of dependencies due to foreign key constraints
        db.execute('DELETE FROM request_log')
        db.execute('DELETE FROM jwt_tokens')
        db.execute('DELETE FROM api_keys')
        db.execute('DELETE FROM ip_addresses')
        
        db.commit()
        
        # Also clear the in-memory request tracking
        global ip_request_tracking
        ip_request_tracking = {}
        
        return jsonify({
            "success": True,
            "message": "Database cleared successfully"
        })
    except Exception as e:
        print(f"Error clearing database: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Error clearing database: {str(e)}"
        })

@app.route('/')
def dashboard():
    """Serve the dashboard HTML page"""
    print("Serving dashboard")
    dashboard_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>API Request Dashboard</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f7fb;
                color: #333;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            .header {
                background-color: #2c3e50;
                color: white;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .header h1 {
                margin: 0;
                font-size: 24px;
            }
            .header-buttons {
                display: flex;
                gap: 10px;
            }
            .stats {
                display: flex;
                gap: 20px;
                margin-bottom: 20px;
            }
            .stat-card {
                flex: 1;
                background-color: white;
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
                position: relative;
            }
            .stat-card:hover {
                transform: translateY(-3px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }
            .stat-card.active {
                border: 2px solid #3498db;
                background-color: #ebf5fb;
            }
            .stat-card h2 {
                margin-top: 0;
                font-size: 18px;
                color: #2c3e50;
            }
            .stat-value {
                font-size: 24px;
                font-weight: bold;
                color: #3498db;
            }
            .filter-badge {
                position: absolute;
                top: -10px;
                right: -10px;
                background-color: #3498db;
                color: white;
                border-radius: 50%;
                width: 20px;
                height: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
                font-size: 12px;
                display: none;
            }
            .active .filter-badge {
                display: flex;
            }
            .filter-info {
                margin-bottom: 15px;
                padding: 10px;
                background-color: #ebf5fb;
                border-radius: 8px;
                display: none;
                align-items: center;
                justify-content: space-between;
            }
            .filter-info.visible {
                display: flex;
            }
            .clear-filter {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
                cursor: pointer;
            }
            .request-log, .revocation-panel {
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            .request-log h2, .revocation-panel h2 {
                margin: 0;
                padding: 15px;
                background-color: #eef2f7;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-size: 18px;
                color: #2c3e50;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                text-align: left;
                padding: 12px 15px;
                border-bottom: 1px solid #eef2f7;
            }
            th {
                background-color: #f8f9fa;
                font-weight: 600;
            }
            .details-btn, .revoke-btn, .refresh-btn, .clear-btn {
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
                cursor: pointer;
            }
            .details-btn {
                background-color: #3498db;
            }
            .revoke-btn {
                background-color: #e74c3c;
            }
            .refresh-btn {
                background-color: #27ae60;
            }
            .clear-btn {
                background-color: #e67e22;
            }
            .modal {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0,0,0,0.5);
                z-index: 1000;
            }
            .modal-content {
                background-color: white;
                margin: 10% auto;
                padding: 20px;
                width: 80%;
                max-width: 800px;
                border-radius: 8px;
                max-height: 80vh;
                overflow-y: auto;
            }
            .close {
                float: right;
                font-size: 24px;
                font-weight: bold;
                cursor: pointer;
            }
            .details-container {
                margin-top: 15px;
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 5px;
            }
            .details-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 15px;
            }
            .details-section {
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                padding: 15px;
            }
            .details-section h3 {
                margin-top: 0;
                color: #2c3e50;
                font-size: 16px;
                border-bottom: 1px solid #eee;
                padding-bottom: 8px;
                margin-bottom: 12px;
            }
            .detail-row {
                display: flex;
                margin-bottom: 8px;
            }
            .detail-label {
                font-weight: 600;
                min-width: 140px;
                color: #7f8c8d;
            }
            .detail-value {
                flex-grow: 1;
            }
            .detail-value.highlight {
                font-weight: bold;
                color: #e74c3c;
            }
            .detail-value.success {
                color: #27ae60;
            }
            .detail-value.warning {
                color: #f39c12;
            }
            .detail-value.danger {
                color: #e74c3c;
            }
            .detail-value.neutral {
                color: #3498db;
            }
            pre {
                margin: 0;
                white-space: pre-wrap;
            }
            .revocation-controls {
                padding: 15px;
                display: flex;
                gap: 10px;
                align-items: center;
            }
            .ip-select {
                flex-grow: 1;
                padding: 8px;
                border-radius: 4px;
                border: 1px solid #ddd;
            }
            .revocation-result {
                padding: 15px;
                margin: 0 15px 15px;
                background-color: #f8f9fa;
                border-radius: 4px;
                display: none;
            }
            .revocation-result.success {
                background-color: #d4edda;
                color: #155724;
            }
            .revocation-result.error {
                background-color: #f8d7da;
                color: #721c24;
            }
            .revoked-ip {
                background-color: #ffebee;
            }
            .no-data {
                text-align: center;
                padding: 30px;
                color: #7f8c8d;
                font-style: italic;
            }
            .revoked-badge {
                background-color: #e74c3c;
                color: white;
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 12px;
                margin-left: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>API Request Dashboard</h1>
                <div class="header-buttons">
                    <button class="refresh-btn" onclick="fetchData()">Refresh Data</button>
                    <button class="clear-btn" onclick="clearAllData()">Clear All Data</button>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-card" id="total-requests-card" onclick="filterByTotal()">
                    <span class="filter-badge">✓</span>
                    <h2>Total Requests</h2>
                    <div class="stat-value" id="total-requests">0</div>
                </div>
                <div class="stat-card" id="unique-ips-card" onclick="filterByUniqueIPs()">
                    <span class="filter-badge">✓</span>
                    <h2>Unique IPs</h2>
                    <div class="stat-value" id="unique-ips">0</div>
                </div>
                <div class="stat-card" id="active-keys-card" onclick="filterByActiveKeys()">
                    <span class="filter-badge">✓</span>
                    <h2>Active API Keys</h2>
                    <div class="stat-value" id="active-keys">0</div>
                </div>
                <div class="stat-card" id="revoked-ips-card" onclick="filterByRevokedIPs()">
                    <span class="filter-badge">✓</span>
                    <h2>Revoked IPs</h2>
                    <div class="stat-value" id="revoked-ips">0</div>
                </div>
            </div>
            
            <div class="filter-info" id="filter-info">
                <span id="filter-text">Showing all requests</span>
                <button class="clear-filter" onclick="clearFilter()">Clear Filter</button>
            </div>
            
            <div class="revocation-panel">
                <h2>Revoke Access by IP Address</h2>
                <div class="revocation-controls">
                    <select id="ip-select" class="ip-select">
                        <option value="">Select IP Address to Revoke</option>
                    </select>
                    <button class="revoke-btn" onclick="revokeIpAccess()">Revoke Access</button>
                </div>
                <div id="revocation-result" class="revocation-result"></div>
            </div>
            
            <div class="request-log">
                <h2>Recent Requests</h2>
                <table id="request-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP Address</th>
                            <th>Model</th>
                            <th>Purpose</th>
                            <th>Fraud Score</th>
                            <th>Anomaly Score</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="request-body">
                        <tr>
                            <td colspan="8" class="no-data">No data available</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Modal for request details -->
        <div id="request-modal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal()">&times;</span>
                <h2>Request Details</h2>
                <div class="details-container">
                    <div class="details-grid" id="request-details-grid">
                        <!-- Content will be populated dynamically -->
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Initialize data
            let requestData = [];
            let filteredData = [];
            let revokedIPs = [];
            let currentFilter = null;
            
            // Fetch data from API
            function fetchData() {
                // Fetch requests data
                fetch('/api/requests')
                    .then(response => response.json())
                    .then(data => {
                        requestData = data.requests;
                        applyCurrentFilter(); // Apply any active filter
                        updateDashboard();
                    })
                    .catch(error => console.error('Error fetching data:', error));
                
                // Fetch revoked IPs
                fetch('/api/revoked-ips')
                    .then(response => response.json())
                    .then(data => {
                        revokedIPs = data.revoked_ips;
                        document.getElementById('revoked-ips').textContent = revokedIPs.length;
                        updateIPSelect();
                        
                        // Re-apply filter if we're filtering by revoked IPs
                        if (currentFilter === 'revoked') {
                            applyCurrentFilter();
                            updateDashboard();
                        }
                    })
                    .catch(error => console.error('Error fetching revoked IPs:', error));
            }
            
            // Filter functions
            function filterByTotal() {
                clearActiveCards();
                document.getElementById('total-requests-card').classList.add('active');
                currentFilter = 'total';
                
                // Show all data
                filteredData = [...requestData];
                
                // Update filter info
                updateFilterInfo('Showing all requests');
                
                // Update table
                updateTable();
            }
            
            function filterByUniqueIPs() {
                clearActiveCards();
                document.getElementById('unique-ips-card').classList.add('active');
                currentFilter = 'unique';
                
                // Get unique IPs
                const uniqueIpSet = new Set();
                
                // Filter to get only one entry per unique IP address
                filteredData = requestData.filter(req => {
                    if (!uniqueIpSet.has(req.ip_address)) {
                        uniqueIpSet.add(req.ip_address);
                        return true;
                    }
                    return false;
                });
                
                // Update filter info
                updateFilterInfo(`Showing unique IPs (${filteredData.length})`);
                
                // Update table
                updateTable();
            }
            
            function filterByActiveKeys() {
                clearActiveCards();
                document.getElementById('active-keys-card').classList.add('active');
                currentFilter = 'active';
                
                // Filter to get only active API keys
                filteredData = requestData.filter(req => 
                    req.api_key && 
                    req.api_key !== "N/A" &&
                    req.status === "Active"
                );
                
                // Update filter info
                updateFilterInfo(`Showing active API keys (${filteredData.length})`);
                
                // Update table
                updateTable();
            }
            
            function filterByRevokedIPs() {
                clearActiveCards();
                document.getElementById('revoked-ips-card').classList.add('active');
                currentFilter = 'revoked';
                
                // Filter to get only revoked IPs
                filteredData = requestData.filter(req => 
                    req.is_revoked || 
                    revokedIPs.includes(req.ip_address) ||
                    req.status === "Revoked"
                );
                
                // Update filter info
                updateFilterInfo(`Showing revoked IPs (${filteredData.length})`);
                
                // Update table
                updateTable();
            }
            
            function clearFilter() {
                clearActiveCards();
                currentFilter = null;
                
                // Reset to show all data
                filteredData = [...requestData];
                
                // Hide filter info
                document.getElementById('filter-info').classList.remove('visible');
                
                // Update table
                updateTable();
            }
            
            function clearActiveCards() {
                // Remove active class from all cards
                document.querySelectorAll('.stat-card').forEach(card => {
                    card.classList.remove('active');
                });
            }
            
            function updateFilterInfo(text) {
                const filterInfo = document.getElementById('filter-info');
                document.getElementById('filter-text').textContent = text;
                filterInfo.classList.add('visible');
            }
            
            function applyCurrentFilter() {
                // Re-apply the current filter when data is refreshed
                if (currentFilter === 'total') {
                    filteredData = [...requestData];
                } else if (currentFilter === 'unique') {
                    const uniqueIpSet = new Set();
                    filteredData = requestData.filter(req => {
                        if (!uniqueIpSet.has(req.ip_address)) {
                            uniqueIpSet.add(req.ip_address);
                            return true;
                        }
                        return false;
                    });
                } else if (currentFilter === 'active') {
                    filteredData = requestData.filter(req => 
                        req.api_key && 
                        req.api_key !== "N/A" &&
                        req.status === "Active"
                    );
                } else if (currentFilter === 'revoked') {
                    filteredData = requestData.filter(req => 
                        req.is_revoked || 
                        revokedIPs.includes(req.ip_address) ||
                        req.status === "Revoked"
                    );
                } else {
                    filteredData = [...requestData];
                }
            }
            
            // Update IP select dropdown
            function updateIPSelect() {
                const ipSelect = document.getElementById('ip-select');
                const uniqueIPs = new Set();
                
                // Collect unique IPs that aren't already revoked
                requestData.forEach(req => {
                    if (req.ip_address && !revokedIPs.includes(req.ip_address)) {
                        uniqueIPs.add(req.ip_address);
                    }
                });
                
                // Clear select and add option
                ipSelect.innerHTML = '<option value="">Select IP Address to Revoke</option>';
                
                // Add each unique IP as an option
                uniqueIPs.forEach(ip => {
                    const option = document.createElement('option');
                    option.value = ip;
                    option.textContent = ip;
                    ipSelect.appendChild(option);
                });
            }
            
            // Revoke access for an IP
            function revokeIpAccess() {
                const ipSelect = document.getElementById('ip-select');
                const selectedIP = ipSelect.value;
                
                if (!selectedIP) {
                    showRevocationResult('Please select an IP address to revoke', 'error');
                    return;
                }
                
                fetch('/revoke', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        ip_address: selectedIP
                    }),
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showRevocationResult(data.message, 'success');
                        fetchData(); // Refresh data after revocation
                    } else {
                        showRevocationResult(data.message, 'error');
                    }
                })
                .catch(error => {
                    console.error('Error revoking access:', error);
                    showRevocationResult('Failed to revoke access. Please try again.', 'error');
                });
            }
            
            // Show revocation result
            function showRevocationResult(message, type) {
                const resultElement = document.getElementById('revocation-result');
                resultElement.textContent = message;
                resultElement.className = 'revocation-result ' + type;
                resultElement.style.display = 'block';
                
                // Hide after 5 seconds
                setTimeout(() => {
                    resultElement.style.display = 'none';
                }, 5000);
            }
            
            // Update dashboard with latest data
            function updateDashboard() {
                // Update stats
                document.getElementById('total-requests').textContent = requestData.length;
                
                // Calculate unique IPs
                const uniqueIps = new Set(requestData.map(req => req.ip_address)).size;
                document.getElementById('unique-ips').textContent = uniqueIps;
                
                // Calculate active keys
                const activeKeys = requestData.filter(req => 
                    req.api_key && 
                    req.api_key !== "N/A" &&
                    req.status === "Active"
                ).length;
                document.getElementById('active-keys').textContent = activeKeys;
                
                // Update the table with filtered data
                updateTable();
            }
            
            // Update table with filtered data
            function updateTable() {
                const tableBody = document.getElementById('request-body');
                const displayData = filteredData.length > 0 ? filteredData : requestData;
                
                if (displayData.length === 0) {
                    tableBody.innerHTML = '<tr><td colspan="8" class="no-data">No data available</td></tr>';
                    return;
                }
                
                tableBody.innerHTML = '';
                displayData.forEach((req, index) => {
                    const row = document.createElement('tr');
                    
                    // Check if IP is revoked
                    const isRevoked = req.is_revoked || revokedIPs.includes(req.ip_address) || req.status === "Revoked";
                    if (isRevoked) {
                        row.classList.add('revoked-ip');
                    }
                    
                    // Format time
                    const date = new Date(req.timestamp);
                    const formattedTime = date.toLocaleString();
                    
                    // Store actual index in original data for details view
                    const originalIndex = requestData.findIndex(item => 
                        item.timestamp === req.timestamp && 
                        item.ip_address === req.ip_address && 
                        item.api_key === req.api_key
                    );
                    
                    row.innerHTML = `
                        <td>${formattedTime}</td>
                        <td>${req.ip_address}${isRevoked ? '<span class="revoked-badge">REVOKED</span>' : ''}</td>
                        <td>${req.model}</td>
                        <td>${req.purpose}</td>
                        <td>${req.fraud_score !== undefined ? req.fraud_score : 'N/A'}</td>
                        <td>${req.anomaly_score ? req.anomaly_score : 'N/A'}</td>
                        <td>${req.status}</td>
                        <td>
                            <button class="details-btn" onclick="showDetails(${originalIndex})">Details</button>
                        </td>
                    `;
                    
                    tableBody.appendChild(row);
                });
            }
            
            // Show details modal
            function showDetails(index) {
                const modal = document.getElementById('request-modal');
                const detailsGrid = document.getElementById('request-details-grid');
                const item = requestData[index];
                
                // Clear previous content
                detailsGrid.innerHTML = '';
                
                // Format timestamp
                const timestamp = new Date(item.timestamp);
                const formattedDate = timestamp.toLocaleDateString('en-US', { 
                    weekday: 'long', 
                    year: 'numeric', 
                    month: 'long', 
                    day: 'numeric' 
                });
                const formattedTime = timestamp.toLocaleTimeString('en-US', {
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit'
                });
                
                // 1. Request Status Section
                const statusSection = document.createElement('div');
                statusSection.className = 'details-section';
                statusSection.innerHTML = `
                    <h3>Request Status</h3>
                    <div class="detail-row">
                        <div class="detail-label">Status</div>
                        <div class="detail-value ${item.status === 'Active' ? 'success' : 'danger'}">${item.status}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Access Given</div>
                        <div class="detail-value ${item.status === 'Active' ? 'success' : 'danger'}">
                            ${item.status === 'Active' ? 'Yes ✓' : 'No ✗'}
                        </div>
                    </div>
                    ${item.status !== 'Active' ? `
                    <div class="detail-row">
                        <div class="detail-label">Denial Reason</div>
                        <div class="detail-value danger">${getDenialReason(item)}</div>
                    </div>` : ''}
                `;
                
                // 2. API Key Section
                const apiKeySection = document.createElement('div');
                apiKeySection.className = 'details-section';
                apiKeySection.innerHTML = `
                    <h3>API Information</h3>
                    <div class="detail-row">
                        <div class="detail-label">API Key</div>
                        <div class="detail-value">${item.api_key || 'Not Issued'}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Model</div>
                        <div class="detail-value">${item.model || 'N/A'}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Purpose</div>
                        <div class="detail-value">${item.purpose || 'N/A'}</div>
                    </div>
                `;
                
                // 3. Security Section
                const securitySection = document.createElement('div');
                securitySection.className = 'details-section';
                securitySection.innerHTML = `
                    <h3>Security Checks</h3>
                    <div class="detail-row">
                        <div class="detail-label">IP Address</div>
                        <div class="detail-value">${item.ip_address}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Fraud Score</div>
                        <div class="detail-value ${parseInt(item.fraud_score) > 50 ? 'warning' : ''}">${item.fraud_score}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Anomaly Score</div>
                        <div class="detail-value ${parseAnomalyScore(item.anomaly_score) > 50 ? 'warning' : ''}">${item.anomaly_score || 'N/A'}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Is Proxy</div>
                        <div class="detail-value">${item.is_proxy ? 'Yes ⚠️' : 'No'}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Is VPN</div>
                        <div class="detail-value">${item.is_vpn ? 'Yes ⚠️' : 'No'}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Is Revoked</div>
                        <div class="detail-value ${item.is_revoked ? 'danger' : ''}">${item.is_revoked ? 'Yes ⚠️' : 'No'}</div>
                    </div>
                `;
                
                // 4. Timestamp Section
                const timeSection = document.createElement('div');
                timeSection.className = 'details-section';
                timeSection.innerHTML = `
                    <h3>Request Timing</h3>
                    <div class="detail-row">
                        <div class="detail-label">Date</div>
                        <div class="detail-value">${formattedDate}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Time</div>
                        <div class="detail-value">${formattedTime}</div>
                    </div>
                `;
                
                // Add all sections to the grid
                detailsGrid.appendChild(statusSection);
                detailsGrid.appendChild(apiKeySection);
                detailsGrid.appendChild(securitySection);
                detailsGrid.appendChild(timeSection);
                
                // Show the modal
                modal.style.display = 'block';
            }
            
            // Helper function to parse anomaly score
            function parseAnomalyScore(scoreStr) {
                if (!scoreStr) return 0;
                return parseFloat(scoreStr.replace('%', '')) || 0;
            }
            
            // Helper function to get denial reason
            function getDenialReason(item) {
                if (item.is_revoked) return "IP Address Revoked";
                if (item.anomaly_score && parseAnomalyScore(item.anomaly_score) > 50) {
                    return `Anomalous Activity (${item.anomaly_score} confidence)`;
                }
                if (item.is_proxy) return "Proxy Detected";
                if (item.is_vpn) return "VPN Detected";
                return "Access Denied";
            }
            
            // Close modal
            function closeModal() {
                document.getElementById('request-modal').style.display = 'none';
            }
            
            // Clear all data from database and UI
            function clearAllData() {
                if (confirm('Are you sure you want to clear all data? This action cannot be undone.')) {
                    fetch('/clear-data', {
                        method: 'POST',
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert(data.message);
                            // Clear the UI data
                            requestData = [];
                            filteredData = [];
                            revokedIPs = [];
                            
                            // Reset filters
                            clearFilter();
                            
                            // Update UI elements
                            document.getElementById('total-requests').textContent = '0';
                            document.getElementById('unique-ips').textContent = '0';
                            document.getElementById('active-keys').textContent = '0';
                            document.getElementById('revoked-ips').textContent = '0';
                            
                            // Clear table
                            const tableBody = document.getElementById('request-body');
                            tableBody.innerHTML = '<tr><td colspan="8" class="no-data">No data available</td></tr>';
                            
                            // Clear IP select
                            const ipSelect = document.getElementById('ip-select');
                            ipSelect.innerHTML = '<option value="">Select IP Address to Revoke</option>';
                            
                            // Show success message
                            showRevocationResult('All data has been cleared', 'success');
                        } else {
                            alert('Error: ' + data.message);
                        }
                    })
                    .catch(error => {
                        console.error('Error clearing data:', error);
                        alert('Failed to clear data. Please try again.');
                    });
                }
            }
            
            // Initial data fetch
            fetchData();
            
            // Refresh data every 30 seconds
            setInterval(fetchData, 30000);
        </script>
    </body>
    </html>
    """
    return render_template_string(dashboard_html)


@app.route('/api/requests', methods=['GET'])
def get_requests():
    """Return the request history from the database"""
    print("Getting request history")
    return jsonify({"requests": get_all_requests()})


@app.route('/api/revoked-ips', methods=['GET'])
def get_revoked_ips():
    """Return the list of revoked IP addresses from the database"""
    return jsonify({"revoked_ips": get_all_revoked_ips()})


@app.route('/revoke', methods=['POST'])
def revoke_ip_access():
    """Revoke access for all API keys from a specific IP address"""
    data = request.json
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({
            "success": False,
            "message": "IP address is required"
        })
    
    # Check if IP is already revoked
    revoked_ips = get_all_revoked_ips()
    if ip_address in revoked_ips:
        return jsonify({
            "success": False,
            "message": f"IP {ip_address} is already revoked"
        })
    
    # Revoke IP in database
    success = revoke_ip(ip_address, "Administrative action")
    
    if success:
        # Log the revocation request
        log_request(
            request.remote_addr, 
            None, 
            "/revoke", 
            "POST", 
            True, 
            200,
            f"Revoked IP: {ip_address}"
        )
        
        return jsonify({
            "success": True,
            "message": f"Successfully revoked access for IP {ip_address}"
        })
    else:
        return jsonify({
            "success": False,
            "message": f"Failed to revoke IP {ip_address}"
        })


@app.route('/analyze', methods=['POST'])
def analyze_request():
    """Analyze a request and generate tokens"""
    print("Analyzing request")
    # Get request data
    data = request.json
    
    # Extract parameters
    ip_address = data.get('ip', request.remote_addr)
    selected_model = data.get('selectedModel', 'model3')
    token_value = data.get('tokenValue', '20000')
    purpose_of_use = data.get('purposeOfUse', 'Research')
    
    # Check if IP is already revoked
    revoked_ips = get_all_revoked_ips()
    if ip_address in revoked_ips:
        print(f"IP {ip_address} is revoked, denying access")
        
        # Check IP reputation for fraud score even if revoked
        ip_reputation = check_ip_reputation(ip_address)
        
        # Log the denied request
        log_request(
            ip_address, 
            "REVOKED", 
            "/analyze", 
            "POST", 
            False, 
            403,
            json.dumps(data),
            json.dumps({"message": "IP is revoked", "ip_reputation": ip_reputation})
        )
        
        return jsonify({
            "status": "denied",
            "api_key": "REVOKED",
            "jwt_token": "REVOKED",
            "access_given": False,
            "time_allocated": 0,
            "message": "Access from this IP has been revoked",
            "denial_reason": "IP address has been revoked",
            "revoked": True,
            "ip_reputation": ip_reputation
        })
    
    # Initialize tracking for this IP if it doesn't exist
    if ip_address not in ip_request_tracking:
        ip_request_tracking[ip_address] = []
    
    # Get current time for this request
    current_time = datetime.now()
    
    # Check IP reputation
    ip_reputation = check_ip_reputation(ip_address)
    
    # Analyze request pattern BEFORE adding the current request time
    request_pattern = analyze_ip_request_pattern(ip_address)
    
    # Now track this request time after analysis
    ip_request_tracking[ip_address].append(current_time)
    
    # Get model number for anomaly check
    model_num = int(get_model_number(selected_model))
    
    # Get token length
    token_length = int(token_value)
    
    # Get time since the last request (default to a reasonable value if not available)
    request_interval = request_pattern.get("seconds_since_last_request", 60)
    
    # Check for anomalous activity
    anomaly_check = check_anomaly(model_num, token_length, request_interval)
    
    # Check if IP is a proxy or VPN or if the request is anomalous
    is_proxy = ip_reputation.get("is_proxy", False)
    is_vpn = ip_reputation.get("is_vpn", False)
    
    # Get anomaly detection result
    anomaly_result = anomaly_check.get("result", "")
    is_anomalous = anomaly_result == "Anomalous"
    anomaly_percentage = anomaly_check.get("anomaly_percentage", "0%")
    
    print(f"Anomaly check result: {anomaly_result}, Is anomalous: {is_anomalous}")
    
    response_data = {}
    
    if is_proxy or is_vpn or is_anomalous:
        # Block access if IP is a proxy or VPN or request is anomalous
        access_given = False
        time_allocated = 0
        api_key = "access_denied"
        jwt_token = "access_denied"
        
        # Set appropriate denial reason
        if is_anomalous:
            denial_reason = f"Anomalous activity detected ({anomaly_percentage} confidence)"
        else:
            denial_reason = "Proxy or VPN detected"
        
        # Prepare response data with anomaly information
        response_data = {
            "status": "denied",
            "denial_reason": denial_reason,
            "anomaly_check": anomaly_check,
            "ip_reputation": ip_reputation
        }
        
        # Log the denied request with json response data
        log_request(
            ip_address, 
            api_key, 
            "/analyze", 
            "POST", 
            False, 
            403,
            json.dumps(data),
            json.dumps(response_data)
        )
    else:
        # Generate API key and token if IP is not a proxy or VPN
        access_given = True
        time_allocated = get_fixed_time_allocation()  # Use fixed time of 60 minutes
        api_key = generate_api_key()
        denial_reason = None
        
        # Set expiration timestamp
        expires_at = (datetime.now() + timedelta(minutes=time_allocated)).isoformat()
        
        # Add API key to database
        add_api_key(
            api_key, 
            ip_address, 
            selected_model, 
            int(token_value), 
            purpose_of_use,
            expires_at
        )
        
        # Generate JWT token
        jwt_token = generate_jwt_token(
            api_key, 
            get_model_number(selected_model), 
            token_value, 
            ip_address, 
            purpose_of_use
        )
        
        # Prepare response data with anomaly information
        response_data = {
            "status": "success",
            "api_key": api_key,
            "jwt_token": jwt_token,
            "anomaly_check": anomaly_check
        }
        
        # Log the successful request with json response data
        log_request(
            ip_address, 
            api_key, 
            "/analyze", 
            "POST", 
            True, 
            200,
            json.dumps(data),
            json.dumps(response_data)
        )
    
    # Full response data to client
    final_response = {
        "status": "success" if access_given else "denied",
        "api_key": api_key,
        "jwt_token": jwt_token,
        "ip_reputation": ip_reputation,
        "request_pattern": request_pattern,
        "anomaly_check": anomaly_check,
        "access_given": access_given,
        "time_allocated": time_allocated,
        "denial_reason": denial_reason,
        "revoked": False
    }
    
    return jsonify(final_response)


@app.route('/verify', methods=['POST'])
def verify_token():
    """Verify an API key or JWT token"""
    print("Verifying token")
    # Get request data
    data = request.json
    
    # Extract key to verify
    key_to_verify = data.get('apiKey', '')
    print(f"Attempting to verify key: {key_to_verify}")
    
    # Check if it's an API key or JWT token
    if key_to_verify.startswith('atk_'):
        # Verify API key from database
        is_valid, result = verify_api_key(key_to_verify)
        
        # Log verification request
        log_request(
            request.remote_addr,
            key_to_verify,
            "/verify",
            "POST",
            is_valid,
            200 if is_valid else 401,
            f"Verifying API key: {key_to_verify}",
            json.dumps(result)
        )
        
        if is_valid:
            return jsonify({
                "verified": True,
                "type": "api_key",
                "expires_at": result.get("expires_at"),
                "message": "API key is valid and active"
            })
        else:
            return jsonify({
                "verified": False,
                "message": result.get("message", "Invalid API key")
            })
    else:
        # This is probably a JWT token, verify it
        valid, payload = verify_jwt_token(key_to_verify)
        
        # Log verification request
        log_request(
            request.remote_addr,
            payload.get("api_key") if valid else None,
            "/verify",
            "POST",
            valid,
            200 if valid else 401,
            f"Verifying JWT token",
            json.dumps({"valid": valid})
        )
        
        if valid:
            return jsonify({
                "verified": True,
                "type": "jwt",
                "payload": payload,
                "message": "JWT token is valid"
            })
        else:
            return jsonify({
                "verified": False,
                "message": payload.get("error", "Invalid JWT token")
            })


@app.after_request
def after_request(response):
    """Add CORS headers to all responses"""
    origin = request.headers.get('Origin')
    if origin:
        response.headers.set('Access-Control-Allow-Origin', origin)
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.set('Access-Control-Allow-Credentials', 'true')
    return response


@app.route('/options', methods=['OPTIONS'])
def handle_options():
    """Handle OPTIONS requests for CORS preflight"""
    response = app.make_default_options_response()
    
    # Add CORS headers
    origin = request.headers.get('Origin')
    if origin:
        response.headers.set('Access-Control-Allow-Origin', origin)
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.set('Access-Control-Allow-Credentials', 'true')
    
    return response


if __name__ == '__main__':
    app.run(debug=True)