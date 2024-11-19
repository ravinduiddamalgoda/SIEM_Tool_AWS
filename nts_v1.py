import csv
import os

import boto3
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
from aws_utils import get_logs, get_instance_metrics
from threat_detection import detect_brute_force, detect_ddos

app = Flask(__name__)
CORS(app)

# Path for storing user data
USER_DATA_FILE = 'users.csv'

# Ensure the CSV file exists and has the correct headers
if not os.path.exists(USER_DATA_FILE):
    with open(USER_DATA_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['email', 'password', 'name'])  # Headers

@app.route('/register', methods=['POST'])
def register_user():
    """Register a new user and store their data in a CSV file."""
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'All fields are required'}), 400

    # Check if email already exists
    with open(USER_DATA_FILE, 'r') as file:
        reader = csv.DictReader(file)
        if any(row['email'] == email for row in reader):
            return jsonify({'message': 'Email already registered'}), 400

    # Save user data to the CSV file
    with open(USER_DATA_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([email, password, name])

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login_user():
    """Log in a user by verifying their credentials from the CSV file."""
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    # Verify user credentials
    with open(USER_DATA_FILE, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['email'] == email and row['password'] == password:
                return jsonify({'message': 'Login successful'}), 200

    return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/fetch_metrics', methods=['POST'])
def fetch_metrics():
    data = request.json
    instance_id = data.get('instance_id')

    # Use the correct references to datetime and timedelta
    start_time = datetime.utcnow() - timedelta(hours=1)
    end_time = datetime.utcnow()

    metrics = get_instance_metrics(instance_id, start_time, end_time)
    return jsonify(metrics)


@app.route('/fetch_logs', methods=['POST'])
def fetch_logs():
    data = request.json
    log_group = data.get('log_group')
    log_stream = data.get('log_stream')
    start_date = data.get('start_date')
    end_date = data.get('end_date')

    # Fetch logs using the AWS utility function
    logs = get_logs(log_group, log_stream)

    # Filter logs by date using the 'timestamp' field directly
    if start_date and end_date:
        start_date_obj = datetime.strptime(start_date, '%Y-%m-%d')
        end_date_obj = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)

        filtered_logs = []
        for log in logs:
            log_timestamp = log['timestamp'] / 1000.0
            log_time_obj = datetime.utcfromtimestamp(log_timestamp)

            if start_date_obj <= log_time_obj < end_date_obj:
                filtered_logs.append(log)
    else:
        filtered_logs = logs

    return jsonify(filtered_logs)

@app.route('/detect_brute_force', methods=['POST'])
def detect_brute_force_route():
    data = request.json
    log_group = data.get('log_group')
    log_stream = data.get('log_stream')
    start_date = data.get('start_date')
    end_date = data.get('end_date')

    logs_response = requests.post('http://localhost:3500/fetch_logs', json={'log_group': log_group, 'log_stream': log_stream, 'start_date': start_date, 'end_date': end_date})
    logs = logs_response.json()

    brute_force_ips = detect_brute_force(logs)
    if(len(brute_force_ips) == 0):
        return jsonify({'status': 'false', 'message': 'No Brute Force IPs detected'})
    return jsonify({'status': 'true', "IPs":brute_force_ips})

@app.route('/detect_ddos', methods=['POST'])
def detect_ddos_route():
    # Parse input data
    data = request.json
    log_group = data.get('log_group')
    log_stream = data.get('log_stream')
    start_date = data.get('start_date')
    end_date = data.get('end_date')

    # Initialize Boto3 client for CloudWatch Logs
    client = boto3.client('logs')

    # Convert start and end dates to timestamps
    start_time = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp() * 1000)
    end_time = int(datetime.strptime(end_date, '%Y-%m-%d').timestamp() * 1000)

    # Fetch logs from CloudWatch Logs
    logs = []
    try:
        response = client.get_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            startTime=start_time,
            endTime=end_time,
            startFromHead=True
        )
        events = response.get('events', [])
        logs.extend(events)

        # Handle pagination if there are more logs
        while 'nextToken' in response:
            response = client.get_log_events(
                logGroupName=log_group,
                logStreamName=log_stream,
                nextToken=response['nextToken'],
                startTime=start_time,
                endTime=end_time,
                startFromHead=True
            )
            events = response.get('events', [])
            logs.extend(events)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    # Detect potential DDoS IPs
    ddos_ips = detect_ddos(logs)

    return jsonify({'ddos_ips': ddos_ips})



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3500)