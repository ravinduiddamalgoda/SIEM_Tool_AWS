import re
from collections import defaultdict


def detect_brute_force(logs):
    failed_attempts = defaultdict(int)
    brute_force_ips = []

    for log in logs:
        # Extract the message and look for signs of brute force
        message = log.get('message', '')

        # Check for patterns indicating failed login attempts
        if 'Connection closed by authenticating user' in message or 'Invalid user' in message:
            # Extract the IP address from the message
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', message)
            if ip:
                failed_attempts[ip[0]] += 1

        # Check for throttling messages
        if 'beginning MaxStartups throttling' in message:
            # If there's an IP in this message, consider it brute force
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', message)
            if ip:
                failed_attempts[ip[0]] += 5  # Assign a higher weight for throttling

    # Identify IPs with more than a threshold of failed attempts
    for ip, count in failed_attempts.items():
        if count > 25:  # Threshold for brute force detection
            brute_force_ips.append(ip)

    return brute_force_ips

# DDoS detection logic with date filtering

def detect_ddos(logs):
    # print(logs)
    request_counts = defaultdict(int)
    ddos_ips = []

    for log in logs:
        message = log['message']
        # Extract both source IP and attacked IP
        ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', message)
        # print(ips)
        if len(ips) >= 2:  # Ensure both source and attacked IPs are available
            attacked_ip = ips[0]  # Attacked IP is the second one in the message
            request_counts[attacked_ip] += 1

    # Identify IPs with excessive requests (potential DDoS)
    for ip, count in request_counts.items():
        if count > 1000:  # Threshold for DDoS detection
            ddos_ips.append({'ip': ip, 'request_count': count})

    return ddos_ips