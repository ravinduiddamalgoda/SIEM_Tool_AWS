import random
import string

# Function to generate random passwords
def generate_passwords(count, length=8):
    passwords = []
    for _ in range(count):
        password = ''.join(random.choices(string.ascii_letters, k=length))
        passwords.append(password)
    return passwords

# Generate 1,000,000 passwords with a length of 8 characters each
passwords = generate_passwords(1000000)

# Save the passwords to a file
with open("password_list.txt", "w") as f:
    for password in passwords:
        f.write(password + "\n")

"password_list.txt"  # Return the path to the generated file
