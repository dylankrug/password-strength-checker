#password_manager/
# password_manager.py
# password_repository.json (This file will store the encrypted passwords)

import re
import json
import os
from cryptography.fernet import Fernet
from getpass import getpass

# Encryption and Decryption Functions
def generate_key():
    """Generate a key for encryption."""
    return Fernet.generate_key()

def load_key():
    """Load the key from a file."""
    return open("secret.key", "rb").read()

def encrypt_password(password, key):
    """Encrypt the password."""
    fernet = Fernet(key)
    encrypted = fernet.encrypt(password.encode())
    return encrypted

def decrypt_password(encrypted_password, key):
    """Decrypt the password."""
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_password).decode()
    return decrypted

# Password Strength Checker
def check_password_strength(password):
    """Check the strength of the password."""
    # Password must be at least 8 characters long
    # Must contain at least one uppercase letter, one lowercase letter, one number, and one special character
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    
    if not re.search(r'[@$!%*?&]', password):
        return False, "Password must contain at least one special character (@$!%*?&)."
    
    return True, "Password is strong."

# Repository Functions
def save_password_to_repo(password, key):
    """Save encrypted password to the repository."""
    if os.path.exists("password_repository.json"):
        with open("password_repository.json", "r") as file:
            data = json.load(file)
    else:
        data = {}

    # Encrypt the password before saving
    encrypted_password = encrypt_password(password, key)

    # Add the encrypted password to the repository
    account = input("Enter the account name for this password: ")
    data[account] = encrypted_password.decode()

    with open("password_repository.json", "w") as file:
        json.dump(data, file, indent=4)

    print(f"Password for {account} saved successfully.")

def retrieve_password_from_repo(account, key):
    """Retrieve decrypted password from the repository."""
    if os.path.exists("password_repository.json"):
        with open("password_repository.json", "r") as file:
            data = json.load(file)
        if account in data:
            encrypted_password = data[account].encode()
            decrypted_password = decrypt_password(encrypted_password, key)
            print(f"The decrypted password for {account} is: {decrypted_password}")
        else:
            print(f"No password found for account: {account}")
    else:
        print("No password repository found.")

# Main Function
def main():
    if not os.path.exists("secret.key"):
        key = generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    else:
        key = load_key()

    while True:
        print("\nPassword Manager")
        print("1. Save Password")
        print("2. Retrieve Password")
        print("3. Check Password Strength")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            password = getpass("Enter password to save: ")
            is_strong, message = check_password_strength(password)
            if is_strong:
                save_password_to_repo(password, key)
            else:
                print(message)

        elif choice == "2":
            account = input("Enter the account name to retrieve the password: ")
            retrieve_password_from_repo(account, key)

        elif choice == "3":
            password = input("Enter password to check strength: ")
            is_strong, message = check_password_strength(password)
            print(message)

        elif choice == "4":
            print("Exiting the Password Manager.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

