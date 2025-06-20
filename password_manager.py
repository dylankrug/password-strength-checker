# password_manager.py

import re
import json
import os
import bcrypt
from getpass import getpass

# Password Hashing Functions
def hash_password(password):
    """Hash a password for storing."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def check_password_hash(password, hashed):
    """Check hashed password."""
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Password Strength Checker
def check_password_strength(password):
    """Check the strength of the password."""
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
def save_password_to_repo(password):
    """Hash password and save to the repository."""
    if os.path.exists("password_repository.json"):
        with open("password_repository.json", "r") as file:
            data = json.load(file)
    else:
        data = {}

    hashed_password = hash_password(password)
    account = input("Enter the account name for this password: ")
    data[account] = hashed_password

    with open("password_repository.json", "w") as file:
        json.dump(data, file, indent=4)

    print(f"Password for {account} saved successfully (hashed).")

def retrieve_password_from_repo(account):
    """Verify password attempt against stored hash."""
    if os.path.exists("password_repository.json"):
        with open("password_repository.json", "r") as file:
            data = json.load(file)
        if account in data:
            hashed_password = data[account]
            password_attempt = getpass("Enter the password to verify: ")
            if check_password_hash(password_attempt, hashed_password):
                print("✅ Password match.")
            else:
                print("❌ Incorrect password.")
        else:
            print(f"No password found for account: {account}")
    else:
        print("No password repository found.")

# Main Function
def main():
    while True:
        print("\nPassword Manager")
        print("1. Save Password")
        print("2. Verify Password")
        print("3. Check Password Strength")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            password = getpass("Enter password to save: ")
            is_strong, message = check_password_strength(password)
            if is_strong:
                save_password_to_repo(password)
            else:
                print(message)

        elif choice == "2":
            account = input("Enter the account name to verify the password: ")
            retrieve_password_from_repo(account)

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
