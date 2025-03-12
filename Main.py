import hashlib
import itertools
import string

# Passwort eingeben
# Hash davon speichern
# Hash-Algorithmus wählen
# Bibliothek hinzufügen


def hash_password(password, algorithm="sha256"):
    """ Hashes a password using the specified algorithm. """
    if algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hashing algorithm")

# 1. Dictionary attack

def dictionary_attack(password_list_file, target_password, algorithm="sha256"):
    """ Tries to crack a hashed password using a dictionary attack. """
    try:
        with open(password_list_file, "r", encoding="utf-8") as file:
            target_hash = hash_password(target_password, algorithm)
            
            for line in file:
                word = line.strip()
                if hash_password(word, algorithm) == target_hash:
                    return f"[+] Password found: {word}"
        
        return "[-] Password not found in dictionary"
    
    except FileNotFoundError:
        return "[!] Error: Password list file not found."

# 2. Brute-Force  attack

def brute_force_attack(target_password, max_length=4, algorithm="sha256"):
    """ Tries to crack a hashed password using brute-force attack. """
    target_hash = hash_password(target_password, algorithm)
    characters = string.ascii_lowercase + string.digits  # Kleinbuchstaben + Zahlen
    
    for length in range(1, max_length + 1):
        for guess in itertools.product(characters, repeat=length):
            guess_word = "".join(guess)
            if hash_password(guess_word, algorithm) == target_hash:
                return f"[+] Password found: {guess_word}"
    
    return "[-] No match found (try increasing max_length)"

if __name__ == "__main__":
    password_to_crack = "abc"
    password_list = "PasswordList.txt"

    print("Starting Dictionary Attack...")
    print(dictionary_attack(password_list, password_to_crack))

    print("\nStarting Brute-Force Attack...")
    print(brute_force_attack(password_to_crack, max_length=3))  # Passwortlänge bis zu 3 Zeichen
