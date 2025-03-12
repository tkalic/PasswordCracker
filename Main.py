import hashlib

# Passwort eingeben
# Hash davon speichern
# Hash-Algorithmus wählen
# Bibliothek hinzufügen

# 1. Dictionary Angriff


# 2. Brute-Force Angriff

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

if __name__ == "__main__":
    password_to_crack = "admin"
    password_list = "PasswordList.txt"
    
    result = dictionary_attack(password_list, password_to_crack)
    print(result)
