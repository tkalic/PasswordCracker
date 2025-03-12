import hashlib
import itertools
import string
import concurrent.futures

def hash_password(password, algorithm="sha256"):
    """Hashes a password using the specified algorithm."""
    if algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hashing algorithm")

def dictionary_attack(password_list_file, target_password, algorithm="sha256"):
    """Attempts to crack a password using a dictionary attack."""
    try:
        with open(password_list_file, "r", encoding="utf-8") as file:
            target_hash = hash_password(target_password, algorithm)
            
            for line in file:
                word = line.strip()
                if hash_password(word, algorithm) == target_hash:
                    return word  # Password found
        
        return None  # Password not found in dictionary
    
    except FileNotFoundError:
        print("[!] Error: Password list file not found.")
        return None

def brute_force_worker(guess, target_hash, algorithm):
    """Hashes a password guess and checks if it matches the target hash."""
    if hash_password(guess, algorithm) == target_hash:
        return guess  # Return the found password
    return None

def brute_force_attack(target_password, max_length=4, algorithm="sha256"):
    """Attempts to crack a password using a brute-force attack with multithreading."""
    target_hash = hash_password(target_password, algorithm)
    
    # Include lowercase, uppercase, digits, and special characters
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for length in range(1, max_length + 1):
            guesses = ("".join(guess) for guess in itertools.product(characters, repeat=length))
            results = executor.map(lambda g: brute_force_worker(g, target_hash, algorithm), guesses)
            
            for result in results:
                if result:
                    return result  # Password found

    return None  # No match found

if __name__ == "__main__":
    # User input for attack method
    print("Select attack method:")
    print("1 - Dictionary Attack")
    print("2 - Brute Force Attack")
    print("3 - Both")
    
    choice = input("Enter your choice (1/2/3): ")

    # Define target password and dictionary file
    password_to_crack = "aB1!"  # Test password
    password_list = "PasswordList.txt"
    
    found_password = None
    method_used = None

    # Execute selected attack method(s)
    if choice == "1":
        print("\n[+] Starting Dictionary Attack...")
        found_password = dictionary_attack(password_list, password_to_crack)
        method_used = "Dictionary Attack"
    elif choice == "2":
        print("\n[+] Starting Brute-Force Attack with Multithreading...")
        found_password = brute_force_attack(password_to_crack, max_length=4)
        method_used = "Brute-Force Attack"
    elif choice == "3":
        print("\n[+] Starting Dictionary Attack...")
        found_password = dictionary_attack(password_list, password_to_crack)
        method_used = "Dictionary Attack"
        
        if not found_password:
            print("\n[+] Dictionary Attack failed. Starting Brute-Force Attack with Multithreading...")
            found_password = brute_force_attack(password_to_crack, max_length=4)
            method_used = "Brute-Force Attack"
    
    # Display final results
    if found_password:
        print(f"\n[+] Password cracked successfully using {method_used}: {found_password}")
    else:
        print("\n[-] Password could not be cracked.")
