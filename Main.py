import hashlib

# Passwort eingeben
# Hash davon speichern
# Hash-Algorithmus wählen
# Bibliothek hinzufügen

# 1. Dictionary Angriff


# 2. Brute-Force Angriff

def hash(password, algorithm):
    if algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()

    if algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()

    if algorithm == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()


pwd = "passwort"
hashedpwd = hashlib.sha256(pwd.encode())
print(hashedpwd)

def dictionaryAttack(File, pwd):
    with open("PasswordList.txt", "r") as file:
        for line in file:
            password = line.strip()
            hashed_password = hash(password, "sha256")
            hashedpwd = hash(pwd, "sha256")
            print(hashed_password)
            if hashedpwd == hashed_password:
                return password
            print(hashedpwd)
        return -1

print(dictionaryAttack("PasswortList.txt", "admin"))