# =================================================================
# 🔐 Secure File Transfer and Storage System (Basic Implementation)
# =================================================================
# Author: Abdul Hayy Khan
# Course: Information Security
# Labs Integrated: Lab 1 - Lab 6
# -------------------------------------------------------------
# Demonstrates: XOR Encryption, AAA Framework, Attack Simulation,
# Hashing, and RSA Encryption
# =================================================================

import os, json, hashlib, random, time, getpass

# =============================
# Section 1: Utility Functions
# =============================
USERS_DB = "users_db.json"
LOG_FILE = "sftss_log.txt"

def load_users():
    if not os.path.exists(USERS_DB):
        return {}
    with open(USERS_DB, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_DB, "w") as f:
        json.dump(users, f, indent=2)

def log_action(msg):
    ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a") as f:
        f.write(f"{ts} {msg}\n")

# =============================================================
# Section 2: Hashing (Lab 5)
# =============================================================
def sha256_hex(data_bytes):
    h = hashlib.sha256(); h.update(data_bytes)
    return h.hexdigest()

def hash_file(path):
    with open(path, "rb") as f: data = f.read()
    return sha256_hex(data)

# =============================================================
# Section 3: RSA (Lab 6)
# =============================================================
def is_prime(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False

    # Miller-Rabin primality test
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        # Ensure it's odd and has the right bit length
        p |= (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

def egcd(a, b):
    if a == 0: return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1: return None  # Should not happen if a and m are coprime
    return x % m

def generate_rsa_keypair():
    # Retry loop to ensure we get a valid keypair
    while True:
        p = generate_large_prime()
        q = generate_large_prime()
        while q == p:
            q = generate_large_prime()
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = 65537
        # Ensure e is coprime to phi
        if egcd(e, phi)[0] != 1:
            e = 3
            if egcd(e, phi)[0] != 1:
                continue # Try different primes
        
        d = modinv(e, phi)
        if d is not None:
            return (n, e, d)

def rsa_encrypt_int(m_int, e, n):
    return pow(m_int, e, n)

def rsa_decrypt_int(c_int, d, n):
    return pow(c_int, d, n)

def int_from_bytes(b):
    return int.from_bytes(b, byteorder="big")

def int_to_bytes(i, length=None):
    if length:
        return i.to_bytes(length, byteorder="big")
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder="big")

# =============================================================
# Section 4: XOR Encryption (Lab 1)
# =============================================================
def xor_bytes(data_bytes, key_bytes):
    res = bytearray(len(data_bytes))
    for i in range(len(data_bytes)):
        res[i] = data_bytes[i] ^ key_bytes[i % len(key_bytes)]
    return bytes(res)

def generate_random_xor_key(length=16):
    return bytes([random.randint(0, 255) for _ in range(length)])

# =============================================================
# Section 5: AAA Authentication (Lab 2)
# =============================================================
def register_user():
    users = load_users()
    username = input("Choose username: ").strip()
    if username in users:
        print("Username already exists."); return
    pwd = getpass.getpass("Choose password: ")
    confirm = getpass.getpass("Confirm password: ")
    if pwd != confirm:
        print("Passwords do not match."); return
    h = sha256_hex(pwd.encode())
    n, e, d = generate_rsa_keypair()
    users[username] = {"password_hash": h, "rsa_n": n, "rsa_e": e, "rsa_d": d}
    save_users(users)
    log_action(f"User registered: {username}")
    print("Registration successful with RSA keys!")

def login_user():
    users = load_users()
    username = input("Username: ").strip()
    if username not in users:
        print("User not found."); return None
    pwd = getpass.getpass("Password: ")
    if sha256_hex(pwd.encode()) == users[username]["password_hash"]:
        print("Login successful!"); log_action(f"Login: {username}"); return username
    print("Login failed!"); return None

# =============================================================
# Section 6: Encryption & Decryption
# =============================================================
def encrypt_file_for_receiver(sender):
    users = load_users()
    print("Available users:", list(users.keys()))
    receiver = input("Receiver username: ").strip()
    if receiver not in users:
        print("Receiver not found.")
        return

    path = input("Enter file path: ").strip()
    if not os.path.exists(path):
        print("File not found.")
        return

    # Read file data
    with open(path, "rb") as f:
        data = f.read()

    xor_key = generate_random_xor_key()
    ciphertext = xor_bytes(data, xor_key)

    # Encrypt the XOR key with RSA
    n, e = users[receiver]["rsa_n"], users[receiver]["rsa_e"]
    enc_key = int_to_bytes(rsa_encrypt_int(int_from_bytes(xor_key), e, n))

    # Save encrypted files
    with open(path + ".enc", "wb") as f:
        f.write(ciphertext)

    with open(path + ".keyenc", "wb") as f:
        f.write(enc_key)

    with open(path + ".hash", "w") as f:
        f.write(sha256_hex(data))

    print(f"✅ Encryption complete!\nSaved as: {path}.enc, {path}.keyenc, {path}.hash")
    log_action(f"{sender} encrypted {path} for {receiver}")


def decrypt_file_for_user(user):
    users = load_users()
    path = input("Enter .enc file path: ").strip()
    if not os.path.exists(path): print("File not found."); return
    keyfile = path.replace(".enc", ".keyenc")
    if not os.path.exists(keyfile): print("Key file missing."); return
    with open(path, "rb") as f: ct = f.read()
    with open(keyfile, "rb") as f: enc_key = f.read()
    n, d = users[user]["rsa_n"], users[user]["rsa_d"]
    # Force 16 bytes length for XOR key to handle leading zeros
    xor_key = int_to_bytes(rsa_decrypt_int(int_from_bytes(enc_key), d, n), length=16)
    pt = xor_bytes(ct, xor_key)
    decfile = path.replace(".enc", ".dec")
    with open(decfile, "wb") as f: f.write(pt)
    print("Decryption done ->", decfile)
    hashf = path.replace(".enc", ".hash")
    if os.path.exists(hashf):
        orig = open(hashf).read().strip()
        if sha256_hex(pt) == orig: print("Integrity OK ✅")
        else: print("Integrity Failed ❌")
    log_action(f"{user} decrypted {path}")

# =============================================================
# Section 7: Attack Simulation (Lab 3)
# =============================================================
def simulate_intercept():
    path = input("Enter .enc file to inspect: ").strip()
    if not os.path.exists(path): print("File not found."); return
    data = open(path, "rb").read(64)
    print("\n=== Simulated Interception ===")
    print("First 64 bytes (hex):", data.hex())
    print("Attacker sees encrypted data only!")

# ====================
# Section 8: CLI Menu
# ====================
def main_menu():
    user = None
    while True:
        print("\n=== SFTSS Main Menu ===")
        print("1) Register\n2) Login\n3) Encrypt File\n4) Decrypt File\n5) Simulate Interception\n6) Exit")
        ch = input("Choice: ").strip()
        if ch == "1": register_user()
        elif ch == "2": user = login_user()
        elif ch == "3":
            if user: encrypt_file_for_receiver(user)
            else: print("Login first.")
        elif ch == "4":
            if user: decrypt_file_for_user(user)
            else: print("Login first.")
        elif ch == "5": simulate_intercept()
        elif ch == "6": print("Exiting..."); break
        else: print("Invalid!")

if __name__ == "__main__":
    print("Welcome to Secure File Transfer and Storage System!")
    main_menu()
