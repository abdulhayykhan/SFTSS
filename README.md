# Secure File Transfer and Storage System (SFTSS)

**SFTSS** is a Python-based command-line tool designed to ensure secure file sharing and storage. It implements a **hybrid encryption model** combining symmetric and asymmetric cryptography to protect data confidentiality, integrity, and authenticity.

## 📌 Project Overview

In an era where data privacy is critical, sharing files without protection can lead to unauthorized access or modification. SFTSS solves this by creating a secure environment where users can encrypt, send, and decrypt files, ensuring that only authorized recipients can access the sensitive data.

The system employs **XOR encryption** for fast file processing and **RSA encryption** for secure key exchange, alongside **SHA-256 hashing** for integrity verification.

## ✨ Key Features

* **User Authentication:** Implements a strict registration and login system. Passwords are securely stored using **SHA-256 hashing** to prevent plain-text leaks.
* **Hybrid Encryption Architecture:**
    * **File Encryption:** Uses **XOR encryption** (Symmetric) to protect the actual file content.
    * **Key Security:** Uses **RSA encryption** (Asymmetric) to securely encrypt the unique XOR key specifically for the intended receiver.
* **Data Integrity:** Automatically generates and checks **SHA-256 hashes** to verify that files have not been corrupted or tampered with during transfer.
* **Interception Simulation:** A built-in feature that demonstrates data confidentiality by showing how encrypted files appear as unreadable ciphertext to unauthorized entities.
* **Audit Logging:** Maintains a local log file (`sftss_log.txt`) that records every system action, including registration, encryption, and decryption events, ensuring accountability.

## 🛠️ Technical Requirements

* **Language:** Python 3.8 or newer
* **Dependencies:** Uses standard Python libraries only (no external `pip` installation required):
    * `os`, `json`, `hashlib`, `random`, `time`, `getpass`

## 🚀 Usage Guide

### 1. Registration & Login
Run the program and use the main menu to register a new user. The system automatically generates a unique RSA key pair (`n`, `e`, `d`) for your account upon registration. You must log in to access encryption/decryption features.

### 2. Encrypting a File
When encrypting a file for another user:
1.  The system reads the file and generates a random XOR key.
2.  The file data is encrypted using the XOR key.
3.  The XOR key is encrypted using the **receiver's Public RSA Key**.
4.  **Output:** The system generates three files:
    * `.enc`: The encrypted file content.
    * `.keyenc`: The encrypted key required to unlock the file.
    * `.hash`: The integrity hash.

### 3. Decrypting a File
1.  The receiver logs in and selects the decryption option.
2.  The system uses the **receiver's Private RSA Key** to decrypt the XOR key.
3.  The file is decrypted and verified against the original hash.

## 📂 File Structure

| File | Description |
| :--- | :--- |
| `sftss.py` | The main application source code containing cryptographic logic and the CLI menu. |
| `test_sftss.py` | Unit tests to verify the functionality of encryption, decryption, and hashing functions. |
| `users_db.json` | A JSON database storing usernames, hashed passwords, and RSA keys. |
| `sftss_log.txt` | A text file that logs all user activities and system events. |

## 💻 How to Run

1.  Clone the repository:
    ```bash
    git clone [https://github.com/abdulhayykhan/SFTSS.git](https://github.com/abdulhayykhan/SFTSS.git)
    ```
2.  Navigate to the directory and run the main script:
    ```bash
    python sftss.py
    ```
3.  Follow the on-screen menu to register, login, and secure your files.

---
*Developed by Abdul Hayy Khan.*
