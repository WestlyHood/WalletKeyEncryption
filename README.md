# Wallet Private Key Encryption

This project provides a simple Java application for encrypting and decrypting cryptocurrency wallet private keys securely using AES encryption. The program leverages a password-based key derivation function (PBKDF2) to generate encryption keys, ensuring a high level of security for sensitive data.

## Features

- **Secure Encryption**: Utilizes AES with CBC mode and PKCS5Padding for strong encryption.
- **Password-Based Security**: Generates encryption keys from user-provided passwords.
- **Random Salt and IV**: Enhances security by introducing randomness to every encryption operation.
- **User-Friendly Interface**: Console-based application for easy interaction.

## Getting Started

Follow the instructions below to set up, compile, and run the program.

---

### Prerequisites

- **Java Development Kit (JDK)**: Version 8 or higher.
- **NetBeans IDE**: Recommended for ease of use.
- **Git**: To clone the repository.

### Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/your-username/wallet-key-encryption.git
    cd wallet-key-encryption
    ```

2. **Open in NetBeans**:
    - Launch NetBeans IDE.
    - Go to `File > Open Project`.
    - Select the cloned `wallet-key-encryption` folder and click `Open`.

3. **Build and Run**:
    - Right-click on the project in NetBeans.
    - Select `Run` or press `Shift + F6`.

---

### Usage

1. **Encrypt a Private Key**:
    - Run the program.
    - Select `1` for encryption.
    - Enter the private key to be encrypted and a password.
    - The program will display the encrypted private key.

2. **Decrypt a Private Key**:
    - Run the program.
    - Select `2` for decryption.
    - Enter the encrypted private key and the password.
    - The program will display the original private key.

---

### Code Overview

The main logic is in the `WalletKeyEncryption` class, which provides methods for:

1. **Encrypting Private Keys**:
    - Generates random salt and IV.
    - Derives a secure AES key using PBKDF2.
    - Encrypts the private key.

2. **Decrypting Private Keys**:
    - Extracts salt, IV, and encrypted data.
    - Reconstructs the AES key using the provided password and salt.
    - Decrypts the private key.

Key Functions:
- `encryptPrivateKey(String privateKey, String password)`
- `decryptPrivateKey(String encryptedPrivateKey, String password)`

---

### Example Output

#### Encryption
```text
=== Wallet Key Encryption ===
1. Encrypt Wallet Private Key
2. Decrypt Wallet Private Key
Choose an option (1 or 2): 1
Enter the private key to encrypt: my_private_key_123
Enter a password: strongpassword
Encrypted Key: M1L0OXhNcDNoaHp4OTczOA==:VjRNRGltY0RyVXE3S1c3Rg==:ZGRycmtrcnNlcnMxNTU=

#### Encryption
```text
=== Wallet Key Encryption ===
1. Encrypt Wallet Private Key
2. Decrypt Wallet Private Key
Choose an option (1 or 2): 2
Enter the encrypted private key: M1L0OXhNcDNoaHp4OTczOA==:VjRNRGltY0RyVXE3S1c3Rg==:ZGRycmtrcnNlcnMxNTU=
Enter the password: strongpassword
Decrypted Key: my_private_key_123
