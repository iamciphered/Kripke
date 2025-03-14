# Kripke: Universal AES File Encryption Tool

## Overview
Kripke is a robust and universal AES-based file encryption tool designed for cybersecurity analysts and ethical hackers. It supports multiple AES encryption modes and ensures secure file encryption and decryption using a user-specified 4-digit numeric password. The tool is optimized for efficiency and security, making it a valuable asset for protecting sensitive data.

## Features
- **Supports AES Encryption Modes**: EAX, CBC, CTR, and GCM
- **Secure 4-Digit Password Protection**
- **Automatic Mode Detection During Decryption**
- **User-Friendly CLI with Rich Formatting**
- **Encryption and Decryption for Large Files (up to 1GB)**
- **Error Handling for Incorrect Passwords or Modes**
- **Cross-Platform Support (Linux, macOS, Windows)**

## Installation
### Prerequisites
Ensure you have Python 3.6+ installed. 

### Clone the Repository
```sh
git clone https://github.com/your-repo/kripke.git
cd kripke
```
### Create a virtual environment to install python libraries
```sh
pyhton3 -m venv venv
```
```sh
pip install -r requirements.txt
```
## Usage
### Encrypting a File
```sh
python kripke.py
```
1. Select option **[1] Encrypt a file**.
2. Enter the full path to the file you wish to encrypt. 
Example: /home/user/file.txt
3. Provide a **4-digit numeric password**.
4. Choose an AES mode: **EAX, CBC, CTR, GCM**.
5. The encrypted file will be saved with `.enc` extension.

### Decrypting a File
```sh
python kripke.py
```
1. Select option **[2] Decrypt a file**.
2. Enter the full path of the encrypted file (must be a `.enc` file).
3. Provide the correct **4-digit numeric password**.
4. If the password is correct, the file will be decrypted and saved with `.dec` extension.

## Technical Details
- **Key Generation**: The 4-digit password is hashed using SHA-256 to generate a **256-bit AES key**.
- **IV/Nonce Handling**: A **16-byte random IV/Nonce** is generated for each encryption session and stored with the encrypted data.
- **Padding**: Uses PKCS7 padding for CBC mode.
- **Error Handling**: Detects incorrect passwords or unsupported modes and displays appropriate messages.

## Security Considerations
- Ensure your **4-digit password** is kept secure. Please remember it for now, thinking of adding a bruteforce feature later in life🚀
- The IV/Nonce is stored with the encrypted data, ensuring safe decryption.

## License
Kripke is open-source and available under the **MIT License**.

## Author & Contributions
Developed by iamciphered. Contributions are welcome! Feel free to open an issue or submit a pull request.

---
This documentation provides an in-depth understanding of Kripke and its capabilities.

