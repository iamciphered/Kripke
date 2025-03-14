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
### Clone the Repository
```sh
git clone https://github.com/iamciphered/kripke.git
```

```sh
cd Kripke
```

```sh
pip install pycryptodome rich
```

## Usage
### Encrypting a File
```sh
python kripke.py
```
1. Select option **[1] Encrypt a file**.
2. Enter the full path to the file you wish to encrypt.
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

## Best AES Modes for Various File Types
| **File Type**      | **Recommended AES Mode** | **Reason** |
|--------------------|------------------------|------------|
| **Text Files (`.txt`, `.log`, `.csv`)** | **CBC** | Provides strong security and works well for structured data. |
| **Documents (`.docx`, `.pdf`, `.xlsx`)** | **GCM** | Authenticated encryption prevents tampering. |
| **Images (`.jpg`, `.png`, `.gif`)** | **CTR** | Preserves data format while ensuring security. |
| **Audio/Video (`.mp3`, `.mp4`, `.avi`)** | **CTR** | Prevents distortion and maintains performance. |
| **Compressed Files (`.zip`, `.rar`, `.tar.gz`)** | **GCM** | Ensures integrity and prevents corruption. |
| **Executable Files (`.exe`, `.bin`, `.sh`)** | **EAX** | Provides authentication along with encryption. |
| **Database Files (`.sql`, `.db`, `.mdb`)** | **CBC** | Ensures structured data encryption without compromising format. |

## Technical Details
- **Key Generation**: The 4-digit password is hashed using SHA-256 to generate a **256-bit AES key**.
- **IV/Nonce Handling**: A **16-byte random IV/Nonce** is generated for each encryption session and stored with the encrypted data.
- **Padding**: Uses PKCS7 padding for CBC mode.
- **Error Handling**: Detects incorrect passwords or unsupported modes and displays appropriate messages.

## Security Considerations
- Ensure your **4-digit password** is kept secure.
- Since AES is strong, brute-forcing is impractical unless the password is weak.
- The IV/Nonce is stored with the encrypted data, ensuring safe decryption.

## License
Kripke is open-source and available under the **MIT License**.

## Author & Contributions
Developed by [Your Name]. Contributions are welcome! Feel free to open an issue or submit a pull request.

---
This documentation provides an in-depth understanding of Kripke and its capabilities. Let me know if you'd like any modifications! 🚀

