# Kripke AES Tool - Universal AES Encryption & Decryption

**Kripke** is an advanced AES encryption and brute-force decryption tool designed for cybersecurity analysts, penetration testers, and ethical hackers. It supports all major AES encryption modes and can attempt decryption using multiple modes until a successful result is obtained.

## Features
✅ Supports AES encryption in **EAX, CBC, CFB, OFB, CTR, GCM, and ECB** modes  
✅ File-based encryption and decryption for secure data storage  
✅ Brute-force decryption support with a custom key list  
✅ Multi-threaded brute-force for faster decryption attempts  
✅ Auto-detection mode to attempt decryption across all AES modes  
✅ Secure key handling and padded encryption for necessary modes  
✅ Built-in CLI interface for smooth interaction  

## Installation on Kali Linux
### 1. Clone the Repository
```bash
git clone https://github.com/iamciphered/Kripke.git
```
```bash
cd kripke.py
```

### 2. Set Up a Virtual Environment (Recommended)
```bash
python3 -m venv venv
```
```bash
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Tool
```bash
python kripke.py
```

## Usage
Once the tool is running, follow the on-screen prompts:

- Select `[1] Encrypt a file` to encrypt a file with AES.
- Select `[2] Decrypt a file` to attempt decryption.
- Select `[3] Exit` to quit the program.

## Contributing
Feel free to fork this repository and submit pull requests for enhancements and bug fixes.

## License
This project is licensed under the MIT License - see the `LICENSE` file for details.

