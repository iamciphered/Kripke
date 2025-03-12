import base64
import json
import os
import sys
import hashlib
from rich.console import Console
from rich.prompt import Prompt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

console = Console()

MAX_FILE_SIZE_MB = 1024  # 1GB limit
AES_MODES = {
    "EAX": AES.MODE_EAX,
    "CBC": AES.MODE_CBC,
    "CTR": AES.MODE_CTR,
    "GCM": AES.MODE_GCM
}

def print_banner():
    banner = """
[bold green]

 #00 0000 #000000   #000000  #0000000 #00 0000 #0000000 
 #00 00   #00   00    #00    #00   00 #00 00   #00
 #00#     #000000     #00    #0000000 #00#     #000000
 #00  00  #00  000    #00    #00      #00 00   #00
 #00  000 #00   000 #000000  #00      #00 0000 #0000000

[/bold green]
[bold blue]Universal AES Encryption & Brute-Force Decryption Tool[/bold blue]
    """
    console.print(banner)

print_banner()

class KripkeAES:
    def __init__(self, password, mode):
        if not password.isdigit() or len(password) != 4:
            console.print("[bold red]Error: Password must be exactly 4 digits long.[/bold red]")
            sys.exit(1)
        self.key = hashlib.sha256(password.encode()).digest()
        self.mode = AES_MODES.get(mode)
        if self.mode is None:
            console.print("[bold red]Error: Unsupported AES mode.[/bold red]")
            sys.exit(1)
    
    def encrypt_file(self, input_file, output_file, mode):
        if not os.path.isfile(input_file):
            console.print("[bold red]Error: File not found. Please check the path.[/bold red]")
            return

        with open(input_file, "rb") as f:
            data = f.read()
        
        cipher, iv_or_nonce = self._get_cipher()
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        
        encrypted_data = {
            "mode": mode,
            "iv_or_nonce": base64.b64encode(iv_or_nonce).decode() if iv_or_nonce else "",
            "ciphertext": base64.b64encode(ciphertext).decode()
        }
        
        with open(output_file, "w") as f:
            json.dump(encrypted_data, f, indent=2)

        console.print(f"[bold green]File encrypted successfully: {output_file}[/bold green]")
    
    def decrypt_file(self, input_file, output_file, password):
        if not os.path.isfile(input_file):
            console.print("[bold red]Error: File not found. Please check the path.[/bold red]")
            return

        file_size_mb = os.path.getsize(input_file) / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_MB:
            console.print("[bold red]Error: File too large for decryption (limit is 1GB).[/bold red]")
            return

        with open(input_file, "r") as f:
            encrypted_data = json.load(f)
        
        try:
            mode = encrypted_data["mode"]
            if mode not in AES_MODES:
                console.print("[bold red]Error: Unsupported AES mode found in file.[/bold red]")
                return
            
            iv_or_nonce = base64.b64decode(encrypted_data["iv_or_nonce"]) if encrypted_data["iv_or_nonce"] else b""
            cipher = KripkeAES(password, mode)
            cipher_obj, _ = cipher._get_cipher(iv_or_nonce)
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            decrypted_data = unpad(cipher_obj.decrypt(ciphertext), AES.block_size)

            with open(output_file, "wb") as f:
                f.write(decrypted_data)
            
            console.print(f"[bold green]File decrypted successfully: {output_file}[/bold green]")
        except (ValueError, KeyError):
            console.print("[bold yellow]Decryption failed: Incorrect password or mode.[/bold yellow]")
    
    def _get_cipher(self, iv_or_nonce=b""):
        iv = iv_or_nonce or get_random_bytes(16)
        if self.mode in [AES.MODE_EAX, AES.MODE_GCM, AES.MODE_CTR, AES.MODE_CBC]:
            return AES.new(self.key, self.mode, nonce=iv if self.mode in [AES.MODE_EAX, AES.MODE_GCM, AES.MODE_CTR] else iv), iv

def main():
    while True:
        console.print("\n[bold cyan]Kripke: Universal AES File Encryption Tool[/bold cyan]")
        console.print("[1] Encrypt a file")
        console.print("[2] Decrypt a file")
        console.print("[3] Exit")
        
        choice = Prompt.ask("[bold yellow]Choose an option[/bold yellow]")

        if choice == "1":
            input_file = Prompt.ask("Enter the file path to encrypt").strip()
            output_file = input_file + ".enc"
            password = Prompt.ask("Enter a 4-digit numeric password", password=True).strip()
            mode = Prompt.ask("Enter AES mode (EAX, CBC, CTR, GCM)").strip().upper()
            if mode not in AES_MODES:
                console.print("[bold red]Error: Unsupported AES mode.[/bold red]")
                continue
            cipher = KripkeAES(password, mode)
            cipher.encrypt_file(input_file, output_file, mode)

        elif choice == "2":
            input_file = Prompt.ask("Enter the file path to decrypt").strip()
            output_file = input_file + ".dec"
            password = Prompt.ask("Enter the 4-digit numeric password", password=True).strip()
            with open(input_file, "r") as f:
                encrypted_data = json.load(f)
            mode = encrypted_data.get("mode", "CBC")  # Use stored mode
            cipher = KripkeAES(password, mode)
            cipher.decrypt_file(input_file, output_file, password)

        elif choice == "3":
            console.print("[bold magenta]Exiting...[/bold magenta]")
            break

if __name__ == "__main__":
    main()

