import base64
import json
import os
import shutil
import threading
from rich.console import Console
from rich.prompt import Prompt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
import tempfile
import hashlib

console = Console()

MAX_FILE_SIZE_MB = 1024  # Set the maximum allowed file size for decryption to 1GB
AES_MODES = {
    "EAX": AES.MODE_EAX,
    "CBC": AES.MODE_CBC,
    "CFB": AES.MODE_CFB,
    "OFB": AES.MODE_OFB,
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
    def __init__(self, password, mode=None):
        if not password.isdigit() or len(password) != 4:
            console.print("[bold red]Error: Password must be exactly 4 digits long.[/bold red]")
            sys.exit(1)
        self.key = hashlib.sha256(password.encode()).digest()
        self.mode = AES_MODES.get(mode) if mode else None
    
    def encrypt_file(self, input_file, output_file, mode):
        if not os.path.isfile(input_file):
            console.print("[bold red]Error: File not found. Please check the path.[/bold red]")
            return

        with open(input_file, "rb") as f:
            data = f.read()
        
        self.mode = AES_MODES.get(mode)
        if self.mode is None:
            console.print("[bold red]Error: Unsupported AES mode.[/bold red]")
            return
        
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
    
    def decrypt_file(self, input_file, output_file):
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
            iv_or_nonce = base64.b64decode(encrypted_data["iv_or_nonce"]) if encrypted_data["iv_or_nonce"] else b""
            mode_str = encrypted_data["mode"]
            self.mode = AES_MODES.get(mode_str)
            if self.mode is None:
                console.print("[bold red]Error: Unsupported AES mode found in file.[/bold red]")
                return
            
            cipher, _ = self._get_cipher(iv_or_nonce)
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

            with open(output_file, "wb") as f:
                f.write(decrypted_data)
            
            console.print(f"[bold green]File decrypted successfully: {output_file}[/bold green]")
        except (ValueError, KeyError):
            console.print("[bold yellow]Decryption failed: Incorrect password or mode.[/bold yellow]")
    
    def _get_cipher(self, iv_or_nonce=b""):
        iv = iv_or_nonce or get_random_bytes(16)
        return AES.new(self.key, self.mode, nonce=iv if self.mode == AES.MODE_EAX else iv), iv

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
            mode = Prompt.ask("Enter AES mode (EAX, CBC, CFB, OFB, CTR, GCM)").strip().upper()
            cipher = KripkeAES(password)
            cipher.encrypt_file(input_file, output_file, mode)

        elif choice == "2":
            input_file = Prompt.ask("Enter the file path to decrypt").strip()
            output_file = input_file + ".dec"
            password = Prompt.ask("Enter the 4-digit numeric password", password=True).strip()
            cipher = KripkeAES(password)
            cipher.decrypt_file(input_file, output_file)

        elif choice == "3":
            console.print("[bold magenta]Exiting...[/bold magenta]")
            break

if __name__ == "__main__":
    main()

