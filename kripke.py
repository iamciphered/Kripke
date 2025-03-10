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

console = Console()

MAX_FILE_SIZE_MB = 1024  # Set the maximum allowed file size for decryption to 1GB

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
    def __init__(self, key, mode):
        self.key = key
        self.mode = mode

    def encrypt_file(self, input_file, output_file):
        input_file = os.path.abspath(input_file)
        output_file = os.path.abspath(output_file)
        
        if not os.path.isfile(input_file):
            console.print("[bold red]Error: File not found. Please check the path.[/bold red]")
            return

        with open(input_file, "rb") as f:
            data = f.read()
        
        cipher, iv_or_nonce = self._get_cipher()
        if self.mode in [AES.MODE_CBC, AES.MODE_ECB]:
            ciphertext = cipher.encrypt(pad(data, AES.block_size))
        else:
            ciphertext = cipher.encrypt(data)

        encrypted_data = {
            "mode": self.mode.name,  # Store mode as string
            "iv_or_nonce": base64.b64encode(iv_or_nonce).decode() if iv_or_nonce else "",
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
        with open(temp_file.name, "w") as f:
            json.dump(encrypted_data, f, indent=2)
        shutil.move(temp_file.name, output_file)

        console.print(f"[bold green]File encrypted successfully: {output_file}[/bold green]")

    def decrypt_file(self, input_file, output_file, key_list=None):
        input_file = os.path.abspath(input_file)
        output_file = os.path.abspath(output_file)
        
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
            mode = getattr(AES, f"MODE_{mode_str}", None)
            
            if mode is None:
                console.print(f"[bold red]Error: Unsupported AES mode '{mode_str}' found in file.[/bold red]")
                return
            
            cipher, _ = self._get_cipher(iv_or_nonce, mode)
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            
            if mode in [AES.MODE_CBC, AES.MODE_ECB]:
                decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
            else:
                decrypted_data = cipher.decrypt(ciphertext)

            with open(output_file, "wb") as f:
                f.write(decrypted_data)
            
            console.print(f"[bold green]File decrypted successfully: {output_file}[/bold green]")
        except (ValueError, KeyError):
            console.print("[bold yellow]Decryption failed, attempting brute-force...[/bold yellow]")
            self.bruteforce_decrypt(input_file, output_file, key_list)

    def _get_cipher(self, iv_or_nonce=b"", mode=None):
        mode = mode or self.mode
        if mode in [AES.MODE_EAX, AES.MODE_GCM, AES.MODE_CTR]:
            nonce = iv_or_nonce or get_random_bytes(16)
            return AES.new(self.key, mode, nonce=nonce), nonce
        elif mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
            iv = iv_or_nonce or get_random_bytes(16)
            return AES.new(self.key, mode, iv=iv), iv
        elif mode == AES.MODE_ECB:
            return AES.new(self.key, AES.MODE_ECB), None
        else:
            raise ValueError("Unsupported AES mode")

def main():
    key = get_random_bytes(32)
    while True:
        console.print("\n[bold cyan]Kripke: Universal AES File Encryption Tool[/bold cyan]")
        console.print("[1] Encrypt a file")
        console.print("[2] Decrypt a file")
        console.print("[3] Exit")
        try:
            choice = Prompt.ask("[bold yellow]Choose an option[/bold yellow]")
        except OSError:
            console.print("[bold red]Input error: running in an unsupported environment.[/bold red]")
            return

        if choice == "1":
            input_file = Prompt.ask("Enter the file path to encrypt (e.g., /home/user/document.txt)").strip()
            output_file = input_file + ".enc"
            console.print("Select AES mode: EAX, CBC, CFB, OFB, CTR, GCM, ECB")
            aes_mode = Prompt.ask("Enter AES mode").strip().upper()
            mode = getattr(AES, f"MODE_{aes_mode}", AES.MODE_EAX)
            cipher = KripkeAES(key, mode)
            cipher.encrypt_file(input_file, output_file)

        elif choice == "2":
            input_file = Prompt.ask("Enter the file path to decrypt (e.g., /home/user/document.txt.enc)").strip()
            output_file = input_file + ".dec"
            key_list = Prompt.ask("Enter a key list (comma-separated)").strip().split(',')
            key_list = [base64.b64decode(k.strip()) for k in key_list if k.strip()]
            cipher = KripkeAES(key, AES.MODE_CBC)
            cipher.decrypt_file(input_file, output_file, key_list)

        elif choice == "3":
            console.print("[bold magenta]Exiting...[/bold magenta]")
            break

if __name__ == "__main__":
    main()

