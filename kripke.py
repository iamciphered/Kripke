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
from colorama import init, Fore, Back, Style

import art
init (autoreset= True)

print (Fore.RED + art.text2art ("KRIPKE", font="block") + Style.RESET_ALL)
console = Console()

MAX_FILE_SIZE_MB = 1024  # 1GB limit
AES_MODES = {
    "EAX": AES.MODE_EAX,
    "CBC": AES.MODE_CBC,
    "CTR": AES.MODE_CTR,
    "GCM": AES.MODE_GCM
}

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
        
        iv_or_nonce = get_random_bytes(16) if mode == "CBC" else get_random_bytes(12)
        
        if self.mode == AES.MODE_CBC:
            cipher = AES.new(self.key, self.mode, iv=iv_or_nonce)
        else:
            cipher = AES.new(self.key, self.mode, nonce=iv_or_nonce)

        ciphertext = cipher.encrypt(pad(data, AES.block_size))

        encrypted_data = {
            "mode": mode,
            "iv_or_nonce": base64.b64encode(iv_or_nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }
        
        with open(output_file, "w") as f:
            json.dump(encrypted_data, f, indent=2)

        console.print(f"[bold green]File encrypted successfully: {output_file}[/bold green]")
    
    def decrypt_file(self, input_file, output_file):
        if not os.path.isfile(input_file):
            console.print("[bold red]Error: File not found. Please check the path.[/bold red]")
            return

        if os.path.getsize(input_file) == 0:  # Check if file is empty
            console.print("[bold red]Error: The file is empty or corrupted.[/bold red]")
            return

        file_size_mb = os.path.getsize(input_file) / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_MB:
            console.print("[bold red]Error: File too large for decryption (limit is 1GB).[/bold red]")
            return

        try:
            with open(input_file, "r") as f:
                encrypted_data = json.load(f)  # This will fail if file is not valid JSON
            
            mode = encrypted_data.get("mode")
            if mode not in AES_MODES:
                console.print("[bold red]Error: Unsupported AES mode found in file.[/bold red]")
                return

            iv_or_nonce = base64.b64decode(encrypted_data["iv_or_nonce"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])

            if AES_MODES[mode] == AES.MODE_CBC:
                cipher = AES.new(self.key, AES_MODES[mode], iv=iv_or_nonce)
            else:
                cipher = AES.new(self.key, AES_MODES[mode], nonce=iv_or_nonce)

            decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

            with open(output_file, "wb") as f:
                f.write(decrypted_data)

            console.print(f"[bold green]File decrypted successfully: {output_file}[/bold green]")

        except json.JSONDecodeError:
            console.print("[bold red]Error: The file is not a valid encrypted JSON format.[/bold red]")
        except (ValueError, KeyError):
            console.print("[bold yellow]Decryption failed: Incorrect password or mode.[/bold yellow]")

def main():
    while True:
        console.print("\n[bold cyan]Kripke: AES File Encryption & Decryption Tool[/bold cyan]")
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
            cipher.decrypt_file(input_file, output_file)

        elif choice == "3":
            console.print("[bold magenta]Exiting...[/bold magenta]")
            break

if __name__ == "__main__":
    main()
