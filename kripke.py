import base64
import json
import os
import threading
from rich.console import Console
from rich.prompt import Prompt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
import tempfile

console = Console()

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
        if not os.path.exists(input_file):
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
            "mode": self.mode,
            "iv_or_nonce": base64.b64encode(iv_or_nonce).decode() if iv_or_nonce else "",
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
        with open(temp_file.name, "w") as f:
            json.dump(encrypted_data, f, indent=2)
        os.replace(temp_file.name, output_file)

        console.print(f"[bold green]File encrypted successfully: {output_file}[/bold green]")

    def decrypt_file(self, input_file, output_file):
        if not os.path.exists(input_file):
            console.print("[bold red]Error: File not found. Please check the path.[/bold red]")
            return

        with open(input_file, "r") as f:
            encrypted_data = json.load(f)
        
        try:
            iv_or_nonce = base64.b64decode(encrypted_data["iv_or_nonce"]) if encrypted_data["iv_or_nonce"] else b""
            mode = getattr(AES, f"MODE_{encrypted_data['mode']}")
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
            self.bruteforce_decrypt(input_file, output_file)

    def bruteforce_decrypt(self, input_file, output_file):
        if not os.path.exists("keys.txt"):
            console.print("[bold red]Error: keys.txt not found. Provide a key list for brute-force.[/bold red]")
            return
        
        with open("keys.txt", "r") as f:
            keys = [line.strip() for line in f.readlines()]

        with open(input_file, "r") as f:
            encrypted_data = json.load(f)
            iv_or_nonce = base64.b64decode(encrypted_data["iv_or_nonce"]) if encrypted_data["iv_or_nonce"] else b""
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])

        def attempt_decrypt(key):
            try:
                key_bytes = base64.b64decode(key)
                mode = getattr(AES, f"MODE_{encrypted_data['mode']}")
                cipher, _ = self._get_cipher(iv_or_nonce, mode)
                if mode in [AES.MODE_CBC, AES.MODE_ECB]:
                    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
                else:
                    decrypted_data = cipher.decrypt(ciphertext)
                
                with open(output_file, "wb") as f:
                    f.write(decrypted_data)
                console.print(f"[bold green]Brute-force successful! Key: {key}[/bold green]")
                return True
            except Exception:
                return False
        
        threads = []
        for key in keys:
            thread = threading.Thread(target=attempt_decrypt, args=(key,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        console.print("[bold red]Brute-force failed: No valid key found.[/bold red]")

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
            input_file = Prompt.ask("Enter the file path to encrypt")
            output_file = input_file + ".enc"
            cipher = KripkeAES(key, AES.MODE_EAX)
            cipher.encrypt_file(input_file, output_file)

        elif choice == "2":
            input_file = Prompt.ask("Enter the file path to decrypt")
            output_file = input_file + ".dec"
            cipher = KripkeAES(key, AES.MODE_CBC)
            cipher.decrypt_file(input_file, output_file)

        elif choice == "3":
            console.print("[bold magenta]Exiting...[/bold magenta]")
            break

if __name__ == "__main__":
    main()

