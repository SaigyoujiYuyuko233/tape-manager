from cleo.commands.command import Command
from cleo.helpers import argument, option
from getpass import getpass

import hashlib
import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class GenkeyCommand(Command):
    name = "genkey"
    description = "Generate encrypted key for device-side auto encryption"
    options = [
        option(
            long_name="non-interactive",
            description="Default: False",
            flag=True,
        )
    ]

    def handle(self):
        isInteractive = not self.option("non-interactive")
        keyRawPass = ""

        if isInteractive:
            self.line('')
            keyRawPass = getpass('Enter device-key password: ')
        else:
            keyRawPass = input("")
        
        keyPass = hashlib.sha256(keyRawPass.encode('utf-8')).digest()

        deviceKeyBytes = get_random_bytes(32)

        cipher = AES.new(keyPass, AES.MODE_CBC)
        deviceKeyEncBytes = cipher.encrypt(deviceKeyBytes)
        
        deviceKeyEncStr = base64.b64encode(deviceKeyEncBytes).decode('utf-8')
    
        if isInteractive:
            self.line('')
            self.line('=' * 50)
            self.line('')
            self.line("Key Generated")
            self.line('')
            self.line(f"<fg=green>{deviceKeyEncStr}</>")
            self.line('')
            self.line('=' * 50)
            self.line('')
        else:
            print(deviceKeyEncStr, end='')
