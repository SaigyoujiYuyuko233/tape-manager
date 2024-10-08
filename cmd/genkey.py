from cleo.commands.command import Command
from cleo.helpers import argument, option
from getpass import getpass

import json
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

        cipher = AES.new(keyPass, AES.MODE_GCM)
        deviceKeyEncBytes, deviceKeyEncMacBytes = cipher.encrypt_and_digest(deviceKeyBytes)

        assert len(cipher.nonce) == 16
        
        deviceKeyEncStr = base64.b64encode(deviceKeyEncBytes).decode('utf-8')
        deviceKeyEncMacStr = base64.b64encode(deviceKeyEncMacBytes).decode('utf-8')
        deviceKeyEncNonceStr = base64.b64encode(cipher.nonce).decode('utf-8')
        
        jsonStr = json.dumps({
            "encKey": deviceKeyEncStr,
            "nonce": deviceKeyEncNonceStr,
            "digits": deviceKeyEncMacStr,
        }, indent=4)

        if isInteractive:
            self.line('')
            self.line('=' * 50)
            self.line('')
            self.line("Key Generated")
            self.line('')
            self.line(f"Key: <fg=green>{deviceKeyEncStr}</>")
            self.line(f"Nonce: <fg=green>{deviceKeyEncNonceStr}</>")
            self.line(f"Digits: <fg=green>{deviceKeyEncMacStr}</>")
            self.line('')
            self.line(jsonStr)
            self.line('')
            self.line('=' * 50)
            self.line('')
        else:
            print(jsonStr, end='')
