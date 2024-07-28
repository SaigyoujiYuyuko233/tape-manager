from cleo.commands.command import Command
from cleo.helpers import argument, option
from getpass import getpass
from pymtst.tape_drive import TapeDrive
from lib import TapeInfo
from tqdm import tqdm

import humanfriendly
import subprocess
import tarfile
import pathlib
import hashlib
import base64
import json
import time
import os

from Crypto.Cipher import AES


class MountCommand(Command):
    name = "mount"
    description = "Mount LTFS"
    arguments = [
        argument(name="tapeDevice", description="Device config"),
        argument(name="encCfg", description="Encryption config"),
        argument(name="mountPath", description="Mount to this path"),
    ]
    options = [
        option(
            long_name="config",
            short_name="c",
            description="Set config file",
            flag=False,
            default="config.json",
        ),
        option(long_name="rw", description="Enable LTFS read-write instead of read-only", flag=True),
        option(long_name="force", short_name="f", description="Force run", flag=True),
    ]

    def handle(self):
        config = None

        try:
            file_config = open(self.option("config"))
            config = json.load(file_config)
            file_config.close()
        except Exception as e:
            self.line_error(f"Load config: {e}", style="error")
            return

        self.line(f"Config [{self.option('config')}] loaded!", style="option=bold")
        self.line("")

        # Check tape device
        taskTapeDeviceCfg = None
        if not self.argument("tapeDevice") in config["tapeDevice"]:
            self.line_error(
                f"Tape device [{self.argument('tapeDevice')}] not found.",
                style="error",
            )
            return
        taskTapeDeviceCfg = config["tapeDevice"][self.argument("tapeDevice")]

        if not pathlib.Path(taskTapeDeviceCfg["path"]).resolve().is_char_device():
            if not self.option("force"):
                self.line_error(
                    f'{taskTapeDeviceCfg["path"]} is not a char device. Pass --force or -f to continue',
                    style="error",
                )
                return
            self.line_error(
                f'Warning: {taskTapeDeviceCfg["path"]} is not a char device',
                style="fg=yellow",
            )

        if not "nst" in taskTapeDeviceCfg["path"]:
            self.line_error(
                f'Warning: {taskTapeDeviceCfg["path"]} does not contain nst. mt-gnu may fail',
                style="fg=yellow",
            )

        tapeDevice = TapeDrive(taskTapeDeviceCfg["path"])

        self.line(
            f"Tape device {taskTapeDeviceCfg['path']} is valid.",
        )

        # decrypt device key
        taskEncCfg = None
        if not self.argument("encCfg") in config["encryption"]:
            self.line_error(
                f"Encryption config [{self.argument('encCfg')}] not found.",
                style="error",
            )
            return
        taskEncCfg = config["encryption"][self.argument("encCfg")]

        encPassword = ""
        if not "passwd" in taskEncCfg:
            encPassword = getpass("Enter device-key password: ")
        else:
            encPassword = taskEncCfg["passwd"]

        encKey = hashlib.sha256(encPassword.encode("utf-8")).digest()

        cipher = AES.new(encKey, mode=AES.MODE_GCM, nonce=base64.b64decode(taskEncCfg["nonce"]))
        deviceKeyBytes = None

        try:
            deviceKeyBytes = cipher.decrypt_and_verify(
                base64.b64decode(taskEncCfg["encKey"]),
                base64.b64decode(taskEncCfg["digits"]),
            )
        except ValueError:
            self.line_error(
                f"Failed to decrypt: wrong passphrase or damaged encKey/nonce/digits",
                style="error",
            )
            return
        except Exception as e:
            self.line_error(
                f"Failed to decrypt: {e}",
                style="error",
            )
            return

        del cipher
        del encKey
        del encPassword

        self.line(f"Decrypt device encryption key successfully.")

        self.line(f"Waiting for tape to be inserted...")
        while True:
            try:
                tapeDevice.status()
            except subprocess.TimeoutExpired:
                self.line(f"Waiting for tape to be inserted...")
                continue

            currentBarcode = TapeInfo(taskTapeDeviceCfg["path"]).barcode()
            self.line(f"Tape [{currentBarcode}] inserted.")

            break

        #
        # enable device encryption
        #
        stenc_args = [
            "/bin/stenc",
            "-f",
            f"{taskTapeDeviceCfg['path']}",
            "-e",
            "on",
            "--ckod",
            "-a",
            "1",
        ]
        proc = subprocess.run(
            stenc_args,
            input=f"{deviceKeyBytes.hex()}\n{deviceKeyBytes.hex()}\ny",
            text=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        if proc.returncode != 0:
            self.line_error(
                f"Failed to enable device encryption",
                style="error;option=bold",
            )
            self.line("")
            self.line_error(proc.stderr.decode("utf-8"), style="error")
            return
        else:
            self.line(f"Device encryption is ENABLED.", style="fg=green")

        del deviceKeyBytes

        #
        # mount ltfs
        #
        ltfs_mount_path = self.argument("mountPath")
        os.makedirs(ltfs_mount_path, exist_ok=True)

        mount_ltfs_args = [
            "ltfs",
            "-o",
            f"devname={taskTapeDeviceCfg['path']}",
            "-o",
            "eject",
            "-o",
            "sync_type=close",
        ]

        if not self.option("rw"):
            mount_ltfs_args = mount_ltfs_args + ["-o", "ro"]

        mount_ltfs_args.append(ltfs_mount_path)
        proc = subprocess.run(
            mount_ltfs_args,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        if proc.returncode != 0:
            self.line_error(
                f"Failed to mount LTFS. Wrong encCfg?",
                style="error;option=bold",
            )
            self.line("")
            self.line_error(proc.stderr.decode("utf-8"), style="error")
            return
        else:
            self.line(f"LTFS mounted to {ltfs_mount_path}", style="fg=green")
