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


TAB = "    "


class RunCommand(Command):
    name = "run"
    description = "Run a backup task"
    arguments = [argument(name="task", description="Name of the task")]
    options = [
        option(
            long_name="config",
            short_name="c",
            description="Set config file",
            flag=False,
            default="config.json",
        ),
        option(
            long_name="split",
            short_name="s",
            description="Set max size of one tar file. File size will be around that size. Set a very large size to disable. (eg 100TB)",
            flag=False,
            default="12 GiB",
        ),
        option(
            long_name="tmp-path",
            description="Set temperate path. Use for LTFS mount",
            flag=False,
            default="/tmp",
        ),
        option(long_name="force", short_name="f", description="Force run", flag=True),
        option(long_name="skip-format", description="Skip formatting LTFS", flag=True),
        option(long_name="skip-archive", description="Skip selected archives", multiple=True, flag=False),
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

        self.line(f"Config [{self.option('config')}] loaded!")

        #
        # Get task config
        #
        taskCfg = None
        taskName = self.argument("task")
        if not taskName in config["tasks"]:
            self.line_error(f"Task [{taskName}] not found. Available tasks are:", style="error")
            for k, _ in config["tasks"].items():
                self.line_error(f"- {k}", style="error")
            return

        taskCfg = config["tasks"][taskName]

        self.line("")
        self.line(f'{"=" * 25} <info>Task: {taskName}</> {"=" * 25}')
        self.line("")
        self.line("> Preflight check list", style="options=bold")

        #
        # Check tape device
        #
        taskTapeDeviceCfg = None
        if not taskCfg["tapeDevice"] in config["tapeDevice"]:
            self.line_error(
                f"{TAB}- Tape device [{taskCfg['tapeDevice']}] used by task [{taskName}] not found.",
                style="error",
            )
            return
        taskTapeDeviceCfg = config["tapeDevice"][taskCfg["tapeDevice"]]

        if not pathlib.Path(taskTapeDeviceCfg["path"]).resolve().is_char_device():
            if not self.option("force"):
                self.line_error(
                    f'{TAB}- {taskTapeDeviceCfg["path"]} is not a char device. Pass --force or -f to continue',
                    style="error",
                )
                return
            self.line_error(
                f'{TAB}- Warning: {taskTapeDeviceCfg["path"]} is not a char device',
                style="fg=yellow",
            )

        if not "nst" in taskTapeDeviceCfg["path"]:
            self.line_error(
                f'{TAB}- Warning: {taskTapeDeviceCfg["path"]} does not contain nst. mt-gnu may fail',
                style="fg=yellow",
            )

        tapeDevice = TapeDrive(taskTapeDeviceCfg["path"])

        self.line(
            f"{TAB}- Tape device {taskTapeDeviceCfg['path']} is valid.",
            style="fg=green",
        )

        #
        # decrypt device key
        #
        taskEncCfg = None
        if not taskCfg["encryption"] in config["encryption"]:
            self.line_error(
                f"{TAB}- Encryption config [{taskCfg['encryption']}] used by task [{taskName}] not found.",
                style="error",
            )
            return
        taskEncCfg = config["encryption"][taskCfg["encryption"]]

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
                f"{TAB}- Failed to decrypt: wrong passphrase or damaged encKey/nonce/digits",
                style="error",
            )
            return
        except Exception as e:
            self.line_error(
                f"{TAB}- Failed to decrypt: {e}",
                style="error",
            )
            return

        del cipher
        del encKey
        del encPassword

        self.line(f"{TAB}- Decrypt device encryption key successfully.", style="fg=green")
        self.line(f"")

        for archive in taskCfg["archives"]:
            if archive["name"] in self.option("skip-archive"):
                self.line(f"> Starting archive job {archive['name']}", style="info;option=bold")
                continue

            self.line(f"> Starting archive job {archive['name']}", style="option=bold")

            #
            # barcode checking
            #
            currentBarcode = None
            while True:
                try:
                    tapeDevice.status()
                except subprocess.TimeoutExpired:
                    self.line(f"{TAB}- Waiting for tape to be inserted...", style="info")
                    continue
                except subprocess.CalledProcessError:
                    self.line(
                        f"{TAB}- mt-gun return non-zero returncode. Tape device may be busy. Did you umount LTFS?",
                        style="fg=yellow;option=bold",
                    )
                    time.sleep(60)
                    continue

                currentBarcode = TapeInfo(taskTapeDeviceCfg["path"]).barcode()

                if currentBarcode != archive["tapeBarcode"]:
                    self.line(
                        f"{TAB}- Wrong tape inserted, Ejecting... Current={currentBarcode} Require={archive['tapeBarcode']}",
                        style="fg=yellow;option=bold",
                    )
                    try:
                        tapeDevice.offline()
                    except Exception as e:
                        pass
                    time.sleep(10)
                    continue

                break

            self.line(f"{TAB}- Tape [{currentBarcode}] inserted.", style="fg=green")

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
                    f"{TAB}- Failed to enable device encryption",
                    style="error;option=bold",
                )
                self.line("")
                self.line_error(proc.stderr.decode("utf-8"), style="error")
                return
            else:
                self.line(f"{TAB}- Device encryption is ENABLED.", style="fg=green")

            #
            # format LTFS
            #
            if not self.option("skip-format"):
                mkltfs_args = [
                    "mkltfs",
                    "-f",
                    "-d",
                    taskTapeDeviceCfg["path"],
                    "-s",
                    currentBarcode,
                    "-n",
                    archive["name"],
                ]
                proc = subprocess.run(
                    mkltfs_args,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                )
                if proc.returncode != 0:
                    self.line_error(f"{TAB}> Failed to format LTFS", style="error;option=bold")
                    self.line("")
                    self.line(proc.stderr)
                    return
                else:
                    self.line(
                        f"{TAB}- LTFS Format [{currentBarcode}] successfully.",
                        style="fg=green",
                    )

            if self.option("skip-format"):
                self.line(f"{TAB}- Skip LTFS format", style="info")

            #
            # mount ltfs
            #
            ltfs_mount_path = os.path.join(self.option("tmp-path"), currentBarcode)
            os.makedirs(ltfs_mount_path, exist_ok=True)

            mount_ltfs_args = [
                "ltfs",
                "-o",
                f"devname={taskTapeDeviceCfg['path']}",
                "-o",
                "eject",
                "-o",
                "sync_type=close",
                ltfs_mount_path,
            ]
            proc = subprocess.run(
                mount_ltfs_args,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            if proc.returncode != 0:
                self.line_error(
                    f"{TAB}> Failed to mount LTFS",
                    style="error;option=bold",
                )
                self.line("")
                self.line_error(proc.stderr.decode("utf-8"), style="error")
                return
            else:
                self.line(f"{TAB}- LTFS mounted.", style="fg=green")

            self.line("")

            #
            # start archiving
            #
            for i, content in enumerate(archive["content"]):
                src_content_path = None
                dst_archive_filename = None

                if type(content) is str:
                    src_content_path = content
                    dst_archive_filename = f"{os.path.basename(src_content_path)}.tar"
                elif type(content) is dict:
                    kv = list(content.items())[0]
                    src_content_path = kv[0]
                    dst_archive_filename = kv[1]
                else:
                    self.line(
                        f"{TAB}> Content [idx={i}] config error: not str or dict",
                        style="error;option=bold",
                    )
                    continue

                self.line(f"{TAB}> Start processing {src_content_path}", style="option=bold")

                # in byte
                currentArchiveIndex = 0
                currentArchiveSize = 0
                currentArchiveFileList = []
                targetArchiveSize = humanfriendly.parse_size(self.option("split"))

                def genArchiveTar():
                    archive_filepath = os.path.join(
                        ltfs_mount_path, f"{dst_archive_filename}.{currentArchiveIndex}.tar"
                    )
                    archive_file = tarfile.open(archive_filepath, "w")
                    self.line(
                        f"{TAB}{TAB}> Archiving {archive_filepath} [{humanfriendly.format_size(currentArchiveSize)}]",
                        style="option=bold",
                    )

                    doneSize = 0
                    doneSize = 0
                    f_iter = tqdm(currentArchiveFileList)
                    for f in f_iter:
                        f_iter.set_description_str(f"{TAB}{TAB}{TAB}- {archive_filepath} <= {f[:]}")

                        archive_file.add(f)
                        doneSize += os.path.getsize(f)

                        f_iter.set_postfix(
                            {
                                "Progress": f"{humanfriendly.format_size(doneSize)}/{humanfriendly.format_size(currentArchiveSize)}"
                            }
                        )

                    archive_file.close()

                    self.line(
                        f"{TAB}{TAB}{TAB}- [{humanfriendly.format_size(currentArchiveSize)}] {archive_filepath} Archived.",
                        style="fg=green;option=bold",
                    )

                for root, dirnames, filenames in os.walk(src_content_path):
                    for filename in filenames:

                        # start archiving
                        if currentArchiveSize >= targetArchiveSize:
                            genArchiveTar()
                            currentArchiveIndex += 1
                            currentArchiveSize = 0
                            currentArchiveFileList = []

                        fullPath = os.path.join(root, filename)
                        currentArchiveSize += os.path.getsize(fullPath)
                        currentArchiveFileList.append(fullPath)

                if len(currentArchiveFileList) > 0:
                    genArchiveTar()

                self.line("")
                self.line(f"{TAB}{TAB}> Start calculating checksums", style="option=bold")

                checksum_lines = []
                for root, dirnames, filenames in os.walk(ltfs_mount_path):
                    for filename in filenames:
                        sha256sum = hashlib.sha256()

                        with open(os.path.join(root, filename), "rb") as f:
                            while True:
                                # 512MB chunks
                                data = f.read(512 * 1024 * 1024)
                                if not data:
                                    break
                                sha256sum.update(data)
                            f.close()

                        sha256sumStr = sha256sum.hexdigest()
                        checksum_lines.append(f"{sha256sumStr} {filename}")

                        self.line(f"{TAB}{TAB}{TAB}- Checksum for {filename} is [{sha256sumStr}]")

                checksum_filepath = os.path.join(ltfs_mount_path, f"{archive['name']}-sha256sums.txt")
                checksum_file = open(checksum_filepath, "w")
                for l in checksum_lines:
                    checksum_file.writelines(l)
                checksum_file.close()

                self.line(f"{TAB}{TAB}{TAB}- Checksum file save to {checksum_filepath}")
                self.line(f"")

                time.sleep(4)

                try_count = 0
                umount_exitcode = -1
                while umount_exitcode != 0:
                    if try_count >= 10:
                        self.line(
                            f"{TAB}{TAB}> Try 10/10, last error: Unable to umount LTFS: {umount_proc.stderr.decode('utf-8')}",
                            style="fg=yellow",
                        )
                        self.line(f"")
                        break

                    try:
                        umount_proc = subprocess.run(
                            ["/bin/umount", ltfs_mount_path], stderr=subprocess.PIPE, stdout=subprocess.PIPE
                        )
                        umount_exitcode = umount_proc.returncode
                    except Exception as e:
                        try_count += 1

                    time.sleep(8)

                if umount_exitcode == 0:
                    os.rmdir(ltfs_mount_path)

                    self.line(f"{TAB}{TAB}> Archive completed! Tape is ejecting!", style="fg=green;option=bold")
                else:
                    self.line(f"{TAB}{TAB}> You may have to eject manually.", style="fg=yellow;option=bold")
                self.line(f"")
                time.sleep(60)

        self.line(f"")
        self.line(f"> Task completed!", style="fg=green;option=bold")
        self.line(f"")
