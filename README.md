# Tape Manager

Helps you archive your backup into tape!

## Usage

It is very simple.

```bash
# Install requirements, if you haven't done it yet.
pip install -r requirements.txt

# Display usage
python main.py
```

and checkout the ``config.example.json``  

#### Run backup task
![run_backup_task](imgs/run_backup_task.png)

#### Mount tape
![mount_tape](imgs/mount_tape.png)

### Generate encrypted device-encryption key
![enc_key](imgs/enc_key.png)

## Requirements

These linux binaries should exist:
- mkltfs
- ltfs
- mt-gnu
- mt-st
- stenc
