import subprocess

class TapeInfo:
    def __init__(self, device: str):
        self.device = device
        self.refresh()

    def refresh(self): 
        self.attr = {}

        proc = subprocess.run(['sg_logs', "-p", "0x17", self.device], check=True,
                stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        
        if proc.returncode != 0:
            raise Exception(proc.stderr)

        outputs = str(proc.stdout).split("\\n")

        for line in outputs:
            if not ":" in line:
                continue

            line = line.replace("  ", "")
            kv = line.split(": ")

            if len(kv) != 2:
                continue
            
            self.attr[kv[0]] = kv[1]
        
    
    def get(self, key: str) -> str:
        return self.attr[key]
    
    def barcode(self) -> str:
        return self.get("Volume barcode")
