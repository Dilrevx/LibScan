from pathlib import Path
import os, shutil

CVEs = Path("/home/li/LibScan/data/CVEs")
libs_dir = Path("/home/li/LibScan/data/phunter.adapt")
os.makedirs(libs_dir, exist_ok=True)

CVEs2libsMapping = {}

for fp in CVEs.rglob("*pre.jar"):
    cve, filename = fp.parts[-2:]

    # if not filename.startswith("log4j"):
    # this line is used to reduce TPL number
    # continue
    shutil.copy(fp, libs_dir / filename)
    CVEs2libsMapping[cve] = filename

import json

# with open("/home/li/LibScan/tmp/CVEs2libsMapping.json", "w") as f:
#     json.dump(CVEs2libsMapping, f)
