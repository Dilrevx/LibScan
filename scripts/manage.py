# Wrapper script to use libScan for all .apk in ROM

"""
usage: LibScan.py detect_all [-h] [-o FOLDER] [-p num_processes] [-af FOLDER] [-lf FOLDER] [-ld FOLDER]

optional arguments:
  -h, --help        show this help message and exit
  -o FOLDER         Specify directory of detection results (containing result in .TXT per app)
  -p num_processes  Specify maximum number of processes used in detection (default=#CPU_cores)
  -af FOLDER        Specify directory of apps
  -lf FOLDER        Specify directory of TPL versions
  -ld FOLDER        Specify directory of TPL versions in DEX files
"""

import shutil
import os
import sys, json
import subprocess
from pathlib import Path
import tempfile

TOOL_PATH = Path("./tool")


def check_apk_sound(apk: Path):
    if not hasattr(check_apk_sound, "APKtoAPKPath"):
        check_apk_sound.APKtoAPKPath = dict()

    if apk.name in check_apk_sound.APKtoAPKPath:
        print("[INFO] apkname duplicate: ", apk.name)

    # assert set(apk.parts).intersection(
    #     [
    #         "system",
    #         "vendor",
    #         "product",
    #     ]
    # ), f"unexpected APK src: {apk}"

    return check_apk_sound.APKtoAPKPath


def detect_all(
    apk_folder: Path,
    tpl_folder: Path,
    tpl_dex_folder: Path,
    output_folder: Path,
    num_processes: str = "",
):
    """
    copy all .apk to /tmp and run libscan
    """
    # TMP_DIR = tempfile.TemporaryDirectory()
    TMP_DIR = Path("./tmp")  # Path(tempfile.mkdtemp())
    print("temp dir: ", TMP_DIR.name)

    for path in apk_folder.rglob("*.apk"):
        APKtoAPKPath = check_apk_sound(path)

        APKtoAPKPath[path.name] = path.absolute().as_posix()
        shutil.copy(path, TMP_DIR)

    print("APK cnt = ", len(tuple(apk_folder.rglob("*.apk"))))

    cmd = "python3 LibScan.py detect_all -o {} -af {} -lf {} -ld {}".format(
        output_folder.absolute(),
        TMP_DIR.name,
        tpl_folder.absolute(),
        tpl_dex_folder.absolute(),
    )

    print(cmd)
    json.dump(
        APKtoAPKPath,
        open((output_folder / apk_folder.name).as_posix() + ".json", "w"),
        indent=4,
    )
    subprocess.run(
        [
            "nohup",
            f"python3",
            "LibScan.py",
            "detect_all",
            "-o",
            output_folder.absolute(),
            "-af",
            TMP_DIR.absolute(),
            "-lf",
            tpl_folder.absolute(),
            "-ld",
            tpl_dex_folder.absolute(),
        ],
        cwd=TOOL_PATH.as_posix(),
        check=True,
        # capture_output=True, # capture means redirect stdout to buf in this script, not console
    )


detect_all(
    apk_folder=Path(
        "/data/firmwares/cheetah-td1a.220804.009.a2-factory-8e7393e1.zip.extracted"
    ),
    # tpl_folder=TOOL_PATH / "libs",
    # tpl_dex_folder=TOOL_PATH / "libs_dex",
    tpl_folder=Path("/home/li/LibScan/data/vulnerability_libs"),
    tpl_dex_folder=Path("/home/li/LibScan/data/vulnerability_libs_dex"),
    output_folder=Path("./"),
    num_processes="",
)
