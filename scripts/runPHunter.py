"""
Run PHunter using the results from LibScan
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, Tuple
from LibScanResultParser import (
    LibScanResultParser,
    _get_phunter_ground_truth,
    MetaPHunterGT,
    LibScanTruePositive,
    LibScanFalsePositive,
)
import yaml

CONFIGURE_PATH = Path("./configuration.yaml")


def _load_config() -> Dict[str, Any]:
    with open(CONFIGURE_PATH) as f:
        return yaml.safe_load(f)


class PHunterRunner:
    def __init__(self, jar_path, android_jar, cve_dataset: Path) -> None:
        """
        init with path to .jar or to PHunter/
        """
        jar_path = Path(jar_path)
        android_jar = Path(android_jar)
        cve_dataset = Path(cve_dataset)

        if os.path.isdir(jar_path):
            jar_path = jar_path / "PHunter.jar"
        assert jar_path.suffix == ".jar", "jar_path should be a .jar file"
        assert android_jar.suffix == ".jar", "android_jar should be a .jar file"

        self.jar_path = jar_path
        self.android_jar = android_jar
        self.cve_dataset = cve_dataset

    def getDiffPrePostTPLfromCVE(self, cve: str) -> Tuple[Path, Path, Path]:
        """
        get preTPL and postTPL from cve
        """
        cve = cve.upper()
        folder = self.cve_dataset / cve

        diff = folder.glob("*.diff").__next__()
        pre_tpl = folder.glob(f"*pre.jar").__next__()
        post_tpl = folder.glob(f"*post.jar").__next__()

        return (
            diff,
            pre_tpl,
            post_tpl,
        )

    def detect_all(
        self,
        pre_tpl: Path,
        post_tpl: Path,
        thread_num: int,
        android_jar: Path,
        patch_files: Path,
        target_apk: Path,
    ):
        cmd = [
            "java",
            "-jar",
            str(self.jar_path),
            "--preTPL",
            str(pre_tpl.absolute()),
            "--postTPL",
            str(post_tpl.absolute()),
            "--threadNum",
            str(thread_num),
            "--androidJar",
            str(android_jar.absolute()),
            "--patchFiles",
            str(patch_files.absolute()),
            "--targetAPK",
            str(target_apk.absolute()),
        ]

        print(" ".join(cmd))

        result = subprocess.run(cmd, capture_output=True)
        print(result.stdout.decode())
        print(result.stderr.decode())

        with open("/home/li/LibScan/runner.log", "a") as f:
            f.write(result.stdout.decode())
            f.write(result.stderr.decode())


def main(cfg, phunter_gt, cve2lib):
    libscan_cfg, phunter_cfg, data_cfg = cfg["libscan"], cfg["phunter"], cfg["dataset"]

    libscan_result_dir = libscan_cfg["args"]["output_folder"]

    parser = LibScanResultParser(libscan_result_dir)
    prunner = PHunterRunner(
        phunter_cfg["path"], phunter_cfg["android_jar"], data_cfg["cve_folder"]
    )

    result_dict = parser.check_result_with_phunter_GT(phunter_gt, cve2lib)

    for apk_name, (lib_tps, lib_fps) in result_dict.items():
        for lib, _ in lib_tps.tp_libs():
            diff, pre_tpl, post_tpl = prunner.getDiffPrePostTPLfromCVE(lib.cve)
            apk_name = apk_name.replace(".dex", ".apk", 1)
            apk_folder = data_cfg["apk_folder"]

            prunner.detect_all(
                pre_tpl=pre_tpl,
                post_tpl=post_tpl,
                thread_num=os.cpu_count(),
                android_jar=Path(phunter_cfg["android_jar"]),
                patch_files=diff,
                target_apk=Path(apk_folder).absolute() / Path(apk_name),
            )


if __name__ == "__main__":
    phunter_gt = _get_phunter_ground_truth()
    cfg = _load_config()

    data_cfg = cfg["dataset"]
    cve2lib = json.load(open(data_cfg["CVEs2libsMapping"]))
    MetaPHunterGT._init_lib2cve(cve2lib)

    main(cfg, phunter_gt, cve2lib)
