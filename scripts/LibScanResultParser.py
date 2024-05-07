from collections import defaultdict
import os
import json
from typing import Dict, List, Set, Tuple

PHUNTER_GROUND_TRUTH_FILE = (
    "/data/phunter/issta23-artifact/dataset/groundtruth_merge.txt"
)
PHUNTER_DATA_MAPPING = "/home/li/LibScan/tmp/CVEs2libsMapping.json"
CHECK_PHUNTER_MISSING_LIBS = "/home/li/LibScan/tmp/phunter_missing.txt"


class MetaPHunterGT:
    cve2Meta: Dict[str, "MetaPHunterGT"] = dict()
    lib2cve: Dict[str, str] = dict()

    @classmethod
    def _init_lib2cve(cls, cve2lib: Dict[str, str]):
        for cve, lib in cve2lib.items():
            lib = lib.replace(".jar", ".dex", 1)
            cls.lib2cve[lib] = cve

    @classmethod
    def from_cve(cls, cve: str) -> "MetaPHunterGT":
        return cls.cve2Meta[cve]

    @classmethod
    def from_pre_lib(cls, lib: str) -> "MetaPHunterGT":
        assert cls.lib2cve, "call _init_lib2cve first"
        return cls.cve2Meta[cls.lib2cve[lib]]

    def __init__(
        self,
        short_name="",
        cve="",
        pre_version="",
        post_version="",
        is_patched=False,
        internal_full_name="",
    ):
        self.short_name = short_name
        self.cve = cve
        self.pre_version = pre_version
        self.post_version = post_version
        self.is_patched = is_patched
        self.internal_full_name = internal_full_name
        MetaPHunterGT.cve2Meta[cve] = self

    def __str__(self) -> str:
        return f"{self.cve} {self.internal_full_name} {self.is_patched}"


def _get_phunter_ground_truth() -> Dict[str, List[MetaPHunterGT]]:
    """
    :return: apk_name.dex -> [
        (lib_name, cve, is_patched, lib_name)
    ]
    """
    with open(PHUNTER_GROUND_TRUTH_FILE) as f:
        lines = f.readlines()
        lines = [line.strip() for line in lines]
    from collections import defaultdict

    ret: Dict[str, List[Tuple[MetaPHunterGT]]] = defaultdict(list)

    for i, txt_line in enumerate(lines):
        if ".txt" not in txt_line:
            continue

        for i_entry in range(i + 1, len(lines), 2):
            if lines[i_entry] == "":
                break
            line1, line2 = lines[i_entry], lines[i_entry + 1]

            line1, line2 = line1.split("\t"), line2.split("\t")

            short_name, cve, pre_version, post_version = line1 + [""] * (4 - len(line1))
            is_flag, internal_full_name = line2

            assert cve.startswith(("CVE-", "APACHE-", "HTTPCLIENT-")), cve
            # assert (
            #     pre_version == post_version == ""
            #     or pre_version <= post_version
            #     or "rel" in pre_version
            #     or "pre" in post_version
            # ), (pre_version, post_version)

            ret[txt_line.replace(".txt", ".dex")].append(
                MetaPHunterGT(
                    short_name,
                    cve,
                    pre_version,
                    post_version,
                    bool(is_flag),
                    internal_full_name,
                )
            )

    return ret


class LibScanFalsePositive:
    """
    per APK 记录 FP 有哪些 TPL
    """

    def __init__(self, apk_name: str) -> None:
        self.apk_name = apk_name
        self._fp_libs: Set[Tuple[str, float]] = set()

    def fp_libs(self):
        return self._fp_libs


class LibScanTruePositive:
    """
    per APK 记录 TP 有哪些 TPL
    """

    def __init__(self, apk_name: str) -> None:
        self.apk_name = apk_name
        self._tp_libs: Set[Tuple[MetaPHunterGT, float]] = set()

    def tp_libs(self):
        return self._tp_libs


class LibScanResultParser:
    def __init__(self, dirpath: str, in_dex=True) -> None:
        """
        open `dirpath` and parse the result. dir should contain <apk>.txt
        读取每个 apk 的分析结果

        Note: apk name should not duplicate

        ---
        Member
        result: Dict[str, Tuple[str, float]]
            .apk -> (libname.dex, similarity)
        """
        self.result: Dict[str, List[Tuple[str, float]]] = defaultdict(
            list
        )  # .apk -> (libname.dex, similarity)
        for filename in os.listdir(dirpath):
            assert filename.endswith(".txt"), "file should be .txt"

            with open(os.path.join(dirpath, filename), "r") as f:
                __results = f.readlines()
                _results = (
                    __results[i : i + 3] for i in range(0, len(__results) - 1, 3)
                )  # remove "time:"

            apk_name = filename[: filename.rfind(".txt")]
            apk_name = apk_name.replace(".apk", ".dex", 1) if in_dex else apk_name

            for lib, sim, _ in _results:
                lib = lib.lstrip("lib: ").strip()
                sim = sim.lstrip("similarity: ").strip()
                self.result[apk_name].append((lib + ".dex", float(sim)))

    def get_result(self):
        """
        ".apk" -> [(libname.dex, similarity), ...]
        """
        return self.result

    def _check_perlib_result_with_phunter_GT(
        self,
        apk_name: str,
        result_lib_name: List[str],
        phunter_ground_truths: Dict[str, List[MetaPHunterGT]],
        cve2lib: Dict[str, List[str]],
    ) -> bool:
        """
        :param apk_name: apk name.dex
        :param result_lib_name: one lib_names.dex

        检查 <apk_name>.dex 的 GT 中是否有 result_lib_name
        """
        ground_truths = phunter_ground_truths.get(apk_name)
        gt_cves = [gt.cve for gt in ground_truths]
        try:
            gt_vuln_libs = [
                cve2lib[cve].replace(".jar", ".dex")
                for cve in gt_cves
                if "CVE-" in cve
                and cve
                not in [
                    "CVE-2016-1000338",
                    "CVE-2017-4995-JK",
                    "CVE-2017-7525",
                    "CVE-2016-1000340",
                    "CVE-2018-14718",
                    "CVE-2018-14719",
                    "CVE-2012-6153",
                    "CVE-2013-4366",
                    "CVE-2011-1498",
                ]
            ]  # TODO: what the APACHE- and HTTPCLIENT- are?
        except Exception as e:
            print(e)
        ret = result_lib_name in gt_vuln_libs

        # TODO: maybe we should not print
        print(f"[{apk_name}] LibScan 测出来了 PHunter 没有标的东西:", end=" ")
        print(result_lib_name, gt_vuln_libs)
        return ret

    def check_result_with_phunter_GT(
        self,
        phunter_ground_truths: Dict[str, List[MetaPHunterGT]],
        cve2lib: Dict[str, List[str]],
    ) -> Dict[str, Tuple[LibScanTruePositive, LibScanFalsePositive]]:
        """
        :param phunter_ground_truths: apk_name.dex -> [
            (lib_name, cve, is_patched, lib_name)
        ]

        过滤掉错误答案，returns
        1. mapping apk_name -> (result_lib_name, similarity)
        2. 每个 apk 的 FP
        """
        ret = dict()

        for apk_name, libscan_results in self.result.items():

            fp_obj = LibScanFalsePositive(apk_name)
            tp_obj = LibScanTruePositive(apk_name)

            for res_lib_name, similarity in libscan_results:
                gt = self._check_perlib_result_with_phunter_GT(
                    apk_name, res_lib_name, phunter_ground_truths, cve2lib
                )

                if not gt:
                    fp_obj.fp_libs().add((res_lib_name, similarity))
                else:
                    tp_obj.tp_libs().add(
                        (MetaPHunterGT.from_pre_lib(res_lib_name), similarity)
                    )

            ret[apk_name] = (tp_obj, fp_obj)
        return ret


if __name__ == "__main__":
    parser = LibScanResultParser("/home/li/LibScan/result/phunter")
    result = parser.get_result()

    cve2lib = json.load(open(PHUNTER_DATA_MAPPING))
    phunter_ground_truths = _get_phunter_ground_truth()
    MetaPHunterGT._init_lib2cve(cve2lib)

    apk2gt_fp = parser.check_result_with_phunter_GT(phunter_ground_truths, cve2lib)

    for apk, (tp, fp) in apk2gt_fp.items():
        print(apk)
        print("TP:", tp.tp_libs())
        print("FP:", fp.fp_libs())
        print()
        input()
