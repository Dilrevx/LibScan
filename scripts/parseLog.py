#!/usr/bin/env python

import json
import os
import subprocess
import argparse
import tempfile
from typing import Dict, List, Tuple

"""
this library is used to compute the F1 scores
"""

LIBSCAN_GROUND_TRUTH_FILE = "/home/li/LibScan/data/apk_ground_truth_list.txt"
PHUNTER_GROUND_TRUTH_FILE = (
    "/data/phunter/issta23-artifact/dataset/groundtruth_merge.txt"
)
PHUNTER_DATA_MAPPING = "/home/li/LibScan/tmp/CVEs2libsMapping.json"


def _get_libscan_ground_truth() -> Dict[str, List[str]]:
    with open(LIBSCAN_GROUND_TRUTH_FILE) as f:
        lines = f.readlines()
        lines = [line.strip() for line in lines]

    ret = {}
    for line in lines:
        apk_name, libs = line.split(":")
        ret[apk_name] = libs.split(",")
    return ret


class MetaPHunterGT:
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


def parse_args():
    parser = argparse.ArgumentParser(description="计算 F1 Score")
    parser.add_argument("file", help="log 文件路径")
    return parser.parse_args()


def _remove_datetime(line: str) -> str:
    return line.split(" - ")[-1]


def _divide_log_by_apk(
    lines: List[str],
) -> List[Tuple[List[str], List[str], List[str]]]:
    lines = filter(lambda line: "API level" not in line, lines)
    _ret: List[List[str]] = []

    for line in lines:
        if "开始分析" in line:
            _ret.append([])
        if len(_ret) == 0:
            continue
        _ret[-1].append(line)

    ret = []
    for apk_lines in _ret:
        period = 0
        ret.append(([], [], []))
        for line in apk_lines:
            if "---------" in line:
                period += 1
                continue
            ret[-1][period].append(line)
    return ret


def _parse_per_apk_content(
    per_apk_content: Tuple[List[str], List[str], List[str]]
) -> Tuple[
    str,
    List[str],
    Dict[str, float],
    Dict[str, float],
    Dict[str, float],
    Dict[str, float],
    Dict[str, float],
]:
    """
    In:
    :param per_apk_contents: [(apk_metas, details, results), ...]

    Out:
    :return: (apk_name.dex, List[dex_name.dex]], Dict)
    (dex_name, result, prematch_fails, prematch_succ, coarse_fails, coarse_succ, fine_test_libs)

    This version of the function can parse log file like repro.2nd, which in log
    - 在 apk metas 节显示哪些预匹配失败了，粗匹配失败了
    - 但不会显示哪些预匹配成功了，也不会显示粗匹配成功率

    upd:
    支持显示预匹配成功率和粗匹配成功率，以及细粒度结果
    """
    apk_metas, details, results = per_apk_content

    apk_name = apk_metas[0].replace("开始分析：", "").strip().replace(".apk", ".dex")
    assert apk_name.endswith(".dex"), apk_name
    lib_num = apk_metas[1].replace("本次分析的库数量为：", "").strip()
    lib_num = int(lib_num)

    prematch_failed_libs_to_acc: Dict[str, float] = {}  # <>.dex -> acc
    coarse_failed_libs_to_acc: Dict[str, float] = {}  # <>.dex -> acc
    prematch_succ_libs_to_acc: Dict[str, float] = {}  # <>.dex -> acc
    coarse_succ_libs_to_acc: Dict[str, float] = {}  # <>.dex -> acc
    fine_libs_to_acc: Dict[str, float] = {}  # <>.dex -> acc

    for i, line in enumerate(apk_metas[2:]):
        if "预匹配失败" in line:
            line = line.replace("预匹配失败库：", "").strip()
            failed_lib, acc = line.split("，预匹配率为：")
            prematch_failed_libs_to_acc[failed_lib] = float(acc)
        elif "预匹配成功" in line:
            line = line.replace("预匹配成功库：", "").strip()
            failed_lib, acc = line.split("，预匹配率为：")
            prematch_succ_libs_to_acc[failed_lib] = float(acc)
        elif "粗粒度匹配失败" in line:
            line = line.replace("粗粒度匹配失败库：", "").strip()
            failed_lib, acc = line.split("，粗粒度匹配率为：")
            coarse_failed_libs_to_acc[failed_lib] = float(acc)
        elif "粗粒度匹配成功" in line:
            line = line.replace("粗粒度匹配成功库：", "").strip()
            failed_lib, acc = line.split("，粗粒度匹配率为：")
            coarse_succ_libs_to_acc[failed_lib] = float(acc)
        elif "细粒度匹配库" in line:
            line = line.replace("细粒度匹配库 ", "").strip()
            fine_lib, acc = line.split("匹配率：")
            fine_libs_to_acc[fine_lib] = float(acc)
        else:
            raise NotImplementedError(line)

    result_apk_lines = details[1:]

    """
    the apk name is of the form:
    1. xxx.dex
    2. a.dex and b.dex
    """
    result_lib_names = map(
        lambda line: line.split(" : ")[0].strip(), result_apk_lines
    )  # modify this line to add support for numbers
    result_lib_names = list(result_lib_names)
    return (
        apk_name,
        result_lib_names,
        prematch_failed_libs_to_acc,
        prematch_succ_libs_to_acc,
        coarse_failed_libs_to_acc,
        coarse_succ_libs_to_acc,
        fine_libs_to_acc,
    )


no_def = set()


def check_result_with_phunter(
    apk_name: str,
    result_lib_names: List[str],
    phunter_ground_truths: Dict[str, List[MetaPHunterGT]],
    cve2lib: Dict[str, List[str]],
) -> Dict[str, bool]:
    """
    :param apk_name: apk name.dex
    :param result_lib_names: list of lib names.dex

    returns a dict mapping isTrue(result_lib_name)
    """
    # result_lib_names = [lib.replace(".dex", "") for lib in result_lib_names]
    ground_truths = phunter_ground_truths.get(apk_name)
    ground_truths = [gt.cve for gt in ground_truths]
    try:
        ground_truths = [
            cve2lib[cve].replace(".jar", ".dex")
            for cve in ground_truths
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
        no_def.add(e.args[0])
        print(e, no_def)

    ret = {name: name in ground_truths for name in result_lib_names}
    for result_lib_name in result_lib_names:
        if ret[result_lib_name]:
            print(f"识别成功：{result_lib_name}")
        else:
            print(f"识别失败：{result_lib_name}")

    print("识别的答案", ground_truths)
    return ret


def main():
    # args = parse_args()
    # file = args.file
    file = "/home/li/LibScan/tool/log.txt"
    ground_truth = _get_phunter_ground_truth()
    cve2lib = json.load(open(PHUNTER_DATA_MAPPING))

    with open(file) as f:
        content = f.readlines()
        content = [_remove_datetime(line) for line in content]
        per_apk_contents = _divide_log_by_apk(content)

    # 用于数据分析的 variables
    FAIL, SUCC = 0, 1
    prematch_rates = ([], [])
    coarse_rates = ([], [])
    fine_test_rates = []

    for per_apk_content in per_apk_contents:
        (
            apk_dex_name,
            result_lib_names,
            prematch_fails,
            prematch_succs,
            coarse_fails,
            coarse_succs,
            fine_tests,
        ) = _parse_per_apk_content(per_apk_content)

        prematch_rates[FAIL].append(max(prematch_fails.values(), default=-1))
        prematch_rates[SUCC].append(max(prematch_succs.values(), default=-1))
        coarse_rates[FAIL].append(max(coarse_fails.values(), default=-1))
        coarse_rates[SUCC].append(max(coarse_succs.values(), default=-1))
        fine_test_rates.append(max(fine_tests.values(), default=-1))

        print(f"-" * 30)
        print(f"apk name: {apk_dex_name}")
        print(f"result # {len(result_lib_names)}: {result_lib_names}")

        [prematch_fails, prematch_succs, coarse_fails, coarse_succs, fine_tests] = map(
            lambda x: sorted(x.items(), key=lambda x: x[1], reverse=True),
            [prematch_fails, prematch_succs, coarse_fails, coarse_succs, fine_tests],
        )

        if len(result_lib_names) > 0:
            print(f"匹配成功：{[result_lib_names]}")
        if len(fine_tests) > 0:
            print(f"细匹配：{fine_tests[:3]}")
        if len(coarse_succs) > 0:
            print(f"最大粗匹配成功库：{coarse_succs[:1]}")
        elif len(coarse_fails) > 0:
            print(f"最大粗匹配失败库：{coarse_fails[:1]}")
        if len(prematch_succs) > 0:
            print(f"最大预匹配成功库：{prematch_succs[:4]}")
        if len(prematch_fails) > 0:
            print(f"最大预匹配失败库：{prematch_fails[:4]}")

        lib_dex_name_to_istrue = check_result_with_phunter(
            apk_dex_name, result_lib_names, ground_truth, cve2lib
        )

        print(f"APK {apk_dex_name} 的结果：")
        print(lib_dex_name_to_istrue)

    from matplotlib import pyplot as plt

    os.makedirs("figures", exist_ok=True)
    BINS = 60

    plt.hist(prematch_rates[SUCC] + prematch_rates[FAIL], bins=BINS, range=(0, 1))
    plt.title("预匹配率")
    plt.savefig("figures/prematch_rates.png")
    plt.clf()
    plt.hist(coarse_rates[SUCC] + coarse_rates[FAIL], bins=BINS, range=(0, 1))
    plt.title("粗匹配率")
    plt.savefig("figures/coarse_fail_rates.png")
    plt.clf()
    plt.hist(fine_test_rates, bins=BINS, range=(0, 1))
    plt.title("细匹配率")
    plt.savefig("figures/fine_test_rates.png")


if __name__ == "__main__":
    main()
