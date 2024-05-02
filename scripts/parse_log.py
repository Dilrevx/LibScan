#!/usr/bin/env python

import os
import subprocess
import argparse
import tempfile
from typing import Dict, List, Tuple

"""
this library is used to compute the F1 scores
仅能处理自带的 log.txt，因为自带 log 会多 log 一次
"""

GROUND_TRUTH_FILE = "/home/li/LibScan/data/apk_ground_truth_list.txt"


def _get_ground_truth() -> Dict[str, List[str]]:
    with open(GROUND_TRUTH_FILE) as f:
        lines = f.readlines()
        lines = [line.strip() for line in lines]

    ret = {}
    for line in lines:
        apk_name, libs = line.split(":")
        ret[apk_name] = libs.split(",")
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
    per_apk_contents: List[Tuple[List[str], List[str], List[str]]]
) -> Dict[str, List[str]]:
    """
    In:
    :param per_apk_contents: [(apk_metas, details, results), ...]
    """
    ret = {}
    for apk_metas, details, results in per_apk_contents:
        apk_name = apk_metas[0].replace("开始分析：", "").strip()
        assert apk_name.endswith(".apk"), apk_name

        result_count = results[0].replace("检测出库的总数：", "").strip()
        result_count = int(result_count)
        result_apk_lines = results[2 : 2 + result_count]

        """
        the apk name is of the form:
        1. xxx.dex
        2. a.dex and b.dex
        """
        result_apk_names = map(
            lambda line: line.split(" : ")[0].strip(), result_apk_lines
        )
        result_apk_names = list(result_apk_names)
        ret[apk_name] = result_apk_names
    return ret


def main():
    args = parse_args()
    file = args.file

    with open(file) as f:
        content = f.readlines()
        content = [_remove_datetime(line) for line in content]
        per_apk_contents = _divide_log_by_apk(content)

    dex_name_result_list = _parse_per_apk_content(per_apk_contents)
    ground_truth = _get_ground_truth()

    for dex_name, result_list in dex_name_result_list.items():
        ground_truth_result = ground_truth[dex_name.replace(".dex", ".apk", 1)]

        for result in result_list:
            if " and " in result:
                raise NotImplementedError()
            print(result in ground_truth_result)


if __name__ == "__main__":
    main()
