#!/usr/bin/env python

import os
import subprocess
import argparse
import tempfile


def parse_args():
    parser = argparse.ArgumentParser(description="比对阈值调优文件")
    parser.add_argument("a")
    parser.add_argument("b")
    return parser.parse_args()


def _remove_datetime(line: str) -> str:
    return line.split(" - ")[-1]


def main():
    args = parse_args()
    a = args.a
    b = args.b

    with open(a) as f:
        a_content = f.readlines()
        a_content = [_remove_datetime(line) for line in a_content]

    with open(b) as f:
        b_content = f.readlines()
        b_content = [_remove_datetime(line) for line in b_content]

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a"), "w") as f:
            f.writelines(a_content)

        with open(os.path.join(d, "b"), "w") as f:
            f.writelines(b_content)

        subprocess.run(["code", "--diff", os.path.join(d, "a"), os.path.join(d, "b")])
        input("Press Enter to exit...")

    """
    compute FP, FN, TP diff
    """

    a_content = filter(lambda line: line.startswith("检测出库的总数"), a_content)
    b_content = filter(lambda line: line.startswith("检测出库的总数"), b_content)

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a"), "w") as f:
            f.writelines(a_content)

        with open(os.path.join(d, "b"), "w") as f:
            f.writelines(b_content)

        subprocess.run(["code", "--diff", os.path.join(d, "a"), os.path.join(d, "b")])
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
