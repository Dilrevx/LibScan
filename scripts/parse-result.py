from collections import defaultdict
import os
from typing import Dict, List, Tuple


class LibScanResultParser:
    def __init__(self, dirpath: str) -> None:
        """
        open `dirpath` and parse the result. dir should contain <apk>.txt

        Note: apk name should not duplicate

        ---
        Member
        result: Dict[str, Tuple[str, float]]
            .apk -> (libname.dex, similarity)
        """
        self.result: Dict[str, Tuple[str, float]] = defaultdict(
            tuple
        )  # .apk -> (libname.dex, similarity)
        for filename in os.listdir(dirpath):
            assert filename.endswith(".txt"), "file should be .txt"

            with open(os.path.join(dirpath, filename), "r") as f:
                _results = f.readlines()[:-1]  # remove "time:"

            apk_name = filename[: filename.rfind(".txt")]

            for lib, sim, _ in _results[::3]:
                self.result[apk_name] = (lib, float(sim))

    def get_result(self) -> Dict[str, Tuple[str, float]]:
        """
        ".apk" -> (libname.dex, similarity)
        """
        return self.result
