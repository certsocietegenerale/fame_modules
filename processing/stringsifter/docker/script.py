#!/usr/bin/env python3
import os
import numpy
import re
import sys
import warnings
import io
from sklearn.utils._testing import ignore_warnings
from sklearn.exceptions import InconsistentVersionWarning
from stringsifter.flarestrings import ASCII_BYTE
from stringsifter.rank_strings import main as rank_strings


def main(target_file, min_len, limit, show_scores):
    re_narrow = re.compile(b"([%s]{%d,})" % (ASCII_BYTE, min_len))
    re_wide = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, min_len))

    strings = set()

    b = open(target_file, "rb").read()
    for match in re_narrow.finditer(b):
        strings.add(match.group().decode("ascii"))
    for match in re_wide.finditer(b):
        try:
            strings.add(match.group().decode("utf-16"))
        except UnicodeDecodeError:
            pass

    min_score = numpy.nan
    batch = False
    rank_strings(io.StringIO("\n".join(strings)), limit, min_score, show_scores, batch)


if __name__ == "__main__":
    # Hide sklearn InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

    target_file = sys.argv[1]
    show_scores = os.getenv("show_scores", "false").lower() == "true"
    min_len = int(os.getenv("min_len", "4"))
    limit = int(os.getenv("limit", "0"))
    if limit == 0:
        limit = None

    main(target_file, min_len, limit, show_scores)
