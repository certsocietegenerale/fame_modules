import os
import sys
from git import Repo


sys.path.append(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "..")))

from fame.common.constants import VENDOR_ROOT


def main():
    peepdf_path = os.path.join(VENDOR_ROOT, "peepdf")

    if not os.path.isfile(os.path.join(peepdf_path, "peepdf.py")):
        Repo.clone_from('https://github.com/jesparza/peepdf', peepdf_path)


if __name__ == '__main__':
    main()
