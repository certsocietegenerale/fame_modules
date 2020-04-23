import os
import sys
from git import Repo

sys.path.append(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "..")))

from fame.common.constants import VENDOR_ROOT


def main():
    dnsdmpstr_path = os.path.join(VENDOR_ROOT, 'dnsdmpstr')

    if os.path.exists(dnsdmpstr_path):
        repo = Repo(dnsdmpstr_path)
        repo.remotes.origin.pull()
    else:
        Repo.clone_from("https://github.com/zeropwn/dnsdmpstr.git", dnsdmpstr_path)

if __name__ == '__main__':
    main()
