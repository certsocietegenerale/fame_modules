import os
import sys
from git import Repo

sys.path.append(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "..")))

from fame.common.constants import VENDOR_ROOT


def main():
    decoders_path = os.path.join(VENDOR_ROOT, 'RATDecoders')

    if os.path.exists(decoders_path):
        repo = Repo(decoders_path)
        repo.remotes.origin.pull()
    else:
        Repo.clone_from("https://github.com/kevthehermit/RATDecoders.git", decoders_path)

if __name__ == '__main__':
    main()
