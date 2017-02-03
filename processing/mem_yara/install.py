import os
import sys
from git import Repo
from shutil import rmtree
from subprocess import call

sys.path.append(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "..")))

from fame.common.constants import VENDOR_ROOT


def main():
    try:
        import volatility
    except ImportError:
        volpath = os.path.join(VENDOR_ROOT, "volatility")
        setup_script = os.path.join(volpath, "setup.py")

        rmtree(volpath, True)
        Repo.clone_from("https://github.com/volatilityfoundation/volatility.git", volpath)

        os.chdir(volpath)
        call(['python', setup_script, 'install'])

if __name__ == '__main__':
    main()
