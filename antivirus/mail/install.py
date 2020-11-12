import sys
from distutils.spawn import find_executable


def main():
    if find_executable('7z') is None:
        print("Missing dependency: 7z. Install it with 'sudo apt-get install p7zip-full' (or equivalent for your platform) and reload modules.")
        sys.exit(1)


if __name__ == '__main__':
    main()
