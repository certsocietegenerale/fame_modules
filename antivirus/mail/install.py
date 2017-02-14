import sys
from distutils.spawn import find_executable


def main():
    if find_executable('7z') is None:
        print "Missing dependency: 7z"
        sys.exit(1)


if __name__ == '__main__':
    main()
