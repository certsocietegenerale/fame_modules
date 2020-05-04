import os
import sys
from distutils.spawn import find_executable


def main():
    if find_executable('docker') is None:
        print "Missing dependency: docker-cli. Please install it with `install.sh' on debian-based systems or refer to the official docker documentation on installation instructions."
        sys.exit(1)

    print "building container"
    build_script = os.path.join(os.path.dirname(__file__), "build.sh")
    subprocess.check_output(["bash", build_script])
    print "container build done"


if __name__ == '__main__':
    main()
