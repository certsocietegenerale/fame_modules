import sys
import subprocess

def main():
    subprocess.check_output([
        sys.executable, '-m', 'pip', 'install',
        '--no-deps', 'git+https://github.com/bwall/bamfdetect#egg=BAMF_Detect'])

if __name__ == '__main__':
    main()
