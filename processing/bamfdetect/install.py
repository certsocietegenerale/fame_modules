import pip


def main():
    pip.main(['install', '--no-deps', 'git+https://github.com/bwall/bamfdetect#egg=BAMF_Detect'])

if __name__ == '__main__':
    main()
