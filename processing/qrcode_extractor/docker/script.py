#!/usr/bin/env python3
import sys
import os
import cv2
from pyzbar.pyzbar import decode

def redirect_stderr(fd, to):
    sys.stderr.close()
    os.dup2(to.fileno(), fd)
    sys.stderr = os.fdopen(fd, 'w')


def main(img):
    qrcode_data = set()
    fd = sys.stderr.fileno()
    old_stderr = os.fdopen(os.dup(fd), 'w')

    redirect_stderr(fd, open(os.devnull, 'w'))
    # attempt QR code decoding via opencv
    image = cv2.imread(img)
    detect = cv2.QRCodeDetector()
    try:
        retval, decoded, points, straight_qr = detect.detectAndDecodeMulti(image)
        redirect_stderr(fd, old_stderr)
        if retval:
            qrcode_data |= set(decoded)
    except cv2.error as e:
        pass

    # attempt QR code decoding via zbar
    redirect_stderr(fd, open(os.devnull, 'w'))
    image = cv2.imread(img, 0)
    try:
        value = decode(image)
        redirect_stderr(fd, old_stderr)
        qrcode_data |= set([v.data.decode() for v in value])
    except TypeError:
        pass

    for data in qrcode_data:
        if data.strip():
            print(data.strip())


if __name__ == "__main__":
    target_file = sys.argv[1]
    main(target_file)
