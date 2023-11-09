#!/usr/bin/env python3
import sys
import cv2
from pyzbar.pyzbar import decode


def main(img):
    qrcode_data = set()

    # attempt QR code decoding via opencv
    image = cv2.imread(img)
    detect = cv2.QRCodeDetector()
    try:
        retval, decoded, points, straight_qr = detect.detectAndDecodeMulti(image)
        if retval:
            qrcode_data |= set(decoded)
    except cv2.error as e:
        pass

    # attempt QR code decoding via zbar
    image = cv2.imread(img, 0)
    try:
        value = decode(image)
        qrcode_data |= set([v.data.decode() for v in value])
    except TypeError:
        pass

    for data in qrcode_data:
        if data.strip():
            print(data.strip())


if __name__ == "__main__":
    target_file = sys.argv[1]
    main(target_file)
