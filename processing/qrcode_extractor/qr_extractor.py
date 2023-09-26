import glob
import pathlib


from fame.core.module import ProcessingModule, ModuleInitializationError, ModuleExecutionError
from fame.common.utils import tempdir



try:
    import cv2
    HAVE_CV2 = True
except ImportError:
    HAVE_CV2 = False

try:
    from pyzbar.pyzbar import decode
    HAVE_PYZBAR = True
except ImportError:
    HAVE_PYZBAR = False


def file_sha256(filepath):
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while True:
            data = f.read(1000000)
            if not data:
                break
            sha256.update(data)


class QrCodeExtractor(ProcessingModule):
    name = "qr_extractor"
    description = "Analyze PDF files and pictures to find QRcodes and decode them with two different libs."
    acts_on = "png, pdf"

    config = [
        {
            "name": "skip_safe_file_review",
            "type": "bool",
            "default": False,
            "description": "Skip file review when no suspicious elements are found."
        }
    ]

    def initialize(self):
        if not HAVE_PEEPDF:
            raise ModuleInitializationError(self, "Missing dependency: peepdf")
        if not HAVE_PYZBAR:
            raise ModuleInitializationError(self, "Missing dependency: pyzbar")

    def outdir(self):
        if self._outdir is None:
            self._outdir = tempdir()

        return self._outdir

    def clean_up(self):
        if self._outdir is not None:
            rmtree(self._outdir)

    def extract_file(self, name, data):
        fpath = os.path.join(self.outdir(), name)

        with open(fpath, 'w') as f:
            f.write(data)

        self.add_extracted_file(fpath)

        sha256 = file_sha256(fpath)
        self.results['files'].add(sha256)


#include document preview for pdf to be able to read the qrcode

################################


def extract_qr_code_by_opencv(filename):
    """Read an image and read the QR code.
    
    Args:
        filename (string): Path to file
    
    Returns:
        qr (string): Value from QR code
    """
    
    try:
        img = cv2.imread(filename, 0)
        detect = cv2.QRCodeDetector()
        value, points, straight_qrcode = detect.detectAndDecode(img)
        print(value)
        return value
    except:
        return
def extract_read_qr_code_by_pyzbar(filename):
    """Read an image and read the QR code.

    Args:
        filename (string): Path to file

    Returns:
        qr (string): Value from QR code
    """

    try:
        img = cv2.imread(filename, 0)
        value = decode(img)
        print(value)
        return value
    except:
        return
    

#Include URL preview


def main():
    print("————PYZBAR————")
	print(extract_read_qr_code_by_pyzbar(file))
	print("————OPENCV————")
	print(extract_qr_code_by_opencv(fie))

if __name__ == "__main__":
	main()
