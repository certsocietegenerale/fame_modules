import glob
import pathlib
import hashlib

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


class QrCodeExtractor(ProcessingModule):
    name = "qr_extractor"
    description = "Analyze files (via screenchot) and pictures (directly) to find QRcodes and decode them with two different libs."
    acts_on = ["png", "pdf", "word", "html", "excel", "powerpoint"]

    config = [
        {
            "name": "skip_safe_file_review",
            "type": "bool",
            "default": False,
            "description": "Skip file review when no suspicious elements are found."
        }
    ]

# Check that libraries wer loaded correctly
    
    def initialize(self):
        if not HAVE_PEEPDF:
            raise ModuleInitializationError(self, "Missing dependency: peepdf")
        if not HAVE_PYZBAR:
            raise ModuleInitializationError(self, "Missing dependency: pyzbar")
          
    """ def file_sha256(filepath):
        sha256 = hashlib.sha256()

        with open(filepath, 'rb') as f:
            while True:
                data = f.read(1000000)
                if not data:
                    break
                sha256.update(data)

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
    """
    # For each, check if QRcode is found and extract potentiel URL
    #   - TO-DO : include document preview for pdf to be able to read the qrcode
    #               Or trigger the qrcode extractor after document preview
    
    def each(self, target):
        self._outdir = None
        self.results = {
            'urls': set()
        }
        
        # add ioc for the url decoded
        if filetype == "url" and not target.startswith("http"):
            target = "http://{}".format(target)

        if filetype == "url":
            self.add_ioc(target)

        # Read image target
        image = cv2.imread(target, 0)
        
        # decode QRcode
        
        def extract_qr_code_by_opencv(target):
            try:
                detect = cv2.QRCodeDetector()
                value, points, straight_qrcode = detect.detectAndDecode(image)
                print(value)
                return value
            except:
                return

        def extract_qr_code_by_pyzbar(target):
            try:
                value = decode(image)
                print(value)
                return value
            except:
                return

#TO-DO Include call to URL preview