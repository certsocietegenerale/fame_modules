from os.path import basename

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

try:
    import rarfile
    HAVE_RARFILE = True
except ImportError:
    HAVE_RARFILE = False

try:
    import Crypto
    HAVE_PYCRYPTO = True
except ImportError:
    HAVE_PYCRYPTO = False

try:
    import pbkdf2
    HAVE_PBKDF2 = True
except ImportError:
    HAVE_PBKDF2 = False

try:
    from BAMF_Detect import handle_file
    HAVE_BAMF = True
except ImportError:
    HAVE_BAMF = False


class BAMFDetect(ProcessingModule):

    name = "bamfdetect"
    description = "Run BAMF_Detect on unpacked executables in order to detect known malware families and extract their configurations."
    acts_on = "unpacked_executable"

    def initialize(self):
        if not HAVE_PEFILE:
            raise ModuleInitializationError(self, "Missing dependency: pefile")
        if not HAVE_YARA:
            raise ModuleInitializationError(self, "Missing dependency: yara")
        if not HAVE_RARFILE:
            raise ModuleInitializationError(self, "Missing dependency: rarfile")
        if not HAVE_PYCRYPTO:
            raise ModuleInitializationError(self, "Missing dependency: pycrypto")
        if not HAVE_PBKDF2:
            raise ModuleInitializationError(self, "Missing dependency: pbkdf2")
        if not HAVE_BAMF:
            raise ModuleInitializationError(self, "Missing dependency: BAMF_Detect")

        self.results = {}

    def each(self, target):
        for fp, r in handle_file(target, None, False):
            self.add_probable_name(r['type'])
            self.results[basename(fp).replace('.', '_')] = {
                'name': r['type'],
                'config': r['information']
            }
            return True

        return False
