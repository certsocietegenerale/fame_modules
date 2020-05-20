import os

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError


try:
    from msoffcrypto import OfficeFile

    HAVE_MSOFFCRYPTO = True
except ImportError:
    HAVE_MSOFFCRYPTO = False


class OfficePassword(ProcessingModule):
    name = "office_password"
    description = "Decrypt password protected office documents."
    acts_on = ["word", "excel", "powerpoint"]

    config = [
        {
            "name": "password_candidates",
            "type": "text",
            "default": "1234\n123456\ninfected",
            "description": "List of passwords to try when decrypting an encrypted Office document (one per line)."
        }
    ]

    def initialize(self):
        if not HAVE_MSOFFCRYPTO:
            raise ModuleInitializationError(self, "Missing dependency: msoffcrypto")

    def each(self, target):
        tmpdir = tempdir()
        password_candidates = self.password_candidates.split("\n")

        with open(target, "rb") as myfile:

            document = OfficeFile(myfile)

            for password in password_candidates:
                password = password.strip()
                try:
                    document.load_key(password=password)
                    out_file = tmpdir + os.path.sep + "decrypted_" + os.path.basename(target)
                    with open(out_file, "wb") as output:
                        document.decrypt(output)
                    if os.path.isfile(out_file):
                        self.add_extracted_file(out_file)
                    break
                except:
                    pass
            else:
                self.log('error', 'Could not extract {} (password not known)'.format(target))

        return True
