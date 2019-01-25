import os
from zipfile import ZipFile

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir


class Zip(ProcessingModule):
    name = "zip"
    description = "Extract files from ZIP archive."
    acts_on = "zip"

    config = [
        {
            "name": "password_candidates",
            "type": "text",
            "default": "virus\ninfected",
            "description": "List of passwords to try when unpacking an encrypted ZIP file (one per line)."
        }
    ]

    def each(self, target):
        tmpdir = tempdir()

        password_candidates = self.password_candidates.split("\n")

        zf = ZipFile(target)

        namelist = zf.namelist()

        if 'classes.dex' in namelist and 'META-INF/MANIFEST.MF' in namelist:
            self.change_type(target, 'apk')
            self.results = {
                'message': 'File type was changed to apk.'
            }
        else:
            for name in namelist:
                try:
                    filepath = zf.extract(name, tmpdir)
                    if os.path.isfile(filepath):
                        self.add_extracted_file(filepath)
                except RuntimeError:
                    for password in password_candidates:
                        try:
                            filepath = zf.extract(name, tmpdir, pwd=password)
                            if os.path.isfile(filepath):
                                self.add_extracted_file(filepath)
                            break
                        except RuntimeError:
                            pass
                    else:
                        self.log('error', 'Could not extract {} (password not known)'.format(name))

        return True
