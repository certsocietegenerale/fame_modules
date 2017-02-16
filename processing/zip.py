import os
from zipfile import ZipFile

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir


class Zip(ProcessingModule):
    name = "zip"
    description = "Extract files from ZIP archive."
    acts_on = "zip"

    def each(self, target):
        tmpdir = tempdir()

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
                    for password in ['virus', 'infected']:
                        try:
                            filepath = zf.extract(name, tmpdir, pwd=password)
                            if os.path.isfile(filepath):
                                self.add_extracted_file(filepath)
                            break
                        except RuntimeError:
                            pass
                    else:
                        self.log('error', 'Could not extract {}'.format(name))

        return True
