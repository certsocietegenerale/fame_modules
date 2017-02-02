import os
from zipfile import ZipFile
from tempfile import mkdtemp
from fame.core.module import ProcessingModule


class Zip(ProcessingModule):
    name = "zip"
    description = "Extract files from ZIP archive."
    acts_on = "zip"

    def each(self, target):
        tempdir = mkdtemp()

        zf = ZipFile(target)
        for name in zf.namelist():
            try:
                filepath = zf.extract(name, tempdir)
                if os.path.isfile(filepath):
                    self.add_extracted_file(filepath)
            except RuntimeError:
                for password in ['virus', 'infected']:
                    try:
                        filepath = zf.extract(name, tempdir, pwd=password)
                        if os.path.isfile(filepath):
                            self.add_extracted_file(filepath)
                        break
                    except RuntimeError:
                        pass
                else:
                    self.log('error', 'Could not extract {}'.format(name))

        return True
