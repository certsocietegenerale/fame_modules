import os
from zipfile import ZipFile

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir


class LegacyZip(ProcessingModule):
    name = "legacyzip"
    description = "Extract files from ZIP archive."
    acts_on = "zip"

    config = [
        {
            "name": "password_candidates",
            "type": "text",
            "default": "virus\ninfected",
            "description": "List of passwords to try when unpacking an encrypted ZIP file (one per line)."
        },
        {
            "name": "maximum_extracted_files",
            "type": "integer",
            "default": 5,
            "description": "If there are more files than this value in the archive, files will not be extracted."
        },
        {
            "name": "maximum_automatic_analyses",
            "type": "integer",
            "default": 1,
            "description": "If there are more files than this value in the archive, no analyses will be automatically created for extracted files."
        }
    ]

    def each(self, target):
        self.results = {
            'warnings': []
        }

        tmpdir = tempdir()

        password_candidates = self.password_candidates.split("\n")

        zf = ZipFile(target)

        namelist = zf.namelist()

        if 'classes.dex' in namelist and 'META-INF/MANIFEST.MF' in namelist:
            self.change_type(target, 'apk')
            self.results['warnings'].append('File type was changed to apk, files were not extracted.')
        else:
            should_extract = len(namelist) <= self.maximum_extracted_files
            should_analyze = len(namelist) <= self.maximum_automatic_analyses

            if should_extract:
                for name in namelist:
                    try:
                        filepath = zf.extract(name, tmpdir)
                        if os.path.isfile(filepath):
                            self.add_extracted_file(filepath, automatic_analysis=should_analyze)
                    except RuntimeError:
                        for password in password_candidates:
                            try:
                                filepath = zf.extract(name, tmpdir, pwd=password.rstrip())
                                if os.path.isfile(filepath):
                                    self.add_extracted_file(filepath, automatic_analysis=should_analyze)
                                break
                            except RuntimeError:
                                pass
                        else:
                            self.results['warnings'].append('Could not extract {} (password not known)'.format(name))

                if not should_analyze:
                    self.results['warnings'].append(
                        "Archive contains more than {} files ({}), so no analysis was automatically created.".format(
                            self.maximum_automatic_analyses, len(namelist)))
            else:
                self.results['warnings'].append(
                    "Archive contains more than {} files ({}), so they were not extracted.".format(
                        self.maximum_extracted_files, len(namelist)))

        if self.results['warnings']:
            self.results['files'] = namelist
        else:
            self.results = None

        return True
