import os
import hashlib
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from fame.common.utils import tempdir

try:
    from oletools import olevba

    HAVE_OLETOOLS = True
except ImportError:
    HAVE_OLETOOLS = False


def str_reverse(match):
    return match.group(1)[::-1]


class OfficeMacros(ProcessingModule):
    name = "office_macros"
    description = "Extract and analyze Office macros."
    acts_on = ["word", "html", "excel", "powerpoint"]

    def initialize(self):
        if not HAVE_OLETOOLS:
            raise ModuleInitializationError(self, "Missing dependency: oletools")

        self.tmpdir = tempdir()

    def each(self, target):
        self.results = {
            'macros': u'',
            'analysis': {
                'AutoExec': [],
                'Suspicious': [],
                'IOC': [],
                'Hex String': [],
                'Base64 String': [],
                'Dridex String': [],
                'VBA String': [],
                'Form String': []
            }
        }

        vba = olevba.VBA_Parser(target)

        # code is inspired by 'reveal' method in olevba
        analysis = vba.analyze_macros(show_decoded_strings=True)

        # extract all macros code
        havemacros = False
        for (_, _, _, vba_code) in vba.extract_all_macros():
            self.results['macros'] += vba_code.decode('utf-8', errors='replace') + '\n'
            havemacros = True

        if havemacros:
            mname = hashlib.sha256(self.results['macros']).hexdigest()
            newfile = "%s/macros_%s.vba" % (self.tmpdir,mname)
            with open(newfile,'wb') as f:
                f.write(self.results['macros'])
            self.add_extracted_file(newfile)

        # extract all form strings
        for (_, _, form_string) in vba.extract_form_strings():
            self.results['analysis']['Form String'].append(form_string.decode('utf-8', errors='replace'))

        # extract all analysis
        if analysis:
            analysis = sorted(analysis, key=lambda type_decoded_encoded: len(type_decoded_encoded[2]), reverse=True)
            for kw_type, keyword, description in analysis:
                # and replace obfuscated strings
                if kw_type in ['VBA string', 'Dridex string', 'Base64 String', 'Hex String']:
                    if olevba.is_printable(keyword):
                        keyword = keyword.replace('"', '""')
                        self.results['macros'] = self.results['macros'].replace(description, '"%s"' % keyword)
                        self.results['analysis'][kw_type].append((keyword.decode('utf-8', errors='replace'), description.decode('utf-8', errors='replace')))
                else:
                    self.results['analysis'][kw_type].append((keyword, description))

        return len(self.results['macros']) > 0
