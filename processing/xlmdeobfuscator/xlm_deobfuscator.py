import re
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


try:
    from XLMMacroDeobfuscator.deobfuscator import process_file

    HAVE_XLMMACRODEOBFUSCATOR = True
except ImportError:
    HAVE_XLMMACRODEOBFUSCATOR = False


def str_reverse(match):
    return match.group(1)[::-1]


class XLMDeobfuscator(ProcessingModule):
    name = "xlm_deobfuscator"
    description = "Extract and analyze Excel 4.0 macros."
    acts_on = ["excel", "xls", "xlsm"]

    def initialize(self):
        if not HAVE_XLMMACRODEOBFUSCATOR:
            raise ModuleInitializationError(self, "Missing dependency: XLMMacroDeobfuscator")

    def each(self, target):
        self.results = {
            'macros': u'',
            'analysis': {
                'IOC': [],
            }
        }

        processed = process_file(target,
                                 noninteractive=True,
                                 noindent=True,
                                 output_formula_format='[[INT-FORMULA]]',
                                 return_deobfuscated=True)

        self.results["macros"] = "\n".join(processed)

        regex_url = r"\w+:(\/\/)[^\s]+"
        reg = re.compile(regex_url)
        for record in processed:
            for match in reg.finditer(record):
                self.add_ioc(match.group(0))
                self.results["IOC"].append(match.group(0))

        return len(self.results) > 0
