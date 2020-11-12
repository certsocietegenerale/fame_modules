import json
from base64 import b64decode

from . import APKPlugin


def is_url(string):
    return string.startswith('http')


def is_package(string):
    return '.' in string


class BankBot(APKPlugin):
    name = "bankbot"
    extraction = "BankBot Configuration"
    probable_name = "BankBot"

    def find_targets_method(self):
        invisible_log = list(self.vm_analysis.find_strings('INVISIBLE-LOG'))
        bank_clients = list(self.vm_analysis.find_strings("SEARCH BANK CLIENT'S"))

        if len(invisible_log) == 0 or len(bank_clients) == 0:
            return None

        for invisible_cls, invisible_method in invisible_log[0].get_xref_from():
            for bank_cls, bank_method in bank_clients[0].get_xref_from():
                if (
                    invisible_method.get_class_name() == bank_method.get_class_name() and
                    invisible_method.get_name() == bank_method.get_name()
                ):
                    self.targets_class = invisible_cls
                    self.targets_method = invisible_method

                    return True

        return False

    def get_strings_from_method(self, method, test_func):
        results = []

        for inst in method.get_instructions():
            if inst.get_name() == 'const-string':
                string = inst.get_output().split(',')[-1].strip(" '")
                if test_func(string):
                    results.append(string)
                else:
                    try:
                        string = b64decode(string)
                        if test_func(string):
                            results.append(string)
                    except Exception:
                        pass

        return results

    def run(self, module):
        if not self.find_targets_method():
            return None

        targets = self.get_strings_from_method(self.targets_method, is_package)

        c2s = []
        for method in self.targets_class.get_methods():
            if not method.is_external():
                c2s += self.get_strings_from_method(method.get_method(), is_url)

        c2s = list(set(c2s))

        if c2s or targets:
            module.add_ioc(c2s, ['bankbot', 'c2'])
            return json.dumps({'targets': targets, 'c2s': c2s}, indent=2)

        return None
