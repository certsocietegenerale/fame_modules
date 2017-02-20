import json
from base64 import b64decode

from . import APKPlugin


def is_url(string):
    return string.startswith('http')


def is_package(string):
    return '.' in string


class MazaInBot(APKPlugin):
    name = "maza-in_bot"
    extraction = "maza-in Bot Configuration"
    probable_name = "maza-in Bot"

    def find_targets_method(self):
        invisible_log = self.vm_analysis.get_tainted_variables().get_string('INVISIBLE-LOG')
        bank_clients = self.vm_analysis.get_tainted_variables().get_string("SEARCH BANK CLIENT'S")

        if invisible_log is None or bank_clients is None:
            return None

        for path in invisible_log.get_paths():
            # We get the method info using the payh idx
            method = self.vm.CM.get_method_ref(path[1])

            for path in bank_clients.get_paths():
                method2 = self.vm.CM.get_method_ref(path[1])

                if ((method.get_class_name() == method2.get_class_name()) and
                   (method.get_name() == method2.get_name())):
                    self.targets_class = method.get_class_name()
                    self.targets_method = method.get_name()
                    self.targets_proto = method.get_descriptor()

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
                    except:
                        pass

        return results

    def run(self, module):
        if not self.find_targets_method():
            return None

        for cls in self.vm.get_classes():
            if self.targets_class in cls.get_name():
                self.targets_class = cls
                break

        c2s = []
        for method in self.targets_class.get_methods():
            if method.name == self.targets_method and method.proto == self.targets_proto:
                targets = self.get_strings_from_method(method, is_package)
            else:
                c2s += self.get_strings_from_method(method, is_url)

        c2s = list(set(c2s))
        module.add_ioc(c2s, ['maza-in', 'c2'])

        return json.dumps({'targets': targets, 'c2s': c2s}, indent=2)
