import os
import sys
import importlib

from fame.core.module import ProcessingModule
from fame.common.constants import VENDOR_ROOT
from fame.common.exceptions import ModuleInitializationError


try:
    sys.path.append(os.path.join(VENDOR_ROOT, 'RATDecoders'))
    from decoders import DarkComet
    HAVE_RATDECODERS = True
except:
    HAVE_RATDECODERS = False


try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


class RATDecoders(ProcessingModule):

    name = "rat_decoders"
    description = "Run rat_decoders on unpacked executables in order to detect known malware families and extract their configurations."
    acts_on = "unpacked_executable"

    def initialize(self):
        if not HAVE_YARA:
            raise ModuleInitializationError(self, "Missing dependency: yara")
        if not HAVE_RATDECODERS:
            raise ModuleInitializationError(self, "Missing dependency: RATDecoders")

        self.results = {}

    def yara_scan(self, data):
        rules = yara.compile(os.path.join(VENDOR_ROOT, 'RATDecoders', 'malwareconfig', 'yaraRules', 'yaraRules.yar'))

        matches = rules.match(data=data)
        if len(matches) > 0:
            return str(matches[0])
        else:
            return None

    def decode(self, family, data):
        module = importlib.import_module('decoders.{0}'.format(family))

        return module.config(data)

    def each(self, target):
        with open(target, 'r') as f:
            data = f.read()
            family = self.yara_scan(data)

            if family:
                config = self.decode(family, data)

                if config:
                    self.add_probable_name(family)
                    self.results[os.path.basename(target).replace('.', '_')] = {
                        'name': family,
                        'config': config
                    }
                    return True

        return False
