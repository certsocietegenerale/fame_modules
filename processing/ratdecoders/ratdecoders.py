import json

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


try:
    from malwareconfig import fileparser
    from malwareconfig.modules import __decoders__, __preprocessors__

    HAVE_RATDECODERS = True
except ImportError:
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
            raise ModuleInitializationError(self, "Missing dependency: malwareconfig")

    def each(self, target):
        file_info = fileparser.FileParser(file_path=target)

        # Check for a valid decoder and then parse
        if file_info.malware_name in __decoders__:
            module = __decoders__[file_info.malware_name]["obj"]()
            module.set_file(file_info)
            module.get_config()

            self.add_probable_name(file_info.malware_name)
            self.add_extraction(
                "{} Configuration".format(file_info.malware_name), json.dumps(module.config, indent=2)
            )

            return True

        return False
