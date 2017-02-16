import os

from fame.common.utils import list_value, tempdir
from ..vol import Volatility


class MemYara(Volatility):
    name = "mem_yara"
    description = "Run YARA rules on memory dump."

    config = [
        {
            'name': 'rules',
            'type': 'text',
            'description': 'YARA rules file that will be used. When using "include", you should specify the full path.'
        },
        {
            'name': 'ignored_rules',
            'type': 'str',
            'default': '',
            'description': 'Comma-delimited list of rules name that will be ignored.'
        },
    ]

    def initialize(self):
        super(MemYara, self).initialize()

        self.needs_plugin("yarascan")
        self.results = []

    def each_dump(self):
        self.ignored_rules = list_value(self.ignored_rules)
        matched = False

        # Create file containing rules
        tmpdir = tempdir()
        rules_path = os.path.join(tmpdir, 'rules')
        rules = open(rules_path, 'wb')
        rules.write(self.rules)
        rules.close()

        self._volconfig.update("YARA_FILE", rules_path)
        plugin = self.plugins["yarascan"](self._volconfig)

        # code mostly taken from cuckoo
        for o, addr, hit, content in plugin.calculate():
            if hit.rule not in self.ignored_rules:
                if o is None:
                    owner = "Unknown Kernel Memory"
                elif o.obj_name == "_EPROCESS":
                    owner = "Process {0} Pid {1}".format(o.ImageFileName, o.UniqueProcessId)
                else:
                    owner = "{0}".format(o.BaseDllName)

                hexdump = "".join(
                    "{0:#010x}  {1:<48}  {2}\n".format(addr + o, h, ''.join(c))
                    for o, h, c in self._volutils.Hexdump(content[0:64]))

                new = {
                    "rule": hit.rule,
                    "owner": owner,
                    "hexdump": hexdump,
                }

                self.results.append(new)
                self.add_tag(hit.rule)
                matched = True

        return matched
