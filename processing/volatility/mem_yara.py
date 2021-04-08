import os
from enum import Enum

from fame.common.utils import list_value, tempdir
from fame.common.exceptions import ModuleInitializationError
from .vol import VolatilityModule

try:
    from volatility.plugins import yarascan
    from volatility.plugins.windows import pslist

    HAVE_VOLATILITY = True
except ImportError:
    HAVE_VOLATILITY = False


try:
    from hexdump import hexdump

    HAVE_HEXDUMP = True
except ImportError:
    HAVE_HEXDUMP = False


class YaraScanResults(Enum):
    Offset = 0
    Rule = 1
    Component = 2
    Value = 3


class MemYara(VolatilityModule):
    name = "mem_yara"
    description = "Run YARA rules on memory dump."

    config = [
        {
            "name": "rules",
            "type": "text",
            "description": 'YARA rules file that will be used. When using "include", you should specify the full path.',
        },
        {
            "name": "ignored_rules",
            "type": "str",
            "default": "",
            "description": "Comma-delimited list of rules name that will be ignored.",
        },
    ]

    def initialize(self):
        super(MemYara, self).initialize()

        # Check dependencies
        if not HAVE_VOLATILITY:
            raise ModuleInitializationError(self, "Missing dependency: volatility")

        if not HAVE_HEXDUMP:
            raise ModuleInitializationError(self, "Missing dependency: hexdump")

        self.needs_plugin("windows.vadyarascan.VadYaraScan")
        self.results = []

    def each_dump(self):
        self.ignored_rules = list_value(self.ignored_rules)

        # Create file containing rules
        tmpdir = tempdir()
        rules_path = os.path.join(tmpdir, "rules")
        rules = open(rules_path, "w")
        rules.write(self.rules)
        rules.close()

        # Build a VadYaraScan plugin instance
        vad_yara_scan = self.configure_plugin(
            "windows.vadyarascan.VadYaraScan", yara_file="file://{}".format(rules_path)
        )

        rules = yarascan.YaraScan.process_yara_options(dict(vad_yara_scan.config))
        for task in pslist.PsList.list_processes(
            context=vad_yara_scan.context,
            layer_name=vad_yara_scan.config["primary"],
            symbol_table=vad_yara_scan.config["nt_symbols"],
        ):
            layer_name = task.add_process_layer()
            layer = vad_yara_scan.context.layers[layer_name]
            for offset, rule_name, name, value in layer.scan(
                context=vad_yara_scan.context,
                scanner=yarascan.YaraScanner(rules=rules),
                sections=vad_yara_scan.get_vad_maps(task),
            ):
                if rule_name not in self.ignored_rules:
                    self.results.append(
                        {
                            "rule": rule_name,
                            "owner": task.ImageFileName.cast(
                                "string", max_length=task.ImageFileName.vol.count, errors="replace"
                            ),
                            "pid": task.UniqueProcessId,
                            "variable": name,
                            "hexdump": hexdump(value, result="return"),
                        }
                    )
                    self.add_tag(rule_name)

        return len(self.results) > 0
