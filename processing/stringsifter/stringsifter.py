from subprocess import Popen, PIPE
from shutil import which
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class StringSifter(ProcessingModule):
    name = "stringsifter"
    description = "Ranks strings based on their relevance for malware analysis."

    config = [
        {
            "name": "min_len",
            "type": "integer",
            "default": 4,
            "description": "Show strings that are at least min_len characters long (default: 4)."
        },
        {
            "name": "show_scores",
            "type": "bool",
            "default": False,
            "description": "Display rank scores within output (default: scores not displayed)."
        },
        {
            "name": "limit",
            "type": "integer",
            "default": None,
            "description": "Limit output to the top `limit` ranked strings (default: no limit)."
        }
    ]

    def initialize(self):
        if which("flarestrings") is None:
            raise ModuleInitializationError(self, "Missing dependency: flarestrings")
        if which("rank_strings") is None:
            raise ModuleInitializationError(self, "Missing dependency: rank_strings")

        return True

    def each(self, target):
        flarestrings_cmd = ("flarestrings", "-n", str(self.min_len), target)
        rank_strings_cmd = ["rank_strings"]

        if self.show_scores:
            rank_strings_cmd.append("--scores")
        if self.limit is not None:
            rank_strings_cmd += ("--limit", str(self.limit))

        flarestrings_process = Popen(flarestrings_cmd, stdout=PIPE)
        rank_strings_process = Popen(rank_strings_cmd,
                                     stdin=flarestrings_process.stdout,
                                     stdout=PIPE)
        flarestrings_process.stdout.close()
        rank_strings_output = rank_strings_process.communicate()[0]

        if rank_strings_process.returncode != 0:
            return False

        self.results = {
            "strings": rank_strings_output.decode("utf-8").rstrip("\n").split("\n")
        }

        return len(self.results["strings"]) > 0
