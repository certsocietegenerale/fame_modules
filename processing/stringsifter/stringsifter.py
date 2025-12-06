from fame.core.module import ProcessingModule, ModuleInitializationError
from ..docker_utils import HAVE_DOCKER, docker_client, docker
import re


class StringSifter(ProcessingModule):
    name = "stringsifter"
    description = "Ranks strings based on their relevance for malware analysis."

    config = [
        {
            "name": "min_len",
            "type": "integer",
            "default": 4,
            "description": "Show strings that are at least min_len characters long (default: 4).",
        },
        {
            "name": "show_scores",
            "type": "bool",
            "default": False,
            "description": "Display rank scores within output (default: scores not displayed).",
        },
        {
            "name": "limit",
            "type": "integer",
            "default": None,
            "description": "Limit output to the top `limit` ranked strings (default: no limit).",
        },
    ]

    def initialize(self):
        if not HAVE_DOCKER:
            raise ModuleInitializationError(self, "Missing dependency: docker")

        return True

    def parse_output(self, out):
        out = out.decode("utf-8", errors="replace")
        self.results = {"strings": [o.strip() for o in out.splitlines() if o.strip()]}

    def each_with_type(self, target, file_type):
        if file_type != "url":
            try:
                self.parse_output(
                    docker_client.containers.run(
                        "fame/stringsifter",
                        "target.file",
                        volumes={target: {"bind": "/data/target.file", "mode": "ro"}},
                        environment={
                            "min_len": int(self.min_len),
                            "limit": int(self.limit or 0),
                            "show_scores": bool(self.show_scores),
                        },
                        stderr=True,
                        remove=True,
                    )
                )
            except (docker.errors.ContainerError, docker.errors.APIError) as e:
                if hasattr(e, "stderr"):
                    self.log("error", e.stderr)
                elif hasattr(e, "explanation"):
                    self.log("error", e.explanation)

        return len(self.results["strings"]) > 0
