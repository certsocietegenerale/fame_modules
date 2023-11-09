from fame.core.module import ProcessingModule, ModuleInitializationError
from ..docker_utils import HAVE_DOCKER, docker_client, docker
import re


class QrCodeExtractor(ProcessingModule):
    name = "qr_extractor"
    description = "find QRcodes in images and decode them"
    acts_on = ["png", "jpeg", "bmp", "webp", "avif"]
    triggered_by = "*_preview"
    config = []

    def initialize(self):
        # Make sure docker is available
        if not HAVE_DOCKER:
            raise ModuleInitializationError(self, "Missing dependency: docker")

    def parse_output(self, out):
        out = out.decode("utf-8", errors="replace")
        for line in out.splitlines():
            if re.match("^https?:", line, re.UNICODE | re.IGNORECASE):
                self.add_ioc(line)
            else:
                if not self.results:
                    self.results = []
                self.results.append(line)

    def each_with_type(self, target, file_type):
        if file_type != "url":
            try:
                self.parse_output(
                    docker_client.containers.run(
                        "fame/qr_extractor",
                        "target.file",
                        volumes={target: {"bind": "/data/target.file", "mode": "ro"}},
                        stderr=True,
                        remove=True,
                    )
                )
            except (docker.errors.ContainerError, docker.errors.APIError) as e:
                if hasattr(e, "stderr"):
                    self.log("error", e.stderr)
                elif hasattr(e, "explanation"):
                    self.log("error", e.explanation)

        return True
