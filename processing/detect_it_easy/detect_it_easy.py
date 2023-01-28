from fame.core.module import ProcessingModule, ModuleInitializationError
from ..docker_utils import HAVE_DOCKER, docker_client, docker


class DetectItEasy(ProcessingModule):
    name = "detect_it_easy"
    description = (
        "Program for determining types of files for Windows, Linux and MacOS. "
    )

    def initialize(self):
        # Make sure docker is available
        if not HAVE_DOCKER:
            raise ModuleInitializationError(self, "Missing dependency: docker")
        return True

    def detect_it_easy(self, target):
        try:
            self.parse_output(
                docker_client.containers.run(
                    "fame/diec",
                    "/data/target.file",
                    volumes={target: {"bind": "/data/target.file", "mode": "ro"}},
                    stderr=True,
                    remove=True,
                )
            )
        except (docker.errors.ContainerError, docker.errors.APIError) as e:
            self.parse_output(e.stderr)

    def parse_output(self, out):
        out = out.decode("utf-8", errors="replace")

        # Parse output
        for line in out.splitlines():
            parts = line.split(":")
            name = parts[0].strip()
            value = ":".join(parts[1:]).strip()

            # Warnings should be in the logs
            if name == "Warning":
                self.log("warning", value)
            # Errors should be in the logs as well
            elif name == "Error":
                self.log("error", value)
            # Filter every attribute in the exclusion list
            else:
                self.results.append((name, value))

    def each_with_type(self, target, file_type):
        self.results = []

        if file_type != "url":
            # Execute diec inside Docker container and parse output
            self.detect_it_easy(target)

        return len(self.results) > 0
