from fame.core.module import ProcessingModule, ModuleInitializationError
from ..docker_utils import HAVE_DOCKER, docker_client, docker


class ExifTool(ProcessingModule):
    name = "exiftool"
    description = "Extract metadata from files with exiftool."

    config = [
        {
            "name": "exclude",
            "type": "text",
            "default": """ExifTool Version Number
File Name
Directory
File Modification Date/Time
File Access Date/Time
File Inode Change Date/Time
File Permissions""",

            "description": "List of properties to exclude from results (one per line)."
        }
    ]

    def initialize(self):
        # Make sure docker is available
        if not HAVE_DOCKER:
            raise ModuleInitializationError(self, "Missing dependency: docker")

        # Properly format exclusion list
        attributes = self.exclude.splitlines()
        self.exclude = []

        for attribute in attributes:
            self.exclude.append(attribute.strip())

        return True

    def exiftool(self, target):
        try:
            self.parse_output(docker_client.containers.run(
                'fame/exiftool',
                'target.file',
                volumes={target: {'bind': '/data/target.file', 'mode': 'ro'}},
                stderr=True,
                remove=True))
        except docker.errors.ContainerError as e:
            self.parse_output(e.stderr)

    def parse_output(self, out):
        out = out.decode('utf-8', errors='replace')

        # Parse output
        for line in out.splitlines():
            parts = line.split(':')
            name = parts[0].strip()
            value = ':'.join(parts[1:]).strip()

            # Warnings should be in the logs
            if name == 'Warning':
                self.log('warning', value)
            # Errors should be in the logs as well
            elif name == 'Error':
                self.log('error', value)
            # Filter every attribute in the exclusion list
            elif name not in self.exclude:
                self.results.append((name, value))

    def each(self, target):
        self.results = []

        # Execute exiftool inside Docker container and parse output
        self.exiftool(target)

        return len(self.results) > 0
