import os
from fame.core.module import ProcessingModule, ModuleInitializationError
from ..docker_utils import HAVE_DOCKER, docker_client, docker, temp_volume


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
        },
        {
            'name': 'docker_volume_name',
            'type': 'str',
            'default': 'fame_fame-share',
            'description': 'Docker volume name which is to be used for sharing samples with the Docker container of this module.'
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
        tmp = temp_volume(target)

        target = os.path.join(
            os.path.basename(tmp),
            os.path.basename(target)
        )

        if os.getenv("FAME_DOCKER", "0") == "1":
            # mount docker volume instead of host directory
            volumes = {self.docker_volume_name: {'bind': '/data', 'mode': 'ro'}}
        else:
            data_folder_path = os.path.dirname(tmp)
            volumes = {data_folder_path: {'bind': '/data', 'mode': 'ro'}}

        try:
            self.parse_output(docker_client.containers.run(
                'fame/exiftool',
                target,
                volumes=volumes,
                stderr=True,
                remove=True))
        except docker.errors.ContainerError as e:
            self.parse_output(e.stderr)

    def parse_output(self, out):
        # Parse output
        if type(out) is bytes:
            out = out.decode()

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

    def each_with_type(self, target, type_):
        if type_ == "url":
            self.log("info", "Module cannot run on URLs")
            return False

        self.results = []

        # Execute exiftool inside Docker container and parse output
        self.exiftool(target)

        return len(self.results) > 0
