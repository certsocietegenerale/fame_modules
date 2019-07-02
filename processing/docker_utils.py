import os
from shutil import copy

from fame.common.utils import tempdir

try:
    import docker
    docker_client = docker.from_env()
    HAVE_DOCKER = True
except Exception:
    HAVE_DOCKER = False
    docker_client = None
    docker = None


def temp_volume(target):
    """Create a temporary directory and copy the target to it.

    Meant to be mounted inside the Docker container to send the target and get the results."""
    tmp = tempdir()

    os.makedirs(os.path.join(tmp, 'output'))
    copy(target, os.path.join(tmp, os.path.basename(target)))

    return tmp
