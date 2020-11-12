from io import BytesIO

from fame.core.module import PreloadingModule
from fame.core.config import Config
from fame.common.exceptions import (
    ModuleExecutionError, ModuleInitializationError
)

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class VirusTotalDownload(PreloadingModule):
    name = "virustotal_download"
    description = "Download file from VT and launch new analysis."

    config = [
        {
            'name': 'api_key',
            'description': 'VirusTotal API key, in order to be able to download files.',
            'type': 'str',
            'value': None
        }
    ]

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(
                self, "Missing module dependency: requests")

    def preload(self, target):
        if not self.api_key:
            self.log("warning", "VirusTotal API key not set.")
            return

        params = {'apikey': self.api_key, 'hash': target}
        response = requests.get(
            'https://www.virustotal.com/vtapi/v2/file/download',
            params=params, stream=True
        )

        if response.status_code == 403:
            raise ModuleExecutionError('VirusTotal API Key required')
        elif response.status_code == 404:
            self.log("warning", "File not found on VirusTotal.")
        elif response.status_code == 200:
            self.add_preloaded_file(fd=BytesIO(response.raw.read()))
        else:
            raise ModuleExecutionError(
                "Could not download file. Status: {}".format(
                    response.status_code))
