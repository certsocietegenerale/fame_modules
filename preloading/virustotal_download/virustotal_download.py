from io import BytesIO

from fame.core.module import PreloadingModule
from fame.core.config import Config
from fame.common.exceptions import (
    ModuleExecutionError, ModuleInitializationError,
    MissingConfiguration
)

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class VirusTotalDownload(PreloadingModule):
    name = "virustotal_download"
    description = "Download file from VT and launch new analysis."
    acts_on = ["hash"]

    named_configs = {
        'virustotal': {
            'description': 'VirusTotal API configuration, in order to be able to submit hashes.',
            'config': [
                {
                    'name': 'api_key',
                    'description': 'VirusTotal Intelligence API key.',
                    'type': 'str',
                    'value': None
                }
            ]
        }
    }

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(
                self, "Missing module dependency: requests")

    def preload(self, target):
        config = Config.get(name="virustotal")
        if config:
            try:
                config = config.get_values()

                params = {'apikey': config.api_key, 'hash': target}
                response = requests.get(
                    'https://www.virustotal.com/vtapi/v2/file/download',
                    params=params, stream=True
                )

                if response.status_code == 403:
                    raise ModuleExecutionError('VirusTotal API Key required')
                elif response.status_code == 404:
                    self.log("warning", "File not found on VirusTotal.")
                elif response.status_code == 200:
                    self.add_preloaded_file(target, BytesIO(response.raw.read()))
                    return True
                else:
                    raise ModuleExecutionError(
                        "Could not download file. Status: {}".format(
                            response.status_code))

            except MissingConfiguration:
                raise ModuleInitializationError(
                    'VirusTotal config not set up.')
        else:
            self.log("warning", "VirusTotal config not found.")

        return False
