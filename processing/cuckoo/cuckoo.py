import os
import time
from urllib.parse import urljoin
from urllib.request import urlopen

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    import ijson
    HAVE_IJSON = True
except ImportError:
    HAVE_IJSON = False

from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError
from fame.core.module import ProcessingModule


class Cuckoo(ProcessingModule):
    name = "cuckoo"
    description = "Submit the file to Cuckoo Sandbox."
    acts_on = ["executable", "word", "html", "rtf", "excel", "pdf", "javascript", "jar", "url", "powerpoint", "vbs"]
    generates = ["memory_dump"]

    config = [
        {
            'name': 'api_endpoint',
            'type': 'str',
            'default': 'http://127.0.0.1:8090/',
            'description': "URL of Cuckoo's API endpoint."
        },
        {
            'name': 'web_endpoint',
            'type': 'str',
            'default': 'http://127.0.0.1:8000/',
            'description': "URL of Cuckoo's web interface."
        },
        {
            'name': 'wait_timeout',
            'type': 'integer',
            'default': 5400,
            'description': 'Time in seconds that the module will wait for cuckoo analysis to be over.'
        },
        {
            'name': 'wait_step',
            'type': 'integer',
            'default': 30,
            'description': "Time in seconds between two check of cuckoo's analysis status"
        },
        {
            'name': 'analysis_time',
            'type': 'integer',
            'default': 300,
            'description': 'Time (in seconds) during which the sample will be analyzed.',
            'option': True
        },
        {
            'name': 'allow_internet_access',
            'type': 'bool',
            'default': True,
            'description': 'This allows full Internet access to the VM running the malware.',
            'option': True
        }
    ]

    permissions = {
        'cuckoo_access': "For users that have access to the Cuckoo instance. Will display a link to Cuckoo's analysis."
    }

    def initialize(self):
        # Check dependencies
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")
        if not HAVE_IJSON:
            raise ModuleInitializationError(self, "Missing dependency: ijson")

    def each_with_type(self, target, file_type):
        # Set root URLs
        self.results = dict()

        options = self.define_options()

        # First, submit the file / URL
        if file_type == 'url':
            self.submit_url(target, options)
        else:
            self.submit_file(target, options)

        # Wait for analysis to be over
        self.wait_for_analysis()

        # Get report, and tag signatures
        self.process_report()

        # Get back memory dump
        self.get_memory_dump()

        # Get back PCAP file
        self.get_pcap()

        # Add report URL to results
        self.results['URL'] = urljoin(self.web_endpoint, "/analysis/{}/summary/".format(self.task_id))

        return True

    def define_options(self):
        if self.allow_internet_access:
            route = "internet"
        else:
            route = "drop"

        return {
            'timeout': self.analysis_time,
            'enforce_timeout': True,
            'options': 'route={}'.format(route)
        }

    def submit_file(self, filepath, options):
        url = urljoin(self.api_endpoint, '/tasks/create/file')
        fp = open(filepath, 'rb')

        response = requests.post(url, files={'file': fp}, data=options)
        self.task_id = response.json()['task_id']

    def submit_url(self, target_url, options):
        url = urljoin(self.api_endpoint, '/tasks/create/url')
        options['url'] = target_url
        response = requests.post(url, data=options)
        self.task_id = response.json()['task_id']

    def wait_for_analysis(self):
        url = urljoin(self.api_endpoint, '/tasks/view/{0}'.format(self.task_id))

        waited_time = 0
        while waited_time < self.wait_timeout:
            response = requests.get(url)
            status = response.json()['task']['status']

            if status == 'reported':
                break

            time.sleep(self.wait_step)
            waited_time += self.wait_step

        if status != 'reported':
            raise ModuleExecutionError('could not get report before timeout.')

    def process_report(self):
        url = urljoin(self.api_endpoint, '/tasks/report/{0}'.format(self.task_id))
        response = urlopen(url)

        if response.getcode() != 200:
            self.log('error', 'could not find report for task id {0}'.format(self.task_id))
        else:
            self.extract_info(response)

    def extract_info(self, report):
        parser = ijson.parse(report)
        self.results['signatures'] = []
        signature = dict()

        for prefix, event, value in parser:
            if prefix == "signatures.item" and event == "end_map":
                self.results['signatures'].append(signature)
                signature = dict()
            elif prefix == "signatures.item.name":
                signature['name'] = value
                self.add_tag(value)
            elif prefix == "signatures.item.severity":
                signature['severity'] = value
            elif prefix == "signatures.item.description":
                signature['description'] = value
            elif prefix == "info.score":
                self.results['score'] = float(value)
            elif prefix in ["network.domains.item.domain", "network.hosts.item.ip", "network.http.item.uri"]:
                if value not in ["8.8.8.8", "8.8.4.4"]:
                    self.add_ioc(value)

    def get_memory_dump(self):
        url = urljoin(self.web_endpoint, '/full_memory/{0}/'.format(self.task_id))
        response = requests.get(url, stream=True)

        self.register_response_as('memory_dump', response)

    def get_pcap(self):
        url = urljoin(self.api_endpoint, '/pcap/get/{0}'.format(self.task_id))
        response = requests.get(url, stream=True)

        self.register_response_as('pcap', response)

    def register_response_as(self, type, response, zipped=False):
        if response.status_code != 200:
            self.log('error', 'could not find {0} for task id {1}'.format(type, self.task_id))
        else:
            tmpdir = tempdir()
            filename = os.path.join(tmpdir, 'cuckoo_response')
            f = open(filename, "wb")

            for chunk in response.iter_content(1024):
                f.write(chunk)

            f.close()
            self.register_files(type, filename)
