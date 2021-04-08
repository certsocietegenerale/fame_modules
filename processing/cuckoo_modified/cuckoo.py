import os
import time
import zipfile
from urllib.request import urlopen, urlretrieve

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


class CuckooModified(ProcessingModule):
    name = "cuckoo_modified"
    description = "Submit the file to Cuckoo Sandbox (cuckoo-modified version)."
    acts_on = ["executable", "word", "html", "rtf", "excel", "pdf", "javascript", "jar", "url", "powerpoint", "vbs"]
    generates = ["memory_dump", "pcap"]

    config = [
        {
            'name': 'host',
            'type': 'str',
            'default': '127.0.0.1',
            'description': 'Hostname or IP address of the Cuckoo Sandbox instance.'
        },
        {
            'name': 'api_port',
            'type': 'integer',
            'default': 8090,
            'description': 'Port of the API listener.'
        },
        {
            'name': 'web_port',
            'type': 'integer',
            'default': 8000,
            'description': 'Port of the web interface.'
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
        self.base_url = 'http://{0}:{1}'.format(self.host, self.api_port)
        self.web_base_url = 'http://{0}:{1}'.format(self.host, self.web_port)

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

        # Store light report
        self.store_report_summary()

        # Get back PCAP file, unused right now
        # self.get_pcap()

        # Get back memory dump
        self.get_memory_dump()

        # Add report URL to results
        self.results['URL'] = "{}/analysis/{}/".format(self.web_base_url, self.task_id)

        return True

    def define_options(self):
        if self.allow_internet_access:
            tag = "internet_access"
        else:
            tag = "no_internet"

        return {
            'timeout': self.analysis_time,
            'enforce_timeout': True,
            'tags': tag
        }

    def submit_file(self, filepath, options):
        url = self.base_url + '/tasks/create/file'
        fp = open(filepath, 'rb')

        response = requests.post(url, files={'file': fp}, data=options)
        self.task_id = response.json()['task_ids'][0]

    def submit_url(self, target_url, options):
        url = self.base_url + '/tasks/create/url'
        options['url'] = target_url
        response = requests.post(url, data=options)
        self.task_id = response.json()['task_id']

    def wait_for_analysis(self):
        url = self.base_url + '/tasks/view/{0}'.format(self.task_id)

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

    def store_report_summary(self):
        url = self.web_base_url + '/filereport/{}/htmlsummary/'.format(self.task_id)
        tmpdir = tempdir()
        filepath = urlretrieve(url, os.path.join(tmpdir, 'cuckoo_report.html'))[0]
        self.add_support_file('Report', filepath)

    def process_report(self):
        url = self.web_base_url + '/api/tasks/get/iocs/{0}'.format(self.task_id)
        response = urlopen(url)

        if response.getcode() != 200:
            self.log('error', 'could not find report for task id {0}'.format(self.task_id))
        else:
            self.extract_info(response)

    def extract_info(self, report):
        # First, build an array with every antivirus information that might be
        # of interrest
        av_prefixes = []
        for av in self._analysis._file['antivirus']:
            av_prefixes.append('data.signatures.item.data.item.{}'.format(av))

        parser = ijson.parse(report)
        self.results['signatures'] = []
        signature = dict()

        for prefix, event, value in parser:
            if prefix == "data.signatures.item" and event == "end_map":
                self.results['signatures'].append(signature)
                signature = dict()
            elif prefix == "data.signatures.item.name":
                signature['name'] = value
                self.add_tag(value)
            elif prefix == "data.signatures.item.severity":
                signature['severity'] = value
            elif prefix == "data.signatures.item.description":
                signature['description'] = value
            elif ('name' in signature
                  and signature['name'] == 'antivirus_virustotal'
                  and prefix in av_prefixes):
                self._analysis._file.update_value(['antivirus', prefix.split('.')[-1]], value)
            elif prefix == "data.malfamily":
                self.results['classification'] = value
            elif prefix == "data.malscore":
                self.results['score'] = str(value)
            elif prefix in ["data.network.domains.item.domain", "data.network.hosts.item.ip", "data.network.traffic.http.item.uri"]:
                self.add_ioc(value)

    def get_pcap(self):
        url = self.base_url + '/pcap/get/{0}'.format(self.task_id)
        response = requests.get(url, stream=True)

        self.register_response_as('pcap', response)

    def get_memory_dump(self):
        url = self.web_base_url + '/full_memory/{0}/'.format(self.task_id)
        response = requests.get(url, stream=True)

        self.register_response_as('memory_dump', response, zipped=True)

    def register_response_as(self, type, response, zipped=False):
        if response.status_code != 200:
            self.log('error', 'could not find {0} for task id {1}'.format(type, self.task_id))
        else:
            tmpdir = tempdir()
            if zipped:
                f = open(os.path.join(tmpdir, 'zip'), 'a+b')
            else:
                filename = os.path.join(tmpdir, 'cuckoo_response')
                f = open(filename, "wb")

            for chunk in response.iter_content(1024):
                f.write(chunk)

            if zipped:
                f.seek(0)
                z = zipfile.ZipFile(f)
                for name in z.namelist():
                    filename = z.extract(name, tmpdir)
                    self.register_files(type, filename)
                f.close()
            else:
                f.close()
                self.register_files(type, filename)
