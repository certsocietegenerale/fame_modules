import os
import re
import time
import mimetypes
from zipfile import ZipFile, BadZipfile
from shutil import copyfileobj
from urllib import urlopen, urlencode

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError

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

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False


class Joe(ProcessingModule):
    name = "joe"
    description = "Submit the file to Joe Sandbox."
    acts_on = ["executable", "word", "html", "rtf", "excel", "pdf", "apk", "javascript", "jar", "url", "powerpoint"]

    config = [
        {
            'name': 'apikey',
            'type': 'str',
            'description': 'API Key to use to connect to your account.'
        },
        {
            'name': 'base_url',
            'type': 'str',
            'default': 'https://jbxcloud.joesecurity.org/index.php/api/',
            'description': 'URL of the API endpoint.'
        },
        {
            'name': 'analysis_url',
            'type': 'str',
            'default': 'https://jbxcloud.joesecurity.org/analysis/{0}',
            'description': 'URL of an analysis. Must contain "{}" that will be replaced with the analysis ID.'
        },
        {
            'name': 'wait_timeout',
            'type': 'integer',
            'default': 5400,
            'description': "Time in seconds that the module will wait for joe's analysis to be over."
        },
        {
            'name': 'wait_step',
            'type': 'integer',
            'default': 30,
            'description': "Time in seconds between two check of joe's analysis status"
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
        'joe_access': "For users that have access to the Joe Sandbox instance. Will display a link to Joe Sandbox's analysis."
    }

    def initialize(self):
        # Check dependencies
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")
        if not HAVE_IJSON:
            raise ModuleInitializationError(self, "Missing dependency: ijson")
        if not HAVE_BS4:
            raise ModuleInitializationError(self, "Missing dependency: bs4")

    def each_with_type(self, target, file_type):
        # Define base params
        self.joe_params = {
            'apikey': self.apikey,
            'tandc': "1"
        }

        self.results = dict()

        # First, submit the file
        self.submit_file(target, file_type)

        # Wait for analysis to be over
        self.wait_for_analysis()

        # Get report, and extract IOCs
        self.process_report()

        # Get unpacked executables
        self.get_unpacked_executables()

        # Add report URL to results
        self.results['URL'] = self.analysis_url.format(self.joe_params['webid'])

        return True

    def submit_file(self, target, file_type):
        url = self.base_url + 'analysis'

        if self.allow_internet_access:
            inet = "1"
        else:
            inet = "0"

        params = {
            'apikey': (None, self.apikey),
            'tandc': (None, "1"),
            'type': (None, "file"),
            'auto': (None, "1"),
            'inet': (None, inet),
            'ssl': (None, inet),
            'scae': (None, "1"),
            'vbainstr': (None, "1"),
            'comments': (None, 'Submitted via FAME'),
        }

        if file_type == 'url':
            params['type'] = (None, "url")
            params['url'] = (None, target)
        else:
            if file_type == 'apk':
                del params['auto']
                params['android1'] = (None, "1")

            params['sample'] = (os.path.basename(target), open(target, 'rb'), mimetypes.guess_type(target)[0] or 'application/octet-stream')

        r = requests.post(url, files=params)

        if r.status_code != 200:
            raise ModuleExecutionError('could not submit: {0}'.format(r.text))

        results = r.json()
        self.joe_params['webid'] = results['webid']

    def wait_for_analysis(self):
        url = self.base_url + 'analysis/check'

        waited_time = 0
        while waited_time < self.wait_timeout:
            response = requests.post(url, data=self.joe_params)
            status = response.json()['status']

            if status == 'finished':
                # Figure out which run is the most interesting
                self.joe_params['run'] = 0
                detections = response.json()['detections'].rstrip(';').split(';')

                max_score = 0
                for i, score in enumerate(detections):
                    if score > max_score:
                        max_score = score
                        self.joe_params['run'] = i

                break

            time.sleep(self.wait_step)
            waited_time += self.wait_step

        if status != 'finished':
            raise ModuleExecutionError('could not get report before timeout.')

    def process_report(self):
        url = self.base_url + 'analysis/download'

        # Download JSON report to extract IOCs
        params = dict(self.joe_params)
        params['type'] = 'lightjson'

        response = urlopen(url, urlencode(params))

        if response.getcode() != 200:
            self.log('error', 'could not find report for task id {}: {}'.format(self.joe_params['webid'], response.read()))
        else:
            self.extract_iocs(response)

        # Download HTML report to extract execution graph
        params['type'] = 'lighthtml'
        response = urlopen(url, urlencode(params))

        if response.getcode() != 200:
            self.log('error', 'could not find report for task id {}: {}'.format(self.joe_params['webid'], response.read()))
        else:
            tmpdir = tempdir()
            filepath = os.path.join(tmpdir, 'joe_report.html')
            with open(filepath, 'w+b') as fd:
                copyfileobj(response, fd)
                fd.seek(0, 0)
                self.extract_graph(fd)

            self.add_support_file('Report', filepath)

    def get_unpacked_executables(self):
        url = self.base_url + 'analysis/download'

        # Download JSON report to extract IOCs
        params = dict(self.joe_params)
        params['type'] = 'unpackpe'

        response = urlopen(url, urlencode(params))

        if response.getcode() != 200:
            self.log('error', 'could not find unpacked PEs for task id {}: {}'.format(self.joe_params['webid'], response.read()))
        else:
            tmpdir = tempdir()
            filepath = os.path.join(tmpdir, 'unpacked.zip')
            with open(filepath, 'w+b') as fd:
                copyfileobj(response, fd)

            try:
                unpacked_files = []
                zf = ZipFile(filepath)
                for name in zf.namelist():
                    unpacked_files.append(zf.extract(name, tmpdir, pwd='infected'))

                self.register_files('unpacked_executable', unpacked_files)
            except BadZipfile:
                pass

    def extract_url(self, scheme, iocs, request):
        match = re.match(r'(GET|POST) (\S+) .*Host: (\S+)', request, re.DOTALL)
        if match:
            iocs.add("{}://{}{}".format(scheme, match.group(3), match.group(2)))

    def extract_iocs(self, report):
        iocs = set()
        parser = ijson.parse(report)
        lines = ""

        for prefix, event, value in parser:
            if prefix in [
                "analysis.behavior.network.tcp.packet.item.srcip",
                "analysis.behavior.network.tcp.packet.item.dstip",
                "analysis.behavior.network.udp.packet.item.srcip",
                "analysis.behavior.network.udp.packet.item.dstip",
                "analysis.behavior.network.dns.packet.item.name",
            ]:
                if not value.startswith("192.168."):
                    iocs.add(value)
            elif prefix in [
                "analysis.behavior.network.http.packet.item.header",
                "analysis.behavior.network.https.packet.item.header",
                "analysis.behavior.network.sslhttp.packet.item.header",
            ]:
                lines = ""
            elif prefix == "analysis.behavior.network.http.packet.item.header.line.item":
                lines += "{}\n".format(value)
                self.extract_url("http", iocs, lines)
            elif prefix in [
                "analysis.behavior.network.https.packet.item.header.line.item",
                "analysis.behavior.network.sslhttp.packet.item.header.line.item"
            ]:
                lines += "{}\n".format(value)
                self.extract_url("https", iocs, lines)

        for ioc in iocs:
            self.add_ioc(ioc)

    def extract_graph(self, report):
        report = BeautifulSoup(report, 'html.parser')
        graph = report.find(id='behaviorGraph')
        if graph is not None:
            graph = graph.find('svg')
            self.results['graph'] = graph.encode('utf8')
