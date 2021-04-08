import os
import re
import io
import time
import mimetypes
from zipfile import ZipFile, BadZipfile
from shutil import copyfileobj
from urllib.request import urlopen
from urllib.parse import urlencode

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError

from fame.core.file import File

try:
    from jbxapi import JoeSandbox, JoeException
    HAVE_JBXAPI = True
except ImportError:
    HAVE_JBXAPI = False

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
        },
        {
            'name': 'force_submit',
            'type': 'bool',
            'default': True,
            'description': 'Always submit samples even if they have already been processed (based on sha256)',
            'option': True
        }

    ]

    permissions = {
        'joe_access': "For users that have access to the Joe Sandbox instance. Will display a link to Joe Sandbox's analysis."
    }

    def initialize(self):
        # Check dependencies
        if not HAVE_JBXAPI:
            raise ModuleInitializationError(self, "Missing dependency: jbxapi")
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")
        if not HAVE_IJSON:
            raise ModuleInitializationError(self, "Missing dependency: ijson")
        if not HAVE_BS4:
            raise ModuleInitializationError(self, "Missing dependency: bs4")


    def each_with_type(self, target, file_type):
        self.joe = JoeSandbox(apikey=self.apikey, accept_tac=True)
        self.analysis_url = "https://jbxcloud.joesecurity.org/analysis/{}/0/html"
        self.results = dict()
        analysis = ""
        try:
            if file_type == 'url':
                analysis = self.joe.analysis_search(target)
            else:
                sha256 = ""
                basename = os.path.basename(target)
                with open(target, 'r+b') as f:
                    filef = File(filename=basename, stream=f)
                    sha256 = filef['sha256']
                analysis = self.joe.analysis_search(sha256)
            if not self.force_submit and len(analysis):
                self.webid = analysis[0]['webid']
                analysis_info = self.joe.analysis_info(self.webid)
                self.analysisid = analysis_info["analysisid"]
            else:
                data = self.submit_file(target, file_type)
                self.submission_id = data["submission_id"]
                # Wait for analysis to be over
                self.wait_for_analysis()

            # Add report URL to results
            self.results['URL'] = self.analysis_url.format(self.analysisid)

            # Get report, and extract IOCs
            self.process_report()

            # Get unpacked executables
            self.get_unpacked_executables()
        except (JoeException, Exception) as error:
            self.log("debug", "{}".format(error))

        return True


    def submit_file(self, target, file_type):
        if self.allow_internet_access:
            internet_access = True
            internet_simulation	= False
            ssl_inspection = True
        else:
            internet_access = False
            internet_simulation	= True
            ssl_inspection = False
        params = {
            'internet-access': internet_access,
            'internet-simulation': internet_simulation,
            'ssl-inspection': ssl_inspection,
            'comments': 'Submitted via FAME',
        }
        if file_type == 'url':
            data = self.joe.submit_sample_url(target, params=params)
        else:
            with open(target, "rb") as f:
                data = self.joe.submit_sample(f, params=params)
        return data


    def wait_for_analysis(self):
        waited_time = 0
        while waited_time < self.wait_timeout:
            try:
                data = self.joe.submission_info(self.submission_id)
                status = data["status"]
            except JoeException as error:
                raise ModuleExecutionError("Error while waiting for analysis:\n{}".format(error))
            if status == 'finished':
                break
            time.sleep(self.wait_step)
            waited_time += self.wait_step
        if status != 'finished':
            raise ModuleExecutionError('Could not get report before timeout.')
        try:
            submission_info = self.joe.submission_info(self.submission_id)
            self.webid = submission_info["most_relevant_analysis"]["webid"]
            analysis_info = self.joe.analysis_info(self.webid)
            self.analysisid = analysis_info["analysisid"]
        except JoeException as error:
            raise ModuleExecutionError("Error while getting analysis details:\n{}".format(error))


    def process_report(self):
        try:
            data = self.joe.analysis_download(self.webid, type="lightjson")
            report = io.BytesIO(data[1])
            self.extract_iocs(report)
            report.seek(0)
            self.extract_threatname(report)
            data = self.joe.analysis_download(self.webid, type="html")
            report = io.BytesIO(data[1])
            report.seek(0)
            self.extract_graph(report)
            tmpdir = tempdir()
            filepath = os.path.join(tmpdir, 'joe_report.html')
            with open(filepath, 'w+b') as fd:
                fd.write(data[1])
            self.add_support_file('Report', filepath)
        except Exception as error:
            raise ModuleExecutionError('Error encountered while processing report:\n{}'.format(error))


    def get_unpacked_executables(self):
        try:
            data = self.joe.analysis_download(self.webid, "unpackpe")
            unpackpe = io.BytesIO(data[1])
            tmpdir = tempdir()
            unpacked_files = []
            with ZipFile(unpackpe) as zf:
                for name in zf.namelist():
                    unpacked_files.append(zf.extract(name, tmpdir, pwd='infected'))
            self.register_files('unpacked_executable', unpacked_files)
        except Exception as err:
            raise ModuleExecutionError('Error encountered while processing unpacked executables:\n{}'.format(err))


    def extract_url(self, scheme, iocs, request):
        match = re.match(r'(GET|POST) (\S+) .*Host: (\S+)', request, re.DOTALL)
        if match:
            iocs.add("{}://{}{}".format(scheme, match.group(3), match.group(2)))


    def extract_threatname(self, report):
        parser = ijson.parse(report)
        for prefix, event, value in parser:
            if prefix == "analysis.signaturedetections.strategy.item.threatname" \
                and value is not None and str(value).lower() != "unknown":
                self.add_probable_name(str(value))
                self.add_tag(str(value).lower())


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

