import hashlib

from fame.core.module import ProcessingModule, ModuleInitializationError

try:
    from virus_total_apis import PublicApi as VirusTotalPublicApi
    HAVE_VIRUSTOTAL = True
except ImportError:
    HAVE_VIRUSTOTAL = False


class VirusTotalPublic(ProcessingModule):

    name = 'virustotal_public'
    description = 'Get Scan Report from VirusTotal (Public API)'

    config = [
        {
            'name': 'api_key',
            'type': 'string',
            'description': 'API Key needed to use the VirusTotal Public API 2.0',
        }
    ]

    def initialize(self):
        if not HAVE_VIRUSTOTAL:
            raise ModuleInitializationError(self, 'Missing dependency: virustotal-api')

        return True

    def extractDetection(self, scans):
        detectedby = None
        suspiciousnames = None
        for scan in scans:
            if scans[scan]['detected']:
                if detectedby is None:
                    detectedby = [scan]
                    suspiciousnames = [scans[scan]['result']]
                else:
                    detectedby.append(scan)
                    suspiciousnames.append(scans[scan]['result'])

        if detectedby is not None:
            detectedby = list(set(detectedby))
            suspiciousnames = list(set(suspiciousnames))
            detectedby = ', '.join(detectedby)
            suspiciousnames = ', '.join(suspiciousnames)

        return detectedby, suspiciousnames

    def each_with_type(self, target, target_type):
        self.results = {}

        vt = VirusTotalPublicApi(self.api_key)

        if target_type == 'url':
            response = vt.get_url_report(target)
        else:
            sha256 = hashlib.sha256(open(target, 'r').read()).hexdigest()
            response = vt.get_file_report(sha256)

        # if request successful
        if response['response_code'] == 200 and response['results']['response_code'] == 1:
            self.results['scan_date'] = response['results']['scan_date']
            self.results['permalink'] = response['results']['permalink']
            self.results['positives'] = response['results']['positives']
            self.results['total'] = response['results']['total']
            self.results['scans'] = response['results']['scans']

            return True

        self.log("debug", 'no report found')
        return False
