# coding: utf-8
import re

from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ThreatIntelligenceModule

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class Urlhaus(ThreatIntelligenceModule):
    name = "URLhaus"
    description = "Submit URLs to URLhaus in order to contribute to maintain a list of malware URLs."

    config = [
        {
            'name': 'api_key',
            'type': 'str',
            'description': "API Key from a Twitter account to use in order to authenticate to URLhaus API"
        },
        {
            'name': 'anonymous',
            'type': 'bool',
            'default': False,
            'description': "Check this box if you do not want your twitter handle to appear as 'Reporter'"
        },
        {
            'name': 'url_urlhaus',
            'type': 'str',
            'default': 'https://urlhaus.abuse.ch/api/',
            'description': "URL of the URLHaus API"
        },
        {
            'name': 'url_regex',
            'type': 'str',
            'default': '(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9]\.[^\s]{2,})',
            'description': 'Regex rule for URL matching'
        },
    ]

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")

        return True

    def iocs_submission(self, analysis, iocs):
        submission = []

        for ioc in iocs:
            # Make sure we only send URLs
            if re.match(self.url_regex, ioc['value']):
                tags = ioc['tags']

                # Make sure we do not have empty tags
                tags = [tag for tag in tags.split(',') if tag]

                # expected structure of the 'submission' key (see jsonData)
                sub = {
                    'threat': 'malware_download',
                    'url': ioc['value'],
                    'tags': tags
                }
                submission.append(sub)

        if submission:
            # body of the post request (json format)
            json_data = {
                'token': self.api_key,
                'anonymous': '1' if self.anonymous else '0',
                'submission': submission
            }
            r = self._urlhaus_request(json_data)
            print(("[URLhaus] Submission status: " + r.text))

    def _urlhaus_request(self, json_data):

        headers = {'Content-Type': 'application/json'}
        r = requests.post(self.url_urlhaus, json=json_data, headers=headers)

        r.raise_for_status()

        return r
