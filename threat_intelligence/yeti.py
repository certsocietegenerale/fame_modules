from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ThreatIntelligenceModule

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class Yeti(ThreatIntelligenceModule):
    name = "Yeti"
    description = "Submit observables to YETI in order to get matching tags and indicators."

    config = [
        {
            'name': 'url',
            'type': 'str',
            'description': "URL of your Yeti instance's API endpoint."
        },
        {
            'name': 'user',
            'type': 'str',
            'default': '',
            'description': "User to use for basic authentication."
        },
        {
            'name': 'password',
            'type': 'str',
            'default': '',
            'description': "Password to use for basic authentication."
        },
        {
            'name': 'api_key',
            'type': 'str',
            'default': '',
            'description': "API Key to use in order to authenticate to Yeti."
        },
    ]

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")

        return True

    def ioc_lookup(self, ioc):
        tags = []
        indicators = []

        query = {
            "observables": [ioc]
        }

        r = self._yeti_request('analysis/match', query)

        results = r.json()
        for result in results['known']:
            if result['value'] == ioc:
                tags = [tag['name'] for tag in result['tags']]
                break

        for result in results['matches']:
            if result['observable']['value'] == ioc:
                indicators.append({
                    'name': result['name'],
                    'description': result['description']
                })

        return tags, indicators

    def ioc_submission(self, analysis, ioc, tags):
        self._yeti_request('observable/', {'value': ioc, 'source': 'fame', 'tags': tags.split(',')})

    def _yeti_request(self, url, data):

        headers = {'accept': 'application/json'}
        if self.api_key:
            headers.update({'X-Api-Key': self.api_key})

        if self.user == "":
            r = requests.post(self.url + url,
                              json=data,
                              headers=headers)
        else:
            r = requests.post(self.url + url,
                              json=data,
                              headers=headers,
                              auth=requests.auth.HTTPBasicAuth(self.user, self.password))

        r.raise_for_status()

        return r
