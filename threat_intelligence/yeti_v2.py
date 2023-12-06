from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ThreatIntelligenceModule

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class Yeti(ThreatIntelligenceModule):
    name = "Yeti version 2"
    description = "Submit observables to YETI v2 in order to get matching tags and indicators."

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

        r = self._yeti_request('v2/graph/match', query)

        results = r.json()
        for result in results['known']:
            if result['value'] == ioc:
                tags = result['tags'].keys()
                break

        for result in results['matches']: 
            if result[0] == ioc:
                indicators.append({
                    'name': result[1]['name'],
                    'description': result[1]['description']
                })

        return tags, indicators

    def ioc_submission(self, analysis, ioc, tags):
        try:
            r = self._yeti_request('v2/observables/', {'type': 'guess', 'value': ioc, 'tags': tags.split(',')}) #Type is mandatory, guess is not converted to proper type
        except requests.HTTPError:
            if r.status_code == 400:
                analysis.log("warning", "Could not submit observable \"%s\" to Yeti, observable already exists" % (ioc,))
            elif r.status_code == 422:
                analysis.log("error", "Could not submit IOC \"%s\" to Yeti, \"not a viable data type\" (aka Yeti does not recognize the format the data)" % (ioc,))
            else:
                import traceback
                analysis.log("warning", "Could not submit IOC \"%s\" to Yeti, HTTP status code: %d" % (ioc, r.status_code))
                analysis.log("debug", traceback.format_exc())
        else:
            result = r.json()
            id = result['id']
            r = self._yeti_request(f"v2/{id}/context", {'context': {'analysis_id': analysis['_id']}, 'source': 'FAME' } ) 
        

    def _yeti_request(self, url, data):
        headers = {'accept': 'application/json'}
        if self.api_key:
            headers.update({'x-yeti-apikey': self.api_key})

        if self.user == "":
            r = requests.post(self.url + url,
                              json=data,
                              headers=headers,
                              verify=False)
        else:
            r = requests.post(self.url + url,
                              json=data,
                              headers=headers,
                              auth=requests.auth.HTTPBasicAuth(self.user, self.password))
        r.raise_for_status()

        return r
