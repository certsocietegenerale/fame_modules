from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ThreatIntelligenceModule

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class Yetiv2(ThreatIntelligenceModule):
    """Implements Yetiv2 Threat Intelligence module"""
    name = "Yeti v2"
    description = "Submit observables to YETI v2 in order to get matching tags and indicators."

    config = [
        {
            'name': 'url',
            'type': 'str',
            'description': "URL of your Yeti instance's API endpoint."
        },
        {
            'name': 'api_key',
            'type': 'str',
            'default': '',
            'description': "API Key to use in order to authenticate to Yeti."
        },
    ]

    def initialize(self):
        """Initialize module"""
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")
        return True

    def ioc_lookup(self, ioc):
        """Enrich the analysis with data from Yeti"""
        tags = []
        indicators = []

        query = {
            "observables": [ioc]
        }

        r = self._yeti_request('/api/v2/graph/match', query)

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
        """Submit IOCs and tags to Yeti"""
        try:
            tag_list = tags.split(',')
            try:
                tag_list.remove('redirection')
            except ValueError:
                pass
            r = self._yeti_request('/api/v2/observables/add_text', { 'text': ioc, 'tags': tag_list})
        except requests.HTTPError as e:
            if e.response.status_code == 400:
                analysis.log("warning",
                             f"Could not submit observable, error message: {e.response.detail}")
        except requests.ConnectTimeout:
            analysis.log("error", "Timeout connecting to Yeti v2")
        else:
            result = r.json()
            obsid = result['id']
            r = self._yeti_request(f"/api/v2/observables/{obsid}/context",
                                   {'context': {'analysis_id': str(analysis['_id'])},
                                   'source': 'FAME' })

    def _yeti_request(self, url, data):
        # Add your API key to the x-yeti-apikey header
        # Write a requests POST call with the api key in the header
        auth = requests.post(
            self.url + "/api/v2/auth/api-token",
            headers={"x-yeti-apikey": self.api_key},
        )
        
        auth.raise_for_status()
        access_token = auth.json().get("access_token")
        headers = {'accept': 'application/json'}
        headers.update({"authorization": f"Bearer {access_token}"})

        r = requests.post(self.url + url,
                              json=data,
                              headers=headers,
                              timeout=60)
        r.raise_for_status()

        return r
