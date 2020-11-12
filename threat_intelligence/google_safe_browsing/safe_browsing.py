# coding: utf-8
import re
import urllib.request, urllib.parse, urllib.error

from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ThreatIntelligenceModule

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class SafeBrowsingLookupAPI(ThreatIntelligenceModule):
    name = "Google Safe Browsing (Lookup API)"
    description = "Use Google Safe Browsing's Lookup API to get information on known URLs"

    config = [
        {
            'name': 'api_key',
            'type': 'str',
            'description': "Google Safe Browsing API Key. See https://developers.google.com/safe-browsing/v4/get-started"
        },
        {
            'name': 'client_name',
            'type': 'str',
            'default': 'fame',
            'description': 'Name of the client implementation (used by Google for server-side logging and accounting).'
        },
        {
            'name': 'client_version',
            'type': 'str',
            'default': '1.0',
            'description': 'Version of the client implementation (used by Google for server-side logging and accounting).'
        },
        {
            'name': 'threat_types',
            'type': 'str',
            'default': 'MALWARE,SOCIAL_ENGINEERING,UNWANTED_SOFTWARE,POTENTIALLY_HARMFUL_APPLICATION',
            'description': "Google threatType lists to use (comma-separated)."
        },
        {
            'name': 'platform_types',
            'type': 'str',
            'default': 'ALL_PLATFORMS,IOS,OSX,ANDROID,LINUX,WINDOWS,CHROME,PLATFORM_TYPE_UNSPECIFIED',
            'description': "Google platformType lists to use (comma-separated)."
        },
        {
            'name': 'url_regex',
            'type': 'str',
            'default': r'(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9]\.[^\s]{2,})',
            'description': 'Regex rule for URL matching'
        },
    ]

    url_safebrowsing = 'https://safebrowsing.googleapis.com/v4'

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(
                self, "Missing dependency: requests")

        self.threat_types = [threat_type.strip() for threat_type in self.threat_types.split(',')]
        self.platform_types = [platform_type.strip() for platform_type in self.platform_types.split(',')]

        return True

    def ioc_lookup(self, ioc):
        tags = set()

        # Make sure we only request information on URLs
        if re.match(self.url_regex, ioc):
            threaturl = [{"url": ioc}]
            # expected body of the post requests
            # https://developers.google.com/safe-browsing/v4/lookup-api#http-post-request
            body = {
                "client": {
                    "clientId": self.client_name,
                    "clientVersion": self.client_version
                },
                "threatInfo": {
                    "threatTypes": self.threat_types,
                    "platformTypes": self.platform_types,
                    "threatEntryTypes": ['URL', 'THREAT_ENTRY_TYPE_UNSPECIFIED', 'EXECUTABLE'],
                    "threatEntries": threaturl
                }
            }

            # post request
            response = self._google_safe_browsing_request('threatMatches:find', body)
            results = response.json()

            # read Response
            # https://developers.google.com/safe-browsing/v4/lookup-api#http-post-response
            if "matches" in results:
                platforms = []

                for match in results["matches"]:
                    tags.add(match["threatType"].lower())
                    platforms.append(match["platformType"].lower())

                    if 'threatEntryMetadata' in match:
                        for metadata in match['threatEntryMetadata']['entries']:
                            tags.add(
                                '{}:{}'.format(metadata['key'], metadata['value']))

                if 'all_platforms' not in platforms:
                    tags.update(platforms)

        return list(tags), []

    def _google_safe_browsing_request(self, method, body):
        headers = {'Content-Type': 'application/json'}
        # format url : https://developers.google.com/safe-browsing/v4/lookup-api#http-post-request
        url = '{}/{}?key={}'.format(self.url_safebrowsing, method, self.api_key)
        r = requests.post(url, json=body, headers=headers)

        r.raise_for_status()

        return r


class SafeBrowsingUpdateAPI(ThreatIntelligenceModule):
    name = "Google Safe Browsing (Update API)"
    description = "Use Google Safe Browsing's Update API to get information on known URLs. Requires a local gglsbl-rest instance."

    config = [
        {
            'name': 'gglsbl_url',
            'type': 'str',
            'description': "URL of gglsbl-rest lookup API (ex: http://localhost:5000/gglsbl/v1/lookup/). Must end with '/'."
        },
        {
            'name': 'url_regex',
            'type': 'str',
            'default': r'(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9]\.[^\s]{2,})',
            'description': 'Regex rule for URL matching'
        }
    ]

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(
                self, "Missing dependency: requests")

        return True

    def ioc_lookup(self, ioc):
        tags = set()

        # Make sure we only request information on URLs
        if re.match(self.url_regex, ioc):
            # percent encoding (url)
            encoded_ioc = urllib.parse.quote(ioc, safe='')

            # request local db (docker)
            # https://github.com/mlsecproject/gglsbl-rest
            response = self._gglsbl_request(encoded_ioc)
            if response.status_code == 200:
                results = response.json()

                if 'matches' in results:
                    platforms = []

                    for match in results["matches"]:
                        tags.add(match["threat"].lower())
                        platforms.append(match["platform"].lower())

                    if 'all_platforms' not in platforms:
                        tags.update(platforms)
            elif response.status_code != 404:
                response.raise_for_status()

        return list(tags), []

    def _gglsbl_request(self, encoded_ioc):
        headers = {'Content-Type': 'application/json'}
        # url: ip:5000/ggslbl/v1/lookup/'url_encoded'
        url = '{}{}'.format(self.gglsbl_url, encoded_ioc)
        r = requests.get(url, headers=headers)

        return r
