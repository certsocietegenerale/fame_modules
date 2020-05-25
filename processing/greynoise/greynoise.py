from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

import requests
import socket
import json

# import urlparse for py3 or py2
try:
    from urllib.parse import urlparse
except:
    from urlparse import urlparse

class GreyNoise(ProcessingModule):
    name = "greynoise"
    description = "GreyNoise domain/IP enrichment and tagging."
    acts_on = ['url']

    config = [
        {
            'name': 'api_key',
            'type': 'string',
            'default': None,
            'description': 'API key for GreyNoise queries.'
        }
    ]

    def initialize(self):
        if not self.api_key:
            raise ModuleInitializationError(self, "GreyNoise API key is missing!")

    def validip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except:
            return False

    def each(self, target):
        self.results = {}
        apistatus = {
            200: "OK",
            400: "Bad Request",
            401: "Unauthorized",
            429: "Too Many Requests"
        }

        headers = {
            'Accept': 'application/json',
            'key': self.api_key
        }

        if not target.startswith('http') and validip(target):
            aip = target
        else:
            url = urlparse(target)
            try:
                aip = socket.gethostbyname(url.netloc)
            except:
                self.log("error", "{} could not be resolved".format(url.netloc))
        
        r = requests.get('https://api.greynoise.io/v2/noise/context/{}'.format(aip), params={}, headers=headers)
        if not r.status_code == 200:
            self.log("error", "GreyNoise says {}".format(apistatus[r.status_code]))
        else:
            data = r.json()
            #self.results['greydata'] = json.dumps(data, indent=4, separators=(',',':'))
            self.results['greydata'] = data
            self.results['json'] = json.dumps(data, indent=4)
            
            

            # https://docs.greynoise.io/?python#ip-context
            # if seen==True -> Grab classification, actor, tags, metadata.tor
            if data["seen"]:
                tags = []
                if data["classification"] == "malicious":
                    tags.append(data["classification"])
                    if not data["actor"] == "unknown":
                        tags.append(data["actor"])
                    
                if data["metadata"]["tor"]:
                        tags.append("TOR")

                for item in data["tags"]:
                    tags.append(item)

                self.results["classification"] = data["classification"]
                self.results['tags'] = data["tags"]
                self.results['metadata'] = data["metadata"]

                self.add_ioc(aip, tags)

        return True
