from posixpath import join as urljoin
from ipaddress import IPv4Address, AddressValueError

from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ThreatIntelligenceModule

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class SEKOIAIO(ThreatIntelligenceModule):
    name = "SEKOIA.IO"
    description = "Submit observables to SEKOIA.IO Intelligence Center in order to get matching indicators."

    config = [
        {
            'name': 'api_key',
            'type': 'str',
            'description': "API Key to use in order to authenticate to SEKOIA.IO."
        },
        {
            'name': 'base_url',
            'type': 'str',
            'default': 'https://app.sekoia.io',
            'description': "Base URL of the Intelligence Center to use."
        }
    ]

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")

        return True

    def ioc_lookup(self, ioc):
        # Try to guess the IOC type
        ioc_type = "domain-name"

        if ioc.startswith("http://") or ioc.startswith("https://"):
            ioc_type = "url"
        else:
            try:
                IPv4Address(ioc)
                ioc_type = "ipv4-addr"
            except AddressValueError:
                pass

        # Fetch context from the Intelligence Center
        params = {
            "value": ioc,
            "type": ioc_type
        }

        response = requests.get(
            urljoin(self.base_url, "api", "v2", "inthreat", "indicators", "context"),
            params=params, headers={"Authorization": f"Bearer {self.api_key}"})

        response.raise_for_status()
        results = response.json()
        objects = {}
        targets = set()
        indicators = []

        for bundle in results["items"]:
            for obj in bundle["objects"]:
                objects[obj["id"]] = obj

                if obj["type"] == "relationship" and obj["relationship_type"] == "indicates":
                    targets.add(obj["target_ref"])

        for target in targets:
            indicators.append({
                "name": objects[target]["name"],
                "description": objects[target].get("description", "")
            })

        return [], indicators
