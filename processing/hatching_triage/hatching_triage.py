import os
import json
import time

from fame.core.module import ProcessingModule, ModuleInitializationError, ModuleExecutionError

try:
    from triage import Client

    HAVE_TRIAGE = True
except ImportError:
    HAVE_TRIAGE = False


class Triage(ProcessingModule):

    name = "triage"
    description = "Analyze a sample with Hatching Triage"

    acts_on = ["executable", "word", "html", "rtf", "excel", "pdf", "javascript", "jar", "url", "powerpoint", "vbs"]

    config = [
        {
            "name": "api_key",
            "type": "string",
            "description": "API Key needed to use the Triage API",
        },
        {
            'name': 'wait_timeout',
            'type': 'integer',
            'default': 3600,
            'description': 'Time in seconds that the module will wait for Triage analysis to be over.'
        },
        {
            'name': 'wait_step',
            'type': 'integer',
            'default': 15,
            'description': "Time in seconds between two check of Triage's analysis status"
        },
        {
            'name': 'private_instance',
            'type': 'bool',
            'default': True,
            'description': 'Use a private Triage instance.',
        }
    ]

    def initialize(self):
        if not HAVE_TRIAGE:
            raise ModuleInitializationError(self, "Missing dependency: hatching-triage")

        return True

    def each_with_type(self, target, target_type):
        self.client = Client(self.api_key, "https://private.tria.ge/api" if self.private_instance else "https://api.tria.ge")

        # Submit the file / URL
        self.submit_target(target, target_type)

        # Wait for analysis to be over
        self.wait_for_analysis()

        # Save Results
        self.results = self.client.overview_report(self.submission["id"])

        # Extract interesting bits
        self.parse_results()

        # Format Results
        self.results = {
            "url": self.results["url"],
            "analysis": self.results["analysis"],
            "signatures": self.results["signatures"]
        }

        return True

    def submit_target(self, target, target_type):
        if target_type == "url":
            self.submission = self.client.submit_sample_url(target)
        else:
            with open(target, "rb") as sample:
                self.submission = self.client.submit_sample_file(os.path.basename(target), sample)

    def wait_for_analysis(self):
        waited_time = 0

        while waited_time < self.wait_timeout:
            sample = self.client.sample_by_id(self.submission["id"])

            if sample["status"] == 'reported':
                return

            time.sleep(self.wait_step)
            waited_time += self.wait_step

        raise ModuleExecutionError('could not get report before timeout.')

    def parse_results(self):
        # Set Probable Names
        for family in self.results.get("analysis", {}).get("family", []):
            self.add_probable_name(family)

        # Extract IOCs
        for target in self.results.get("targets", []):
            iocs = target.get("iocs", {})
            for ioc_type in ["urls", "domains", "ips"]:
                for ioc in iocs.get(ioc_type, []):
                    self.add_ioc(ioc)

        # Add Extractions
        extractions = self.results.get("extracted", [])
        for extraction in extractions:
            if "config" in extraction:
                self.add_extraction(f"{extraction['config']['family']} Configuration", json.dumps(extraction["config"], indent=2))

                for c2 in extraction["config"].get("c2", []):
                    self.add_ioc(c2, "c2")

            if "ransom_note" in extraction:
                self.add_extraction(f"{extraction['ransom_note']['family']} Ransom Note", json.dumps(extraction["ransom_note"], indent=2))

            if "credentials" in extraction:
                self.add_extraction("Credentials", json.dumps(extraction["credentials"], indent=2))

            if "dropper" in extraction:
                self.add_extraction("Dropper", json.dumps(extraction["dropper"], indent=2))

                for url in extraction["dropper"].get("urls", []):
                    self.add_ioc(url["url"], url["type"])

        # Add Report URL
        if self.private_instance:
            self.results["url"] = f"https://private.tria.ge/{self.results['sample']['id']}"
        else:
            self.results["url"] = f"https://tria.ge/{self.results['sample']['id']}"
