import json

from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ReportingModule

try:
    import requests

    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    from defang import defang

    HAVE_DEFANG = True
except ImportError:
    HAVE_DEFANG = False


class Mattermost(ReportingModule):
    name = "mattermost"
    description = "Post message on Mattermost when an analysis is finished."

    config = [
        {"name": "url", "type": "str", "description": "Incoming webhook URL."},
        {
            "name": "fame_base_url",
            "type": "str",
            "description": "Base URL of your FAME instance, as you want it to appear in links.",
        },
    ]

    def initialize(self):
        if ReportingModule.initialize(self):
            if not HAVE_REQUESTS:
                raise ModuleInitializationError(self, "Missing dependency: requests")

            if not HAVE_DEFANG:
                raise ModuleInitializationError(self, "Missing dependency: defang")

            return True
        else:
            return False

    def done(self, analysis):
        string = "Just finished analysis on {0}\n".format(
            defang(", ".join(analysis._file["names"]))
        )

        if analysis["modules"]:
            string += f"Selected Modules: {', '.join(analysis['modules'])}\n"

        if analysis["probable_names"]:
            string += f"Probable Names: {', '.join(analysis['probable_names'])}\n"

        if analysis["extractions"]:
            string += f"Extractions: {', '.join([x['label'] for x in analysis['extractions']])}\n"

        string += f"<{self.fame_base_url}/analyses/{analysis['_id']}|See analysis>\n"

        if analysis["iocs"]:
            string += "\n| Observable | Tags |\n"
            string += "|:-----------|:-----|\n"

            for ioc in analysis["iocs"]:
                string += f"|{defang(ioc['value'])}|{', '.join(ioc['tags'])}|\n"

        string += "\n| Module | Status |\n"
        string += "|:-------|:------:|\n"

        for module in analysis["executed_modules"]:
            string += f"|{module}| :ok_hand: executed |\n"

        for module in analysis["canceled_modules"]:
            string += f"|{module}| :rage2: canceled |\n"

        data = {"text": string}
        requests.post(self.url, data={"payload": json.dumps(data)})
