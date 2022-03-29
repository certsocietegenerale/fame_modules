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
            string += "Selected Modules: {}\n".format(', '.join(analysis['modules']))

        if analysis["probable_names"]:
            string += "Probable Names: {}\n".format(', '.join(analysis['probable_names']))

        if analysis["extractions"]:
            string += "Extractions: {}\n".format(', '.join([x['label'] for x in analysis['extractions']]))

        string += "<{}/analyses/{}|See analysis>\n".format(self.fame_base_url, analysis['_id'])

        if analysis["iocs"]:
            string += "\n| Observable | Tags |\n"
            string += "|:-----------|:-----|\n"

            for ioc in analysis["iocs"]:
                string += "|{}|{}|\n".format(defang(ioc['value']), ', '.join(ioc['tags']))

        string += "\n| Module | Status |\n"
        string += "|:-------|:------:|\n"

        for module in analysis["executed_modules"]:
            string += "|{}| :ok_hand: executed |\n".format(module)

        for module in analysis["canceled_modules"]:
            string += "|{}| :rage: canceled |\n".format(module)

        data = {"text": string}
        requests.post(self.url, data={"payload": json.dumps(data)})
