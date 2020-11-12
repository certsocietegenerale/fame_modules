
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
        {
            'name': 'url',
            'type': 'str',
            'description': 'Incoming webhook URL.'
        },
        {
            'name': 'fame_base_url',
            'type': 'str',
            'description': 'Base URL of your FAME instance, as you want it to appear in links.'
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

        string = "Just finished analysis on {0}\n".format(defang(', '.join(analysis._file['names'])))

        if analysis['modules'] is not None:
            string += "modules used: "
            for module in analysis['modules']:
                string += "{0} ".format(module)
            string += "\n"

        if len(analysis['extractions']) > 0:
            string += "Extractions: {0}\n".format(','.join([x['label'] for x in analysis['extractions']]))

        if len(analysis['iocs']) > 0:
            string += "IOCs: {0}\n".format(','.join(analysis['iocs']))

        if len(analysis['probable_names']) > 0:
            string += "Probable Names: {0}\n".format(','.join(analysis['probable_names']))

        string += "<{0}/analyses/{1}|See analysis>\n\n".format(self.fame_base_url, analysis['_id'])
        array =  "| modules used | execution status | TBD                                   |\n"
        array += "|:-----------|:-----------:|:-----------------------------------------------|\n"
        for module in analysis['modules']:
            executed = ':ok_hand: executed' if module in analysis['executed_modules'] else ':rage2: execution failed'
            array += "| {0}     | {1}         | TBD                           |\n".format(module,executed)
        data = {'text': string + array }
        requests.post(self.url, data={'payload': json.dumps(data)})
