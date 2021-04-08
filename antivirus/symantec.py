import os
import mimetypes

from fame.core.module import AntivirusModule, ModuleInitializationError


try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


class Symantec(AntivirusModule):
    name = "Symantec"
    description = "Submit the file to Symantec for inclusion in detections."

    submission_url = "https://submit.symantec.com/websubmit/bcs.cgi"

    config = [
        {
            'name': 'support_id',
            'type': 'str',
            'description': 'Symantec support ID'
        },
        {
            'name': 'email_address',
            'type': 'str',
            'description': 'Your email address'
        },
        {
            'name': 'first_name',
            'type': 'str',
            'description': 'Your first name'
        },
        {
            'name': 'last_name',
            'type': 'str',
            'description': 'Your last name'
        },
        {
            'name': 'company',
            'type': 'str',
            'description': 'The name of your company'
        },
    ]

    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")

        return True

    def submit(self, file):
        s = requests.Session()
        s.get(self.submission_url)
        filename = os.path.basename(file)

        with open(file, 'r+b') as f:
            params = {
                'mode': "2",
                'fname': self.first_name,
                'lname': self.last_name,
                'cname': self.company,
                'email': self.email_address,
                'email2': self.email_address,
                'pin': self.support_id,
                'stype': "upfile",
                'comments': None
            }
            files = {
                'upfile': (filename, f, mimetypes.guess_type(filename)[0] or 'application/octet-stream')
            }

            s.post(self.submission_url, data=params, files=files)
