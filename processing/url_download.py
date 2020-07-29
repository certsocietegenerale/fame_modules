import os
import requests
from cgi import parse_header

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir
from fame.common.exceptions import ModuleExecutionError


class URLDownload(ProcessingModule):
    name = "url_download"
    description = "Download file from URL and launch new analysis."
    acts_on = "url"

    # This is a trick to make sure that this module only executes when
    # explicitly asked by the user.
    triggered_by = "!"

    def each(self, target):
        self.add_ioc(target)
        response = requests.get(target, stream=True)

        if response.status_code == 200:
            tmpdir = tempdir()
            try:
                filename = parse_header(response.headers['content-disposition'])[1]['filename']
            except KeyError:
                filename = target.split('/')[-1]

            if not filename:
                filename = "no_filename"

            filepath = os.path.join(tmpdir, filename)

            with open(filepath, 'wb') as fd:
                for chunk in response.iter_content(1024):
                    fd.write(chunk)

            self.add_extracted_file(filepath)
            self.add_ioc(target, 'payload_delivery')

            return True
        else:
            raise ModuleExecutionError("Could not download file. Status: {}".format(response.status_code))
