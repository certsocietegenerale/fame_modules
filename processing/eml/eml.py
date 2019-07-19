# coding: utf-8

import os
import email.utils
import mimetypes

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir


class EML(ProcessingModule):
    name = "eml"
    description = "Extract attachments and headers from .eml messages."
    acts_on = "eml"

    def headers_string(self, header):
        header_string = ''

        for part in header:
            header_string += '{}: {}\n'.format(part[0], part[1])

        return header_string

    def register_headers(self, msg, outdir):
        # Create a temporary output dir
        headers = os.path.join(outdir, '__headers.txt')

        with open(headers, 'w') as f:
            f.write(self.headers_string(msg.items()))

        self.register_files('email_headers', headers)

    def each(self, target):
        with open(target, 'r') as f:
            msg = email.message_from_file(f)

        outdir = tempdir()

        # Extract Headers
        self.register_headers(msg, outdir)

        # Extract Attachments
        counter = 1
        for part in msg.walk():
            # multipart/* are just containers
            if part.get_content_maintype() == 'multipart':
                continue

            content_disposition = part.get('Content-Disposition', None)
            if content_disposition and 'attachment' in content_disposition:
                filename = part.get_filename()
                if not filename:
                    ext = mimetypes.guess_extension(part.get_content_type())

                    if not ext:
                        # Use a generic bag-of-bits extension
                        ext = '.bin'

                    filename = 'part-{}{}'.format(counter, ext)
                    counter += 1

                filepath = os.path.join(outdir, filename)
                with open(filepath, 'wb') as out:
                    out.write(part.get_payload(decode=True))

                self.add_extracted_file(filepath)
