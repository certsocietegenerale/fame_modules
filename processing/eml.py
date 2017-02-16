import os
import email.utils
import mimetypes

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir


class eml(ProcessingModule):
    name = "eml"
    description = "Extract attachments from .eml messages."
    acts_on = "eml"

    def each(self, target):
        fp = open(target)
        msg = email.message_from_file(fp)

        fp.close()
        path_temp = tempdir()
        counter = 1
        for part in msg.walk():
            # multipart/* are just containers
            if part.get_content_maintype() == 'multipart':
                continue
            # Applications should really sanitize the given filename so that an
            # email message can't be used to overwrite important files
            filename = part.get_filename()
            if not filename:
                ext = mimetypes.guess_extension(part.get_content_type())
                if not ext:
                    # Use a generic bag-of-bits extension
                    ext = '.bin'
                filename = 'part-%03d%s' % (counter, ext)
            counter += 1
            filepath = os.path.join(path_temp, filename)
            fp = open(filepath, 'wb')
            fp.write(part.get_payload(decode=True))
            fp.close()
            self.add_extracted_file(filepath)
