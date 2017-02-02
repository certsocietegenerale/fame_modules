import subprocess
from os import path, remove
from uuid import uuid4
from distutils.spawn import find_executable

from fame.common.email_utils import EmailMixin, EmailServer
from fame.common.config import fame_config
from fame.core.module import AntivirusModule, ModuleInitializationError


class MailSubmission(EmailMixin, AntivirusModule):
    """Abstract class for Antivirus submission modules based on emails

    Inherit from this class to easily create email-based antivirus submission
    modules. Using this module as the parent class enables the creation of
    modules as simple as::

        class McAfee(MailSubmission):
            name = "McAfee"

            mail_submission = "virus_research@mcafee.com"

    Only two attributes are mandatory: the classical :attr:`name`, and
    :attr:`mail_submission`.

    This module will automatically create a password protected zip file and
    send it by email to the antivirus vendor.

    Attributes:
        mail_submission (string): email address to send the sample to.
        password (string): password to use when creating the encrypted zip file.
            Default value: ``infected``.
        mail_subject (string): subject to use in the email sent to the vendor.
            Default value: ``Sample submitted for analysis``.
    """

    password = "infected"
    mail_subject = "Sample submitted for analysis"

    config = [
        {
            'name': 'mail_template',
            'type': 'text',
            'default': """Hello,

We have detected a new sample which is not detected by your engine. Therefore, as a customer we are sending you the suspected binary.

The binary is attached to this mail within a zip file encrypted with the password '{}'.

The threat is considered as an emergency for us, so we would appreciate if you could analyze the binary as soon as possible.

In the case your analysis would lead to the conclusion that the file is truly a malware, we would really appreciate you to add its signature to your database.

Thank you for your kind help.

Best regards""",
            'description': 'Content of the email that will be sent to the antivirus vendor. You can include "{}" that will be replaced by the encryption password.'
        },
    ]

    def initialize(self):
        if find_executable("7z") is None:
            raise ModuleInitializationError(self, "Missing dependency: 7z")

        return True

    def submit(self, file):
        archive_name = "sample_{}.zip".format(uuid4())
        archive_file = path.join(fame_config.temp_path, archive_name)
        subprocess.call(["7z", "a", "-tzip", "-p{}".format(self.password), archive_file, file])

        server = EmailServer()
        msg = server.new_message(self.mail_subject, self.mail_template.format(self.password))
        msg.add_attachment(archive_file, archive_name)
        msg.send([self.mail_submission])

        remove(archive_file)

        return True
