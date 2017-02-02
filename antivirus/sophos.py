from .mail_submission import MailSubmission


class Sophos(MailSubmission):
    name = "Sophos"
    description = "Submit the file to Sophos for inclusion in detections."

    mail_submission = "samples@sophos.com"
    mail_subject = "Sample submitted for analysis - Reply needed"
