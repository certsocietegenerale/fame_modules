from .mail_submission import MailSubmission


class McAfee(MailSubmission):
    name = "McAfee"
    description = "Submit the file to McAfee for inclusion in detections."

    mail_submission = "virus_research@mcafee.com"
