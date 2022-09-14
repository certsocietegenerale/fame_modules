from os import path
from zipfile import ZipFile
from subprocess import Popen, PIPE
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from fame.common.utils import tempdir


try:
    from androguard.misc import AnalyzeAPK
    HAVE_ANDROGUARD = True
except ImportError:
    HAVE_ANDROGUARD = False

try:
    from gpapi.googleplay import GooglePlayAPI, RequestError
    HAVE_GOOGLEPLAY = True
except ImportError:
    HAVE_GOOGLEPLAY = False


class APKVerification(ProcessingModule):
    name = "apk_verification"
    description = "Compare submitted APK with the one on the Google Play Store in order to verify if they were signed with the same certificate."
    acts_on = ["apk"]

    config = [
        {
            'name': 'google_login',
            'type': 'str',
            'description': 'A email address matching a Google account.'
        },
        {
            'name': 'google_password',
            'type': 'str',
            'description': 'An application password related to your Google account. You can generate one here: https://myaccount.google.com/apppasswords'
        },
    ]

    def initialize(self):
        if not HAVE_ANDROGUARD:
            raise ModuleInitializationError(self, "Missing dependency: androguard")

        if not HAVE_GOOGLEPLAY:
            raise ModuleInitializationError(self, "Missing dependency: gpapi")

    def validate_signature(self, file, key='target'):
        # Verify the signature
        p = Popen(["jarsigner", "-verify", file], stdout=PIPE)
        out = p.communicate()[0].decode().strip()
        self.results["{}_output".format(key)] = out
        self.results["{}_status".format(key)] = ((p.returncode == 0) and (out.startswith('jar verified.')))
        if not 'jar is unsigned.' in out:
            # Extract the certificate
            z = ZipFile(file)
            for name in z.namelist():
                if name.startswith('META-INF/') and name.endswith('.RSA'):
                    cert = z.extract(name, self.tmpdir)
                    break
            z.close()

            # Extract certificate details
            p = Popen(["keytool", "-printcert", "-file", cert], stdout=PIPE)
            self.results["{}_certificate".format(key)] = p.communicate()[0].decode().strip()

    def download_reference_apk(self):
        api = GooglePlayAPI()
        api.login(self.google_login, self.google_password)

        package = api.details(self.results['package'])
        version = package['details']['appDetails']['versionCode']
        offer_type = package['offer'][0]['offerType']

        ref_path = path.join(self.tmpdir, "ref.apk")
        data = api.download(self.results['package'], version, offer_type)
        with open(ref_path, "wb") as out:
            for chunk in data['file']['data']:
                out.write(chunk)

        return ref_path

    def each(self, target):
        self.tmpdir = tempdir()
        self.results = dict()

        apk, vm, vm_analysis = AnalyzeAPK(target)
        self.results['package'] = apk.get_package()
        self.validate_signature(target)
        try:
            ref_apk = self.download_reference_apk()
            self.validate_signature(ref_apk, "ref")

            self.results['verification_result'] = self.results['target_status'] and self.results['ref_status'] and (self.results['target_certificate'] == self.results['ref_certificate'])
        except RequestError:
            self.log("debug", "Submitted APK was not found on the Play Store")
            self.results['verification_result'] = False


        return True
