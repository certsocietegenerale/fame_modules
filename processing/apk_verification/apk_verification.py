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
    from googleplay_api.googleplay import GooglePlayAPI
    HAVE_GOOGLEPLAY = True
except ImportError:
    HAVE_GOOGLEPLAY = False


class APKVerification(ProcessingModule):
    name = "apk_verification"
    description = "Compare submitted APK with the one on the Google Play Store in order to verify if they were signed with the same certificate."
    acts_on = ["apk"]

    config = [
        {
            'name': 'android_id',
            'type': 'str',
            'description': 'An Android device ID (https://developer.android.com/reference/android/provider/Settings.Secure.html#ANDROID_ID)'
        },
        {
            'name': 'google_login',
            'type': 'str',
            'description': 'A email address matching a Google account.'
        },
        {
            'name': 'google_password',
            'type': 'str',
            'description': 'The password of the previously configured Google account.'
        },
    ]

    def initialize(self):
        if not HAVE_ANDROGUARD:
            raise ModuleInitializationError(self, "Missing dependency: androguard")

        if not HAVE_GOOGLEPLAY:
            raise ModuleInitializationError(self, "Missing dependency: googleplay-api")

    def validate_signature(self, file, key='target'):
        # Verify the signature
        p = Popen(["jarsigner", "-verify", file], stdout=PIPE)
        out = p.communicate()[0]
        self.results["{}_output".format(key)] = out
        self.results["{}_status".format(key)] = ((p.returncode == 0) and (out.startswith('jar verified.')))

        # Extract the certificate
        z = ZipFile(file)
        for name in z.namelist():
            if name.startswith('META-INF/') and name.endswith('.RSA'):
                cert = z.extract(name, self.tmpdir)
                break
        z.close()

        # Extract certificate details
        p = Popen(["keytool", "-printcert", "-file", cert], stdout=PIPE)
        self.results["{}_certificate".format(key)] = p.communicate()[0]

    def download_reference_apk(self):
        api = GooglePlayAPI(self.android_id)
        api.login(self.google_login, self.google_password)

        package = api.details(self.results['package'])
        doc = package.docV2
        version = doc.details.appDetails.versionCode
        offer_type = doc.offer[0].offerType

        ref_path = path.join(self.tmpdir, "ref.apk")
        data = api.download(self.results['package'], version, offer_type)
        with open(ref_path, "wb") as out:
            out.write(data)

        return ref_path

    def each(self, target):
        self.tmpdir = tempdir()
        self.results = dict()

        apk, vm, vm_analysis = AnalyzeAPK(target)
        self.results['package'] = apk.get_package()
        self.validate_signature(target)

        ref_apk = self.download_reference_apk()
        self.validate_signature(ref_apk, "ref")

        self.results['verification_result'] = self.results['target_status'] and self.results['ref_status'] and (self.results['target_certificate'] == self.results['ref_certificate'])

        return True
