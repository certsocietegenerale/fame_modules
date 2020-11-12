import json
import base64
import xml.etree.ElementTree as ET

from . import APKPlugin

try:
    from Crypto.Cipher import Blowfish
    HAVE_PYCRYPTO = True
except ImportError:
    HAVE_PYCRYPTO = False


class ThoughtCrime(APKPlugin):
    name = "thoughtcrime"
    extraction = "ThoughtCrime Configuration"
    probable_name = "ThoughtCrime"

    def run(self, module):
        if not HAVE_PYCRYPTO:
            module.log('warning', 'thoughtcrime: missing dependency: pycrypto')
            return None

        if self.zipfile and 'res/raw/blfs.key' in self.zipfile.namelist() and 'res/raw/config.cfg' in self.zipfile.namelist():
            iv = "12345678"  # this has to be done better
            key = self.zipfile.open('res/raw/blfs.key').read()
            key = ''.join(['%x' % x for x in key])[0:50]
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            decode = base64.b64decode(self.zipfile.open('res/raw/config.cfg').read())
            config = cipher.decrypt(decode)
            config = config[:config.find(b'</config>') + 9]
            config = ET.fromstring(config)
            c2 = config.findall('.//data')[0].get('url_main').split(';')
            phone = config.findall('.//data')[0].get('phone_number')

            module.add_ioc(c2, ['thoughtcrime', 'c2'])

            return json.dumps({'c2': c2, 'phone': phone}, indent=2)
        else:
            return None
