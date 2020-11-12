import gzip
import json
from io import BytesIO
from . import APKPlugin

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

try:
    from elftools.elf.elffile import ELFFile
    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False


class Z3Core(APKPlugin):
    name = "z3core"
    extraction = "Z3Core Configuration"
    probable_name = "Z3Core"

    WHITELISTED_DLL = [
        'System_Core_dll', 'NLua_Android_dll',
        'KopiLua_Android_dll', 'Mono_Android_dll',
        'Z_VFS_Android_dll', 'Xamarin_Mobile_dll',
        'mscorlib_dll', 'System_dll', 'Mono_Android_Export_dll',
        'System_Xml_dll'
    ]

    def run(self, module):
        if not HAVE_YARA:
            module.log('warning', 'z3core: missing dependency: yara')
            return None
        if not HAVE_ELFTOOLS:
            module.log('warning', 'z3core: missing dependency: elftools')
            return None

        if self.zipfile is None:
            return None

        bundle = False
        if 'lib/armeabi-v7a/libmonodroid.so' in self.zipfile.namelist() and 'lib/armeabi-v7a/libmonodroid_bundle_app.so' in self.zipfile.namelist():
            bundle = 'lib/armeabi-v7a/libmonodroid_bundle_app.so'
        elif 'lib/armeabi/libmonodroid.so' in self.zipfile.namelist() and 'lib/armeabi/libmonodroid_bundle_app.so' in self.zipfile.namelist():
            bundle = 'lib/armeabi/libmonodroid_bundle_app.so'

        if not bundle:
            return None

        c2 = []
        f = self.zipfile.open(bundle)
        data = f.read()
        f = BytesIO(data)
        elffile = ELFFile(f)
        section = elffile.get_section_by_name('.dynsym')
        for symbol in section.iter_symbols():
            if symbol['st_shndx'] != 'SHN_UNDEF' and symbol.name.startswith('assembly_data_'):
                if symbol.name[14:] in self.WHITELISTED_DLL:
                    continue
                dll_data = data[symbol['st_value']:symbol['st_value'] + symbol['st_size']]
                dll_data = gzip.GzipFile(fileobj=BytesIO(dll_data)).read()
                regexp = """rule find_url {
                            strings:
                            $url = /http:\/\/[A-Za-z0-9\.\/$\-_+!\*'(),]*/ wide
                            condition:
                            $url}"""
                compiled = yara.compile(source=regexp)
                s = compiled.match(data=dll_data)

                for entry in s[0].strings:
                    cc = dll_data[entry[0]:entry[0] + len(entry[2])].decode('utf-16')
                    c2.append(cc)

        if c2:
            module.add_ioc(c2, ['z3core', 'c2'])

            return json.dumps({'c2': c2}, indent=2)
        else:
            return None
