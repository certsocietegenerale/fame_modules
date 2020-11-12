import os
import hashlib
from shutil import rmtree

from fame.core.module import ProcessingModule, ModuleInitializationError, ModuleExecutionError
from fame.common.utils import tempdir

try:
    import peepdf
    HAVE_PEEPDF = True
except ImportError:
    HAVE_PEEPDF = False

try:
    from jsbeautifier import beautify
    HAVE_JSBEAUTIFY = True
except ImportError:
    HAVE_JSBEAUTIFY = False


def file_sha256(filepath):
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while True:
            data = f.read(1000000)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()


def js_beautify_string(string):
    if HAVE_JSBEAUTIFY:
        string = beautify(string)

    return string


class Peepdf(ProcessingModule):
    name = "peepdf"
    description = "Analyze PDF files with peepdf."
    acts_on = "pdf"

    def initialize(self):
        if not HAVE_PEEPDF:
            raise ModuleInitializationError(self, "Missing dependency: peepdf")

    def outdir(self):
        if self._outdir is None:
            self._outdir = tempdir()

        return self._outdir

    def clean_up(self):
        if self._outdir is not None:
            rmtree(self._outdir)

    def extract_file(self, name, data):
        fpath = os.path.join(self.outdir(), name)

        with open(fpath, 'w') as f:
            f.write(data)

        self.add_extracted_file(fpath)

        sha256 = file_sha256(fpath)
        self.results['files'].add(sha256)

    def extract_attachments(self, pdf, obj, version):
        if not isinstance(obj.object, peepdf.PDFCore.PDFDictionary):
            return

        if "/F" not in obj.object.elements:
            return
        if "/EF" not in obj.object.elements:
            return

        filename = obj.object.elements["/F"]
        if not isinstance(filename, peepdf.PDFCore.PDFString):
            return

        ref = obj.object.elements["/EF"]
        if not isinstance(ref, peepdf.PDFCore.PDFDictionary):
            return

        if "/F" not in ref.elements:
            return

        ref = ref.elements["/F"]
        if not isinstance(ref, peepdf.PDFCore.PDFReference):
            return

        if ref.id not in pdf.body[version].objects:
            return

        obj = pdf.body[version].objects[ref.id]
        self.extract_file(filename.value, obj.object.decodedStream)

    def extract_link(self, obj):
        if "/URI" in obj.elements:
            if isinstance(obj.elements['/URI'], peepdf.PDFCore.PDFString):
                url = obj.elements['/URI'].value
                self.add_ioc(url)
                self.results['urls'].add(url)

    def extract_javascript(self, pdf, obj, version):
        if "/JS" in obj.elements:
            ref = obj.elements["/JS"]

            if isinstance(ref, peepdf.PDFCore.PDFReference):
                if ref.id not in pdf.body[version].objects:
                    return

                js = pdf.body[version].objects[ref.id].object.decodedStream
            elif isinstance(ref, peepdf.PDFCore.PDFString):
                js = ref.value

            self.results['javascript'] += "{}\n\n".format(js_beautify_string(js))

    def walk_objects(self, pdf, obj, version):
        if isinstance(obj, peepdf.PDFCore.PDFIndirectObject):
            self.walk_objects(pdf, obj.object, version)
        elif isinstance(obj, peepdf.PDFCore.PDFDictionary):
            self.extract_link(obj)
            self.extract_javascript(pdf, obj, version)

            for element in list(obj.elements.values()):
                self.walk_objects(pdf, element, version)
        elif isinstance(obj, peepdf.PDFCore.PDFArray):
            for element in obj.elements:
                self.walk_objects(pdf, element, version)

    def extract_elements(self, pdf):
        stats = pdf.getStats()

        for version in stats['Versions']:
            for subtype in ['Events', 'Actions', 'Elements', 'Vulns']:
                if version[subtype] is not None:
                    for element in version[subtype]:
                        if element in self.results:
                            self.results[element].update(version[subtype][element])
                        elif element in peepdf.PDFCore.vulnsDict:
                            self.results['vulns'].append((
                                element,
                                version[subtype][element], peepdf.PDFCore.vulnsDict[element][1]
                            ))

    def get_object(self, pdf, object_id):
        return pdf.getObject(object_id).getValue()

    def extract_objects(self, pdf):
        for element_type in [
            '/Names', '/OpenAction', '/AA', '/AcroForm', '/XFA', '/Launch', '/SubmitForm',
            '/ImportData', '/RichMedia', '/Flash'
        ]:
            for object_id in self.results[element_type]:
                self.results['objects'][str(object_id)] = self.get_object(pdf, object_id)

        for vuln in self.results['vulns']:
            for object_id in vuln[1]:
                self.results['objects'][str(object_id)] = self.get_object(pdf, object_id)

    def convert_sets(self):
        for key in self.results:
            if isinstance(self.results[key], set):
                self.results[key] = list(self.results[key])

    def each(self, target):
        self._outdir = None

        self.results = {
            'files': set(),
            'urls': set(),
            'vulns': [],
            '/Names': set(),
            '/OpenAction': set(),
            '/AA': set(),
            '/AcroForm': set(),
            '/XFA': set(),
            '/JS': set(),
            '/JavaScript': set(),
            '/Launch': set(),
            '/SubmitForm': set(),
            '/ImportData': set(),
            '/RichMedia': set(),
            '/Flash': set(),
            'javascript': "",
            'objects': {}
        }

        result, pdf = peepdf.PDFCore.PDFParser().parse(
            target,
            forceMode=True,
            looseMode=True
        )

        if result:
            raise ModuleExecutionError('error during PDF parsing: {}'.format(result))

        for version in range(pdf.updates + 1):
            for obj in list(pdf.body[version].objects.values()):
                self.extract_attachments(pdf, obj, version)
                self.walk_objects(pdf, obj, version)

        self.extract_elements(pdf)
        self.extract_objects(pdf)
        self.convert_sets()

        self.clean_up()

        clean = True
        for element_type in self.results:
            if self.results[element_type]:
                clean = False

        self.results['clean'] = clean

        return True
