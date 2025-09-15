import os
import hashlib
from shutil import rmtree
from typing import Any

from fame.core.module import ProcessingModule, ModuleInitializationError, ModuleExecutionError
from fame.common.utils import tempdir

try:
    from peepdf import PDFCore, PDFVulns
    HAVE_PEEPDF = True
except ImportError:
    HAVE_PEEPDF = False
    class PDFCore:
        # declare a fake class
        # To prevent errors when peepdf is missing
        PDFFile = PDFIndirectObject = PDFDictionary = None
        

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


def js_beautify_string(string):
    if HAVE_JSBEAUTIFY:
        string = beautify(string)

    return string


class Peepdf(ProcessingModule):
    name = "peepdf"
    description = "Analyze PDF files with peepdf."
    acts_on = "pdf"

    config = [
        {
            "name": "skip_safe_file_review",
            "type": "bool",
            "default": False,
            "description": "Skip file review when no suspicious elements are found."
        }
    ]

    def initialize(self):
        if not HAVE_PEEPDF:
            raise ModuleInitializationError(self, "Missing dependency: peepdf-3")

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

    def extract_attachments(self, pdf: PDFCore.PDFFile, obj: PDFCore.PDFIndirectObject, version: int) -> None:
        object = obj.getObject()
        if not isinstance(object, PDFCore.PDFDictionary):
            return

        if "/F" not in object.elements:
            return
        if "/EF" not in object.elements:
            return

        filename = object.elements["/F"]
        if not isinstance(filename, PDFCore.PDFString):
            return

        ref = object.elements["/EF"]
        if not isinstance(ref, PDFCore.PDFDictionary):
            return

        if "/F" not in ref.elements:
            return

        ref = ref.elements["/F"]
        if not isinstance(ref, PDFCore.PDFReference):
            return

        if ref.getId() not in pdf.body[version].objects:
            return

        obj = pdf.body[version].objects[ref.getId()]
        self.extract_file(filename.value, obj.getObject().decodedStream)

    def extract_link(self, obj: PDFCore.PDFDictionary) -> None:
        if "/URI" in obj.elements:
            if isinstance(obj.elements['/URI'], PDFCore.PDFString):
                url = obj.elements['/URI'].value
                self.add_ioc(url)
                self.results['urls'].add(url)

    def extract_javascript(self, pdf: PDFCore.PDFFile, obj: PDFCore.PDFDictionary, version: int) -> None:
        if "/JS" in obj.elements:
            ref = obj.elements["/JS"]

            if isinstance(ref, PDFCore.PDFReference):
                if ref.getId() not in pdf.body[version].objects:
                    return

                js = pdf.body[version].objects[ref.getId()].getObject().decodedStream
            elif isinstance(ref, PDFCore.PDFString):
                js = ref.value

            self.results['javascript'] += "{}\n\n".format(js_beautify_string(js))

    def walk_objects(self, pdf: PDFCore.PDFFile, obj: object, version: int) -> None:
        if isinstance(obj, PDFCore.PDFIndirectObject):
            self.walk_objects(pdf, obj.getObject(), version)
        elif isinstance(obj, PDFCore.PDFDictionary):
            self.extract_link(obj)
            self.extract_javascript(pdf, obj, version)

            for element in list(obj.elements.values()):
                self.walk_objects(pdf, element, version)
        elif isinstance(obj, PDFCore.PDFArray):
            for element in obj.elements:
                self.walk_objects(pdf, element, version)

    def extract_elements(self, pdf: PDFCore.PDFFile) -> None:
        stats = pdf.getStats()

        for version in stats['Versions']:
            for subtype in ['Events', 'Actions', 'Elements', 'Vulns']:
                if version[subtype] is not None:
                    for element in version[subtype]:
                        if element in self.results:
                            self.results[element].update(version[subtype][element])
                        elif element in PDFVulns.vulnsDict:
                            self.results['vulns'].append((
                                element,
                                version[subtype][element], PDFVulns.vulnsDict[element][1]
                            ))

    def get_object(self, pdf: PDFCore.PDFFile, object_id: int) -> str:
        object: PDFCore.PDFObject = pdf.getObject(object_id)
        return object.getValue()

    def extract_objects(self, pdf: PDFCore.PDFFile) -> None:
        for element_type in [
            '/Names', '/OpenAction', '/AA', '/AcroForm', '/XFA', '/Launch', '/SubmitForm',
            '/ImportData', '/RichMedia', '/Flash'
        ]:
            for object_id in self.results[element_type]:
                self.results['objects'][str(object_id)] = self.get_object(pdf, object_id)

        for vuln in self.results['vulns']:
            for object_id in vuln[1]:
                self.results['objects'][str(object_id)] = self.get_object(pdf, object_id)

    def convert_sets(self) -> None:
        for key in self.results:
            if isinstance(self.results[key], set):
                self.results[key] = list(self.results[key])

    def each(self, target: str) -> bool:
        self._outdir = None

        self.results: dict[str, Any] = {
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
        try:
            pdf: PDFCore.PDFFile
            result, pdf = PDFCore.PDFParser().parse(
                target,
                forceMode=True,
                looseMode=True
            )
        except Exception as e:
            result = e

        if result:
            raise ModuleExecutionError('error during PDF parsing: {}'.format(result))

        for version in range(pdf.updates + 1):
            body: PDFCore.PDFBody = pdf.body[version]
            obj: PDFCore.PDFIndirectObject
            for obj in list(body.objects.values()):
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
        if clean and self.skip_safe_file_review:
            self.skip_review()

        return True
