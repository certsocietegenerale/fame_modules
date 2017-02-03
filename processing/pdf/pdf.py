import os
import json
import uuid
from subprocess import check_output, CalledProcessError

from fame.core.module import ProcessingModule
from fame.common.constants import VENDOR_ROOT


class PDF(ProcessingModule):
    name = "pdf"
    description = "Statically analyze PDFs with peepdf."
    acts_on = ["pdf"]

    def initialize(self):
        # Get a unique name for the commands file
        self.peepdf_commands = "/tmp/{}".format(str(uuid.uuid4()))
        self.peepdf_path = os.path.join(VENDOR_ROOT, "peepdf", "peepdf.py")

    def each(self, target):
        self.results = {
            'exploits': [],
            'suspicious_objects': [],
            'objects_content': dict()
        }

        # First, get analysis summary
        analysis = self.peepdf("-j", target)
        analysis = json.loads(analysis)['peepdf_analysis']['advanced'][0]['version_info']

        # List every suspicious object
        for object_type in ['actions', 'elements', 'triggers']:
            if analysis['suspicious_elements'][object_type]:
                for element in analysis['suspicious_elements'][object_type]:
                    self.results['suspicious_objects'].append((element, analysis['suspicious_elements'][object_type][element]))
                    self.fetch_objects(target, analysis['suspicious_elements'][object_type][element])

        # See if we have objects with JS
        if analysis['js_objects']:
            self.results['suspicious_objects'].append(('Objects with JS', analysis['js_objects']))

        # See if we found any exploit
        for element in analysis['suspicious_elements']['js_vulns']:
            self.results['exploits'].append(element)
            self.fetch_objects(target, element['objects'])

        # Remove the commands file
        try:
            os.remove(self.peepdf_commands)
        except:
            pass

        return True

    def fetch_objects(self, target, ids):
        for object_id in ids:
            with open(self.peepdf_commands, "w") as cmd:
                cmd.write("object {}\n".format(object_id))

            object_content = self.peepdf("-s", self.peepdf_commands, target)
            self.results['objects_content'][str(object_id)] = object_content

    def peepdf(self, *args):
        try:
            return check_output([self.peepdf_path] + list(args))
        except CalledProcessError, e:
            if e.output:
                return e.output
            else:
                raise
