import os
import re
import json
from subprocess import check_output, CalledProcessError

from fame.core.module import ProcessingModule
from fame.common.constants import VENDOR_ROOT
from fame.common.utils import tempdir


class PDF(ProcessingModule):
    name = "pdf"
    description = "Statically analyze PDFs with peepdf."
    acts_on = ["pdf"]

    def initialize(self):
        # Get a unique name for the commands file
        self.peepdf_commands = os.path.join(tempdir(), 'peepdf_commands.txt')
        self.peepdf_path = os.path.join(VENDOR_ROOT, "peepdf", "peepdf.py")

    def each(self, target):
        self.results = {
            'exploits': [],
            'suspicious_objects': [],
            'objects_content': dict(),
            'links': []
        }

        # First, get analysis summary
        analysis = self.peepdf("-f", "-j", target)
        analysis = json.loads(analysis)['peepdf_analysis']['advanced'][0]['version_info']

        # List every suspicious object
        for object_type in ['actions', 'triggers']:
            if analysis['suspicious_elements'][object_type]:
                for element in analysis['suspicious_elements'][object_type]:
                    self.results['suspicious_objects'].append((element, analysis['suspicious_elements'][object_type][element]))
                    self.fetch_objects(target, analysis['suspicious_elements'][object_type][element])

        for element in analysis['suspicious_elements']['elements']:
            if element['vuln_cve_list']:
                self.results['exploits'].append(element)
            else:
                self.results['suspicious_objects'].append((element['name'], element['objects']))
            self.fetch_objects(target, element['objects'])

        # See if we have objects with JS
        if analysis['js_objects']:
            self.results['suspicious_objects'].append(('Objects with JS', analysis['js_objects']))

        # See if we found any exploit
        for element in analysis['suspicious_elements']['js_vulns']:
            self.results['exploits'].append(element)
            self.fetch_objects(target, element['objects'])

        # Look for links
        self.search_links(target)

        # Remove the commands file
        try:
            os.remove(self.peepdf_commands)
        except:
            pass

        return True

    def fetch_object(self, target, object_id):
        with open(self.peepdf_commands, "w") as cmd:
            cmd.write("object {}\n".format(object_id))

        return self.peepdf("-f", "-s", self.peepdf_commands, target)

    def fetch_objects(self, target, ids):
        for object_id in ids:
            self.results['objects_content'][str(object_id)] = self.fetch_object(target, object_id)

    def search_links(self, target):
        links = set()

        try:
            object_list = self.peepdf("-f", "-C", "search URI", target)
            if '[' in object_list:
                objects_with_uri = json.loads("[{}]".format(self.peepdf("-f", "-C", "search URI", target).split('[')[1].split(']')[0]))

                url_pattern = re.compile(r'/URI[ (]+([^ )\n]+)')
                for object_id in objects_with_uri:
                    content = self.fetch_object(target, object_id)
                    for url in url_pattern.finditer(content):
                        url = url.group(1)
                        if '.' in url or '/' in url:
                            links.add(url)
        except:
            self.log('warning', 'error while searching for links')

        self.results['links'] = list(links)

    def peepdf(self, *args):
        try:
            return check_output(["python", self.peepdf_path] + list(args))
        except CalledProcessError, e:
            if e.output:
                return e.output
            else:
                raise
