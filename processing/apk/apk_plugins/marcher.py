import re
import json
from . import APKPlugin


class Marcher(APKPlugin):
    name = "marcher"
    extraction = "Marcher Configuration"
    probable_name = "Marcher"

    def run(self, module):
        # First, we are searching for the string "default_json"
        variable = self.vm_analysis.get_tainted_variables().get_string('default_json')

        if variable is None:
            return None

        for path in variable.get_paths():
            # We get the method info using the payh idx
            method = self.vm.CM.get_method_ref(path[1])

            # Check for a specific prototype, we are looking for the method that sets 'default_json'
            if method.get_descriptor() == '(Landroid/content/Context; Ljava/lang/String;)V':
                break
        # If we did not find any matching method, exit
        else:
            return None

        # Look for C2 URLs
        result = dict()
        result['c2_urls'] = self.look_for_c2_urls(module)

        # Now that we have the method, look for method calls
        method_calls = self.vm_analysis.get_tainted_packages().search_methods(method.get_class_name(), method.get_name(), re.escape(method.get_descriptor()))

        # Look for a call with a string literal as argument
        for method_call in method_calls:
            # Get the calling method object
            src_method = self.vm.get_method_by_idx(method_call.get_src_idx())
            # Get the method call position
            pos = src_method.code.get_bc().off_to_pos(method_call.get_idx())
            # Look at previous instruction
            instruction = src_method.code.get_bc().get_instruction(pos - 1)
            # If this is a string literal, we have our configuration
            if instruction.get_name() == 'const-string':
                result['overlays'] = json.loads(instruction.get_output()[4:].strip("' "))

                module.add_ioc(result['c2_urls'], ['marcher', 'c2'])
                for overlay in result['overlays']:
                    module.add_ioc(overlay['body'], ['marcher', 'webfake'])

                return json.dumps(result, indent=2)

        return None

    def look_for_c2_urls(self, module):
        base_url = ""
        commands = []
        urls = []

        for string in self.vm.get_strings():
            if string.startswith("http"):
                base_url = string
            elif string.endswith(".php"):
                commands.append(string)

        for command in commands:
            urls.append(base_url + command)

        return urls
