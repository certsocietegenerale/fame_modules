import json
from . import APKPlugin


class Marcher(APKPlugin):
    name = "marcher"
    extraction = "Marcher Configuration"
    probable_name = "Marcher"

    def run(self, module):
        config_method = self.get_config_method()

        if not config_method:
            return None

        # Look for C2 URLs
        result = dict()
        result['c2_urls'] = self.look_for_c2_urls(module)

        # Look for a call with a string literal as argument
        for cls, method_call, offset in config_method.get_xref_from():
            pos = method_call.code.get_bc().off_to_pos(offset)
            instruction = method_call.get_instruction(pos - 1)

            # If this is a string literal, we have our configuration
            if instruction.get_name() == 'const-string':
                result['overlays'] = json.loads(instruction.get_output()[4:].strip("' "))

                module.add_ioc(result['c2_urls'], ['marcher', 'c2'])
                for overlay in result['overlays']:
                    module.add_ioc(overlay['body'], ['marcher', 'webfake'])

                return json.dumps(result, indent=2)

        return None

    def get_config_method(self):
        # First, we are searching for the string "default_json"
        strings = self.vm_analysis.find_strings('default_json')

        if strings:
            for string in strings:
                for cls, method in string.get_xref_from():
                    # Check for a specific prototype, we are looking for the method that sets 'default_json'
                    if method.get_descriptor() == '(Landroid/content/Context; Ljava/lang/String;)V':
                        return self.vm_analysis.classes[cls.name].get_method_analysis(method)

    def look_for_c2_urls(self, module):
        base_url = ""
        commands = []
        urls = []

        for string in self.vm_analysis.get_strings():
            string = string.get_value()
            if string.startswith("http"):
                base_url = string
            elif string.endswith(".php"):
                commands.append(string)

        for command in commands:
            urls.append(base_url + command)

        return urls
