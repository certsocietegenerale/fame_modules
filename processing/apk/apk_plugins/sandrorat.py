import json
from . import APKPlugin


class SandroRAT(APKPlugin):
    name = "sandrorat"
    extraction = "SandroRAT Configuration"
    probable_name = "SandroRAT"

    def run(self, module):
        for s in self.vm_analysis.get_strings():
            s = s.get_value()
            if 'sandrorat' in s.lower() or 'droidjack' in s.lower():
                break
        else:
            return None

        c2 = []
        port = []
        for cls in self.vm_analysis.get_classes():
            if (
                len(cls.get_fields()) == 3 and
                set(['a', 'b', 'c']) == set([x.name for x in cls.get_fields()]) and
                len(cls.get_methods()) == 1 and
                cls.get_methods()[0].name.endswith('<clinit>')
            ):
                clinit = cls.get_methods()[0]

                for inst in clinit.get_method().get_instructions():
                    if inst.get_name() == 'const-string':
                        c2.append(inst.get_output().split(',')[-1].strip(" '"))
                    elif inst.get_name() == 'const/16':
                        port.append(int(inst.get_output().split(',')[-1].strip(" '")))
        servers = []
        for i, server in enumerate(c2):
            if len(port) > i:
                servers.append(server + ':' + str(port[i]))
            else:
                servers.append(server)

        module.add_ioc(servers, ['sandrorat', 'c2'])

        return json.dumps({'c2': servers}, indent=2)
