import json
from . import APKPlugin


class Xbot007(APKPlugin):
    name = "xbot007"
    extraction = "Xbot007 Configuration"
    probable_name = "Xbot007"

    def run(self, module):
        if self.apk is None:
            return None

        for s in self.vm.get_strings():
            if 'xbot007' in s.lower().translate(None, '#%'):
                break
        else:
            return None

        php_end = None
        for string in self.vm.get_strings():
            if string.endswith('.php'):
                php_end = string

        host = []
        hostname = self.apk.get_android_resources().get_string(self.apk.get_package(), 'domain')
        if hostname:
            host.append(hostname[1])
        hostname = self.apk.get_android_resources().get_string(self.apk.get_package(), 'domain2')
        if hostname:
            host.append(hostname[1])
        for cls in self.vm.get_classes():
            # There has to be a better method to do THIS
            if len(cls.get_methods()) == 1 and\
                cls.get_methods()[0].name == '<clinit>' and\
                len(cls.get_fields()) >= 2 and\
                len(cls.get_fields()) < 10:
                for inst in cls.get_methods()[0].get_instructions():
                    if inst.get_name() == 'const-string':
                        host.append(inst.get_output().translate(None, '#%').split(',')[-1].strip("' "))
        host = filter(lambda x: not x.endswith('.apk'), host)
        host = filter(lambda x: x, host)
        c2 = map(lambda h: ('http://' + h + '/' + php_end), host)

        module.add_ioc(c2, ['xbot007', 'c2'])

        return json.dumps({'c2': c2}, indent=2)
