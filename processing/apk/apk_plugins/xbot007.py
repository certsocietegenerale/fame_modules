import json
from . import APKPlugin


REMOVE_CHARACTERS = {ord(c): None for c in "#%"}


class Xbot007(APKPlugin):
    name = "xbot007"
    extraction = "Xbot007 Configuration"
    probable_name = "Xbot007"

    def run(self, module):
        if self.apk is None:
            return None

        for s in self.vm_analysis.get_strings():
            if "xbot007" in s.get_value().lower().translate(REMOVE_CHARACTERS):
                break
        else:
            return None

        php_end = None
        for string in self.vm_analysis.get_strings():
            string = string.get_value()
            if string.endswith(".php"):
                php_end = string

        host = []
        hostname = self.apk.get_android_resources().get_string(self.apk.get_package(), "domain")
        if hostname:
            host.append(hostname[1])
        hostname = self.apk.get_android_resources().get_string(self.apk.get_package(), "domain2")
        if hostname:
            host.append(hostname[1])
        for cls in self.vm_analysis.get_classes():
            # There has to be a better method to do THIS
            if (
                len(cls.get_methods()) == 1
                and cls.get_methods()[0].name == "<clinit>"
                and len(cls.get_fields()) >= 2
                and len(cls.get_fields()) < 10
            ):
                for inst in cls.get_methods()[0].get_method().get_instructions():
                    if inst.get_name() == "const-string":
                        host.append(
                            inst.get_output()
                            .translate(REMOVE_CHARACTERS)
                            .split(",")[-1]
                            .strip("' ")
                        )
        host = [x for x in host if not x.endswith(".apk")]
        host = [x for x in host if x]
        c2 = [("http://" + h + "/" + php_end) for h in host]

        module.add_ioc(c2, ["xbot007", "c2"])

        return json.dumps({"c2": c2}, indent=2)

        return None
