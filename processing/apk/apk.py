from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from .apk_plugins import *


try:
    from androguard.misc import AnalyzeAPK, AnalyzeDex
    HAVE_ANDROGUARD = True
except ImportError:
    HAVE_ANDROGUARD = False


class APK(ProcessingModule):
    name = "apk"
    description = "Perform static analysis on APK/DEX files. Will also run static analysis modules trying to extract configuration from known Android malware."
    acts_on = ["apk", "dex"]

    def initialize(self):
        if not HAVE_ANDROGUARD:
            raise ModuleInitializationError(self, "Missing dependency: androguard")

    def each(self, target):
        self.results = dict()

        try:
            apk, vm, vm_analysis = AnalyzeAPK(target)

            # First, get basic information about the APK
            self.results['name'] = apk.get_app_name()
            self.results['package'] = apk.get_package()
            self.results['permissions'] = apk.get_permissions()
            self.results['main_activity'] = apk.get_main_activity()
            self.results['receivers'] = apk.get_receivers()
            self.results['services'] = apk.get_services()

            for cls in vm_analysis.get_classes():
                cls = cls.get_vm_class()
                if f"L{self.results['main_activity'].replace('.', '/')};".lower() in cls.get_name().lower():
                    self.results['main_activity_content'] = cls.get_source()
        except Exception:
            apk = None
            vm, vm_analysis = AnalyzeDex(target)
            self.results['dex'] = True

        # Then, run all the APK Plugins in order to see if this is a known malware
        for plugin in APKPlugin.__subclasses__():
            plugin = plugin(target, apk, vm, vm_analysis)
            plugin.apply(self)

        return True
