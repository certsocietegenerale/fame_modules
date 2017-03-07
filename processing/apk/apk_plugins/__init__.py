import os
import glob
from zipfile import ZipFile


modules = glob.glob(os.path.dirname(__file__) + "/*.py")
__all__ = [os.path.basename(f)[:-3] for f in modules] + ['APKPlugin']


class APKPlugin(object):
    """Base class for plugins that try to perform extractions with Androguard

    All plugins that inherit from this class and are located in the same
    directory (`fame/modules/processing/apk_plugins`) will automatically be
    executed by the `apk` processing module.

    Plugins should define the
    :func:`fame.modules.processing.apk_plugins.APKPlugin.run`
    method.

    Plugins can access instance variables ``self.apk``, ``self.vm`` and
    ``self.vm_analysis`` that are the result of Androguard's ``AnalyzeAPK``.
    ``self.zipfile`` is also available, containing the APK's ZipFile object.

    Attributes:
        name (string): Name of the plugin.
        extraction (string): Label for the extraction if the module was
            successful.
        probable_name (string): Probable name of the malware if the module was
            successful.

    """
    name = None
    extraction = None
    probable_name = None

    def __init__(self, target, apk, vm, vm_analysis):
        self.apk = apk
        self.vm = vm
        self.vm_analysis = vm_analysis
        if self.apk:
            self.zipfile = ZipFile(target)
        else:
            self.zipfile = None

    def apply(self, module):
        extraction = self.run(module)
        if extraction:
            module.add_tag(self.name)
            module.add_probable_name(self.probable_name)
            module.add_extraction(self.extraction, extraction)

    def run(self, module):
        """To implement. Perform some static analysis on the APK.

        Returns:
            Should return the extraction content if the module was successful,
            ``False`` otherwise."""
        raise NotImplementedError
