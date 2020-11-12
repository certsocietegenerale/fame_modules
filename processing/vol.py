import io
from importlib import import_module

from fame.common.utils import iterify
from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ProcessingModule

try:
    import volatility.conf as conf

    HAVE_VOLATILITY = True
except ImportError:
    HAVE_VOLATILITY = False


class Volatility(ProcessingModule):
    """Abstract class for Processing Modules that rely on volatility.

    This class takes care of the necessary setup actions to use a Volatility
    plugin from Python.

    It also provides a default scenario that is the following:

    * Launch a specific volatility plugin (:attr:`plugin_name`)
    * Look for a specific pattern (:attr:`success_match`) in the plugin output
    * If it matched, create a extraction with label :attr:`extraction_label`,
    * And add a probable name of :attr:`probable_name`.

    This default scenario makes it possible to create processing modules as
    simple as::

        class Dyre(Volatility):
            name = "dyre"
            triggered_by = "*dyre*"

            plugin_name = "dyrescan"
            success_match = "Dyre main configuration"
            extraction_label = "Dyre Configuration"
            probable_name = "Dyre"

    The default scenario is only used when
    :func:`fame.modules.processing.vol.Volatility.each_dump` is not defined.

    Attributes:
        plugin_name (string): name of the volatility plugin to run. Only used
            when using the default scenario.
        success_match (string): pattern to look for in the plugin output. If
            it matched, it means the module was successful. Only used when using the default scenario.
        extraction_label (string): label to the extraction that will be added to
            the analysis if output matched. Only used when using the default
            scenario.
        probable_name (string): probable name of the malware if output matched.
            Only used when using the default scenario.
    """
    acts_on = "memory_dump"

    named_configs = {
        'volatility': {
            'description': 'Configure volatility integration.',
            'config': [
                {
                    'name': 'plugins',
                    'type': 'str',
                    'default': None,
                    'description': 'Path of additional volatility plugins'
                },
                {
                    'name': 'profile',
                    'type': 'str',
                    'default': 'Win7SP1x64',
                    'description': 'Volatility profile to use'
                },
            ]
        }
    }

    plugin_name = None
    success_match = None
    extraction_label = None
    probable_name = None

    def initialize(self):
        # Check dependencies
        if not HAVE_VOLATILITY:
            raise ModuleInitializationError(self, "Missing dependency: volatility")

        # Default configuration
        base_conf = {
            "profile": self.volatility.profile,
            "use_old_as": None,
            "kdbg": None,
            "help": False,
            "kpcr": None,
            "tz": None,
            "pid": None,
            "output_file": None,
            "physical_offset": None,
            "conf_file": None,
            "dtb": None,
            "output": None,
            "info": None,
            "plugins": self.volatility.plugins,
            "debug": None,
            "cache_dtb": True,
            "filename": None,
            "cache_directory": None,
            "verbose": None,
            "write": False
        }

        # Create Volatility API configuration
        self._volconfig = conf.ConfObject()
        self._volconfig.optparser.set_conflict_handler("resolve")
        for key, value in list(base_conf.items()):
            self._volconfig.update(key, value)

        # Get all available plugins

        # These two imports must occur after configuration init
        # Else, 'plugins' configuration will not be effective
        self._volcommands = import_module("volatility.commands")
        self._volregistry = import_module("volatility.registry")
        self._volutils = import_module("volatility.utils")

        self._volregistry.PluginImporter()
        self.plugins = self._volregistry.get_plugin_classes(self._volcommands.Command, lower=True)

        # Check if we have the right volatility plugins for this module
        if self.plugin_name is not None:
            self.needs_plugin(self.plugin_name)

    def needs_plugin(self, plugins):
        """Indicate that this module needs specific volatility plugins.

        Only useful when outside of the default scenario.

        Args:
            plugins: a string or list of strings containing volatility plugins
                names.

        Raises:
            ModuleInitializationError: when one of the plugins is not
            available."""
        for plugin in iterify(plugins):
            if plugin not in self.plugins:
                raise ModuleInitializationError(self, "volatility plugin '%s' needed" % plugin)

    def each(self, target):
        self._volconfig.update("location", "file://%s" % target)
        self._volregistry.register_global_options(self._volconfig, self._volcommands.Command)

        return self.each_dump()

    def each_dump(self):
        """To implement. Define actions that should be taken against each dump.

        When called, Volatility is already configured, and points at the
        correct memory dump.

        ``self._volconfig`` contains Volatility's configuration.
        ``self.plugins`` contains available plugin classes.

        Only define this method if cases where the default scenario does not
        work.
        """
        self.needs_variable(('plugin_name', 'success_match'))

        # Run volatility plugin
        plugin = self.plugins[self.plugin_name](self._volconfig)
        data = plugin.calculate()

        # Get normal output in string
        outfd = io.StringIO()
        plugin.render_text(outfd, data)
        result = outfd.getvalue()
        outfd.close()

        # See if output is matching
        if result.find(self.success_match) != -1:
            if self.extraction_label is not None:
                self.add_extraction(self.extraction_label, result)
            if self.probable_name is not None:
                self.add_probable_name(self.probable_name)

            self.post_processing(result)

            return True
        else:
            return False

    def post_processing(self, result):
        """To implement. Do something with the plugin's output.

        This method is automatically called in the default scenario when a match
        occured. Modules should define this method in order to do post
        processing on the plugin's output, such as extracting IOCs.

        Args:
            result (string): output of the Volatility plugin
        """
        pass
