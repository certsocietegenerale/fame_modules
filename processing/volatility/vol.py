import os

from fame.common.utils import iterify
from fame.common.exceptions import ModuleInitializationError
from fame.core.module import ProcessingModule

try:
    import volatility
    import volatility.plugins
    from volatility.framework.interfaces.configuration import path_join
    from volatility.framework.interfaces.plugins import FileHandlerInterface
    from volatility.framework import (
        automagic,
        constants,
        contexts,
        plugins as volplugins,
    )

    HAVE_VOLATILITY = True
except ImportError:
    HAVE_VOLATILITY = False


class MuteProgress:
    """A dummy progress handler that produces no output when called."""

    def __call__(self, progress, description):
        pass


class VolatilityModule(ProcessingModule):
    """Abstract class for Processing Modules that rely on volatility.

    This class takes care of the necessary setup actions to use a Volatility
    plugin from Python.
    """

    acts_on = "memory_dump"

    named_configs = {
        "volatility": {
            "description": "Configure volatility integration.",
            "config": [
                {
                    "name": "plugins",
                    "type": "str",
                    "default": None,
                    "description": "Path of additional volatility plugins",
                },
            ],
        }
    }

    def initialize(self):
        # Check dependencies
        if not HAVE_VOLATILITY:
            raise ModuleInitializationError(self, "Missing dependency: volatility")

        # Make sure installed volatility is compatible
        volatility.framework.require_interface_version(2, 0, 0)

        # Create the context and list plugins
        self.vol_ctx = contexts.Context()

        volatility.plugins.__path__ = constants.PLUGINS_PATH

        if self.volatility.plugins and os.path.isdir(self.volatility.plugins):
            volatility.plugins.__path__.append(self.volatility.plugins)

        volatility.framework.import_files(volatility.plugins, True)
        self.plugins = volatility.framework.list_plugins()

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
                raise ModuleInitializationError(self, "volatility plugin '{}' needed".format(plugin))

    def configure_plugin(self, plugin_name, **kwargs):
        """Configure and return a plugin

        Args:
            plugin_name: name of the plugin to configure, as a string.
            **kwargs: configuration options passed to the plugin

        Returns:
            The instantiated and configure volatility plugin.
        """
        plugin = self.plugins[plugin_name]

        # Set arguments
        for key, value in kwargs.items():
            config_path = path_join("plugins", plugin.__name__, key)
            self.vol_ctx.config[config_path] = value

        # Filter automagics
        available_automagics = automagic.available(self.vol_ctx)
        automagics = automagic.choose_automagic(available_automagics, plugin)

        # Instantiate the plugin
        return volplugins.construct_plugin(
            self.vol_ctx,
            automagics,
            plugin,
            "plugins",
            MuteProgress(),
            FileHandlerInterface,
        )

    def run_plugin(self, plugin_name, **kwargs):
        """Run a specific Volatility Plugin.

        Only useful when outside of the default scenario.

        Args:
            plugin_name: name of the plugin to run, as a string.

        Returns:
            The plugin's result, as a list of dict objects
        """
        plugin_instance = self.configure_plugin(plugin_name, **kwargs)

        # Run the plugin and return results
        return self._convert(plugin_instance.run())

    def each(self, target):
        self.vol_ctx.config["automagic.LayerStacker.single_location"] = "file://{}".format(target)

        return self.each_dump()

    def each_dump(self):
        """To implement. Define actions that should be taken against each dump.

        When called, Volatility is already configured, and points at the
        correct memory dump.

        ``self.vol_ctx`` contains the Volatility context.
        ``self.plugins`` contains available plugin classes.
        """
        raise NotImplementedError

    def _convert(self, results):
        """Convert TreeGrid plugin results into a list of dict objects.

        Args:
            results: TreeGrid: results of a plugin execution

        Returns:
            The results, formatted as a list of dict objects.
        """
        columns = [column.name for column in results.columns]
        formatted_results = []

        def visitor(node, _):
            node_results = {}

            for offset in range(len(columns)):
                node_results[columns[offset]] = node.values[offset]

            formatted_results.append(node_results)

        results.populate(visitor)

        return formatted_results
