# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Dict, Iterator

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules

from volatility3.framework import interfaces, deprecation
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, TreeGrid, NotAvailableValue
from volatility3.framework.symbols.linux import extensions
from volatility3.framework.constants import architectures
from volatility3.framework.symbols.linux.utilities import tainting

vollog = logging.getLogger(__name__)


class Modxview(interfaces.plugins.PluginInterface):
    """Centralize lsmod, check_modules and hidden_modules results to efficiently \
spot modules presence and taints."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 17, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="linux_utilities_modules",
                component=linux_utilities_modules.Modules,
                version=(2, 0, 0),
            ),
            requirements.VersionRequirement(
                name="linux-tainting", component=tainting.Tainting, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="plain_taints",
                description="Display the plain taints string for each module.",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    @deprecation.deprecated_method(
        replacement=linux_utilities_modules.Modules.flatten_run_modules_results,
        replacement_version=(2, 0, 0),
    )
    def flatten_run_modules_results(
        cls, run_results: Dict[str, List[extensions.module]], deduplicate: bool = True
    ) -> Iterator[extensions.module]:
        """Flatten a dictionary mapping plugin names and modules list, to a single merged list.
        This is useful to get a generic lookup list of all the detected modules.

        Args:
            run_results: dictionary of plugin names mapping a list of detected modules
            deduplicate: remove duplicate modules, based on their offsets

        Returns:
            Iterator of modules objects
        """
        return linux_utilities_modules.Modules.flatten_run_modules_results(
            run_results, deduplicate
        )

    @classmethod
    @deprecation.deprecated_method(
        replacement=linux_utilities_modules.Modules.run_modules_scanners,
        replacement_version=(2, 0, 0),
    )
    def run_modules_scanners(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_name: str,
        run_hidden_modules: bool = True,
    ) -> Dict[str, List[extensions.module]]:
        """Run module scanning plugins and aggregate the results. It is designed
        to not operate any inter-plugin results triage."""
        return linux_utilities_modules.Modules.run_modules_scanners(
            context, kernel_name, run_hidden_modules
        )

    def _generator(self):
        kernel_name = self.config["kernel"]

        kernel = self.context.modules[kernel_name]

        run_results = linux_utilities_modules.Modules.run_modules_scanners(
            self.context, kernel_name, flatten=False
        )

        aggregated_modules = {}
        # We want to be explicit on the plugins results we are interested in
        for plugin_name in ["lsmod", "check_modules", "hidden_modules"]:
            # Iterate over each recovered module
            for mod_info in run_results[plugin_name]:
                # Use offsets as unique keys, whether a module
                # appears in many plugin runs or not
                if aggregated_modules.get(mod_info.offset, None) is not None:
                    # Append the plugin to the list of originating plugins
                    aggregated_modules[mod_info.offset].append(plugin_name)
                else:
                    aggregated_modules[mod_info.offset] = [plugin_name]

        for module_offset, originating_plugins in aggregated_modules.items():
            # Tainting parsing capabilities applied to the module
            module = kernel.object("module", offset=module_offset, absolute=True)

            if self.config.get("plain_taints"):
                taints = tainting.Tainting.get_taints_as_plain_string(
                    self.context,
                    kernel_name,
                    module.taints,
                    True,
                )
            else:
                taints = ",".join(
                    tainting.Tainting.get_taints_parsed(
                        self.context,
                        kernel_name,
                        module.taints,
                        True,
                    )
                )

            yield (
                0,
                (
                    module.get_name() or NotAvailableValue(),
                    format_hints.Hex(module_offset),
                    "lsmod" in originating_plugins,
                    "check_modules" in originating_plugins,
                    "hidden_modules" in originating_plugins,
                    taints or NotAvailableValue(),
                ),
            )

    def run(self):
        columns = [
            ("Name", str),
            ("Address", format_hints.Hex),
            ("In procfs", bool),
            ("In sysfs", bool),
            ("Hidden", bool),
            ("Taints", str),
        ]

        return TreeGrid(
            columns,
            self._generator(),
        )
