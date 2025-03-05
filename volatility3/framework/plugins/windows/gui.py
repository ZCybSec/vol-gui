# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import os
from itertools import count
from typing import List, Tuple

from volatility3.framework import interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import versions

# from volatility3.plugins.windows import pslist, vadinfo, modules

vollog = logging.getLogger(__name__)


class WinGUI(interfaces.plugins.PluginInterface):
    """Parses information about Windows GUI Objects"""

    _required_framework_version = (2, 0, 0)

    # These checks must be completed from newest -> oldest OS version.
    _win_version_file_map: List[Tuple[versions.OsDistinguisher, str]] = [
        (versions.is_win10_19577_or_later, "gui-win10-19577-x64"),
        (versions.is_win10_19041_or_later, "gui-win10-19041-x64"),
        (versions.is_win10_18362_or_later, "gui-win10-18362-x64"),
        (versions.is_win10_17763_or_later, "gui-win10-17763-x64"),
        (versions.is_win10_17134_or_later, "gui-win10-17134-x64"),
        (versions.is_win10_16299_or_later, "gui-win10-16299-x64"),
        (versions.is_win10_15063_or_later, "gui-win10-15063-x64"),
        (versions.is_win10_10586_or_later, "gui-win10-10586-x64"),
        (versions.is_windows_8_or_later, "gui-win8-x64"),
        (versions.is_windows_7_sp1, "gui-win7sp1-x64"),
        (versions.is_windows_7_sp0, "gui-win7sp0-x64"),
    ]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @staticmethod
    def create_gui_table(
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        config_path: str,
    ) -> str:
        """Creates a symbol table for windows GUI types

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of an existing symbol table containing the kernel symbols
            config_path: The configuration path within the context of the symbol table to create

        Returns:
            The name of the constructed GUI table
        """
        native_types = context.symbol_space[symbol_table].natives

        if not symbols.symbol_table_is_64bit(context, symbol_table):
            raise NotImplementedError(
                "This plugin only supports x64 versions of Windows"
            )

        table_mapping = {"nt_symbols": symbol_table}

        try:
            symbol_filename = next(
                filename
                for version_check, filename in WinGUI._win_version_file_map
                if version_check(context=context, symbol_table=symbol_table)
            )
        except StopIteration:
            raise NotImplementedError("This version of Windows is not supported!")

        vollog.debug(f"Using GUI table {symbol_filename}")

        return intermed.IntermediateSymbolTable.create(
            context,
            config_path,
            os.path.join("windows", "gui"),
            symbol_filename,
            native_types=native_types,
            table_mapping=table_mapping,
        )

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        gui_table = self.create_gui_table(
            self.context, kernel.symbol_table_name, self.config_path
        )

        c = count()
        for _ in range(10):
            yield (
                0,
                (next(c), tuple()),
            )

    def run(self):
        return renderers.TreeGrid(
            [],
            self._generator(),
        )
