# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from typing import Iterator, List, Tuple, Iterable

from volatility3.framework import (
    renderers,
    interfaces,
    constants,
    symbols,
    exceptions,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import versions, extensions
from volatility3.plugins.windows import ssdt, kpcrs

vollog = logging.getLogger(__name__)


class Timers(interfaces.plugins.PluginInterface):
    """Print kernel timers and associated module DPCs"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="ssdt", component=ssdt.SSDT, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="kpcrs", component=kpcrs.KPCRs, version=(2, 0, 0)
            ),
        ]

    @classmethod
    def list_timers(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> Iterable[extensions.KTIMER]:
        """Lists all kernel timers.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate

        Yields:
            A _KTIMER entry
        """

        kernel = context.modules[kernel_module_name]
        if versions.is_windows_7(
            context=context, symbol_table=kernel.symbol_table_name
        ) or versions.is_windows_8_or_later(
            context=context, symbol_table=kernel.symbol_table_name
        ):
            # Starting with Windows 7, there is no more KiTimerTableListHead. The list is
            # at _KPCR.PrcbData.TimerTable.TimerEntries
            # See http://pastebin.com/FiRsGW3f
            for kpcr, _ in kpcrs.KPCRs.list_kpcrs(context, kernel_module_name):
                if hasattr(kpcr.Prcb.TimerTable, "TableState"):
                    for timer_entries in kpcr.Prcb.TimerTable.TimerEntries:
                        for timer_entry in timer_entries:
                            for timer in timer_entry.Entry.to_list(
                                kernel.symbol_table_name + constants.BANG + "_KTIMER",
                                "TimerListEntry",
                            ):
                                yield timer

                else:
                    for timer_entries in kpcr.Prcb.TimerTable.TimerEntries:
                        for timer in timer_entries.Entry.to_list(
                            kernel.symbol_table_name + constants.BANG + "_KTIMER",
                            "TimerListEntry",
                        ):
                            yield timer

        elif versions.is_xp_or_2003(
            context=context, symbol_table=kernel.symbol_table_name
        ) or versions.is_vista_or_later(
            context=context, symbol_table=kernel.symbol_table_name
        ):
            is_64bit = symbols.symbol_table_is_64bit(context, kernel.symbol_table_name)
            if is_64bit or versions.is_vista_or_later(
                context=context, symbol_table=kernel.symbol_table_name
            ):
                # On XP x64, Windows 2003 SP1-SP2, and Vista SP0-SP2, KiTimerTableListHead
                # is an array of 512 _KTIMER_TABLE_ENTRY structs.
                array_size = 512
            else:
                # On XP SP0-SP3 x86 and Windows 2003 SP0, KiTimerTableListHead
                # is an array of 256 _LIST_ENTRY for _KTIMERs.
                array_size = 256

            timer_table_list_head = kernel.object(
                object_type="array",
                offset=kernel.get_symbol("KiTimerTableListHead").address,
                subtype=kernel.get_type("_LIST_ENTRY"),
                count=array_size,
            )
            for table in timer_table_list_head:
                for timer in table.to_list(
                    kernel.symbol_table_name + constants.BANG + "_KTIMER",
                    "TimerListEntry",
                ):
                    yield timer

        else:
            raise NotImplementedError("This version of Windows is not supported!")

    def _generator(self) -> Iterator[Tuple]:
        collection = ssdt.SSDT.build_module_collection(
            context=self.context,
            kernel_module_name=self.config["kernel"],
        )

        # FIXME - the list_timers API is gross. Fix after GUI merge
        for timer in self.list_timers(
            self.context,
            self.config["kernel"],
        ):
            if not timer.valid_type():
                continue

            try:
                dpc = timer.get_dpc()
                if dpc == 0:
                    continue
                if dpc.DeferredRoutine == 0:
                    continue
                deferred_routine = dpc.DeferredRoutine
            except exceptions.InvalidAddressException as exc:
                vollog.debug(
                    f"Failed to get _KTIMER.Dpc due to {exc.__class__.__name__}"
                )
                continue

            module_symbols = list(
                collection.get_module_symbols_by_absolute_location(deferred_routine)
            )

            if module_symbols:
                for module_name, symbol_generator in module_symbols:
                    symbols_found = False

                    # we might have multiple symbols pointing to the same location
                    for symbol in symbol_generator:
                        symbols_found = True
                        yield (
                            0,
                            (
                                format_hints.Hex(timer.vol.offset),
                                timer.get_due_time(),
                                timer.Period,
                                timer.get_signaled(),
                                format_hints.Hex(deferred_routine),
                                module_name,
                                symbol.split(constants.BANG)[1],
                            ),
                        )

                    # no symbols, but we at least can report the module name
                    if not symbols_found:
                        yield (
                            0,
                            (
                                format_hints.Hex(timer.vol.offset),
                                timer.get_due_time(),
                                timer.Period,
                                timer.get_signaled(),
                                format_hints.Hex(deferred_routine),
                                module_name,
                                renderers.NotAvailableValue(),
                            ),
                        )
            else:
                # no module was found at the absolute location
                yield (
                    0,
                    (
                        format_hints.Hex(timer.vol.offset),
                        timer.get_due_time(),
                        timer.Period,
                        timer.get_signaled(),
                        format_hints.Hex(deferred_routine),
                        renderers.NotAvailableValue(),
                        renderers.NotAvailableValue(),
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("DueTime", str),
                ("Period(ms)", int),
                ("Signaled", str),
                ("Routine", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
