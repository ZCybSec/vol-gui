# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
from typing import Iterable, Callable, Optional, Tuple

from volatility3.framework import renderers, interfaces, layers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins import timeliner
from volatility3.plugins.windows import info
from volatility3.plugins.windows import poolscanner
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class PsScan(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for processes present in a particular windows memory image."""

    _required_framework_version = (2, 3, 1)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed processes",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="physical",
                description="Display physical offset instead of virtual",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def physical_offset_from_virtual(cls, context, layer_name, proc):
        """Calculate the physical offset from the virtual offset of a process.

        Args:
            context: The context containing layers and modules information.
            layer_name: The name of the layer containing the process memory.
            proc: The process object for which to calculate the physical offset.

        Returns:
            int: The physical offset of the process.
        Raises:
            TypeError: If the primary layer is not an Intel layer.
        """
        memory = context.layers[layer_name]

        if not isinstance(memory, layers.intel.Intel):
            raise TypeError("Primary layer is not an intel layer")

        (_, _, ph_offset, _, _) = list(
            memory.mapping(offset=proc.vol.offset, length=0)
        )[0]

        return ph_offset

    @classmethod
    def create_offset_filter(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        offset: Optional[int] = None,
        physical: bool = True,
        exclude: bool = False,
    ) -> Callable[[interfaces.objects.ObjectInterface], bool]:
        """A factory for producing filter functions that filter based on the physical offset of the process.

        Args:
            offset: A number that is the physical offset to be filtered out
            exclude: Accept only tasks that are not the offset argument

        Returns:
            Filter function to be passed to the list of processes.
        """

        def filter_func(_):
            return False

        if offset:
            if physical:
                if exclude:

                    def filter_func(proc):
                        return (
                            cls.physical_offset_from_virtual(context, layer_name, proc)
                            == offset
                        )

                else:

                    def filter_func(proc):
                        return (
                            cls.physical_offset_from_virtual(context, layer_name, proc)
                            != offset
                        )

            else:
                if exclude:

                    def filter_func(proc):
                        return proc.vol.offset == offset

                else:

                    def filter_func(proc):
                        return proc.vol.offset != offset

        return filter_func

    @classmethod
    def scan_processes(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable[
            [interfaces.objects.ObjectInterface], bool
        ] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for processes using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module for the kernel

        Returns:
            A list of processes found by scanning the `layer_name` layer for process pool signatures
        """

        kernel = context.modules[kernel_module_name]

        constraints = poolscanner.PoolScanner.builtin_constraints(
            kernel.symbol_table_name, [b"Pro\xe3", b"Proc"]
        )

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, kernel_module_name, constraints
        ):
            _constraint, mem_object, _header = result
            if not filter_func(mem_object):
                yield mem_object

    @classmethod
    def virtual_process_from_physical(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        proc: interfaces.objects.ObjectInterface,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Returns a virtual process from a physical addressed one

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module inside the kernel
            proc: the process object with physical address

        Returns:
            A process object on virtual address layer

        """

        ntkrnlmp = context.modules[kernel_module_name]

        version = cls.get_osversion(context, kernel_module_name)

        tleoffset = ntkrnlmp.get_type("_ETHREAD").relative_child_offset(
            "ThreadListEntry"
        )
        # Start out with the member offset
        offsets = [tleoffset]

        # If (and only if) we're dealing with 64-bit Windows 7 SP1
        # then add the other commonly seen member offset to the list
        bits = context.layers[ntkrnlmp.layer_name].bits_per_register
        if version == (6, 1, 7601) and bits == 64:
            offsets.append(tleoffset + 8)

        # Now we can try to bounce back
        for ofs in offsets:
            ethread = ntkrnlmp.object(
                object_type="_ETHREAD",
                offset=proc.ThreadListHead.Flink - ofs,
                absolute=True,
            )

            # Ask for the thread's process to get an _EPROCESS with a virtual address layer
            virtual_process = ethread.owning_process()
            # Sanity check the bounce.
            # This compares the original offset with the new one (translated from virtual layer)
            (_, _, ph_offset, _, _) = list(
                context.layers[ntkrnlmp.layer_name].mapping(
                    offset=virtual_process.vol.offset, length=0
                )
            )[0]
            if virtual_process and proc.vol.offset == ph_offset:
                return virtual_process
        return None

    @classmethod
    def get_osversion(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> Tuple[int, int, int]:
        """Returns the complete OS version (MAJ,MIN,BUILD)

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module for the kernel
        Returns:
            A tuple with (MAJ,MIN,BUILD)
        """
        kuser = info.Info.get_kuser_structure(context, kernel_module_name)
        nt_major_version = int(kuser.NtMajorVersion)
        nt_minor_version = int(kuser.NtMinorVersion)
        vers = info.Info.get_version_structure(context, kernel_module_name)
        build = vers.MinorVersion
        return (nt_major_version, nt_minor_version, build)

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )
        memory = self.context.layers[kernel.layer_name]
        if not isinstance(memory, layers.intel.Intel):
            raise TypeError("Primary layer is not an intel layer")

        for proc in self.scan_processes(
            self.context,
            self.config["kernel"],
            filter_func=pslist.PsList.create_pid_filter(self.config.get("pid", None)),
        ):
            file_output = "Disabled"
            if self.config["dump"]:
                # windows 10 objects (maybe others in the future) are already in virtual memory
                if proc.vol.layer_name == kernel.layer_name:
                    vproc = proc
                else:
                    try:
                        vproc = self.virtual_process_from_physical(
                            self.context,
                            self.config["kernel"],
                            proc,
                        )
                    except exceptions.PagedInvalidAddressException:
                        vproc = None

                file_output = "Error outputting file"
                if vproc:
                    file_handle = pslist.PsList.process_dump(
                        self.context,
                        kernel.symbol_table_name,
                        pe_table_name,
                        vproc,
                        self.open,
                    )

                    if file_handle:
                        file_output = file_handle.preferred_filename

            if not self.config["physical"]:
                offset = proc.vol.offset
            else:
                (_, _, offset, _, _) = list(
                    memory.mapping(offset=proc.vol.offset, length=0)
                )[0]

            try:
                yield (
                    0,
                    (
                        proc.UniqueProcessId,
                        proc.InheritedFromUniqueProcessId,
                        proc.ImageFileName.cast(
                            "string",
                            max_length=proc.ImageFileName.vol.count,
                            errors="replace",
                        ),
                        format_hints.Hex(offset),
                        proc.ActiveThreads,
                        proc.get_handle_count(),
                        proc.get_session_id(),
                        proc.get_is_wow64(),
                        proc.get_create_time(),
                        proc.get_exit_time(),
                        file_output,
                    ),
                )
            except exceptions.InvalidAddressException:
                vollog.info(
                    f"Invalid process found at address: {proc.vol.offset:x}. Skipping"
                )

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = f"Process: {row_data[0]} {row_data[2]} ({row_data[3]})"
            yield (description, timeliner.TimeLinerType.CREATED, row_data[8])
            yield (description, timeliner.TimeLinerType.MODIFIED, row_data[9])

    def run(self):
        offsettype = "(V)" if not self.config["physical"] else "(P)"
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("PPID", int),
                ("ImageFileName", str),
                (f"Offset{offsettype}", format_hints.Hex),
                ("Threads", int),
                ("Handles", int),
                ("SessionId", int),
                ("Wow64", bool),
                ("CreateTime", datetime.datetime),
                ("ExitTime", datetime.datetime),
                ("File output", str),
            ],
            self._generator(),
        )
