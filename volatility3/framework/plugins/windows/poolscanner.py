# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import enum
import logging
from typing import Dict, Generator, List, Optional, Tuple

from volatility3.framework import constants, interfaces, renderers, exceptions, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins, configuration
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import extensions, versions
from volatility3.plugins.windows import handles

vollog = logging.getLogger(__name__)


class PoolType(enum.IntFlag):
    """Class to maintain the different possible PoolTypes The values must be
    integer powers of 2."""

    PAGED = 1
    NONPAGED = 2
    FREE = 4


class PoolConstraint:
    """Class to maintain tag/size/index/type information about Pool header
    tags."""

    def __init__(
        self,
        tag: bytes,
        type_name: str,
        object_type: Optional[str] = None,
        page_type: Optional[PoolType] = None,
        size: Optional[Tuple[Optional[int], Optional[int]]] = None,
        index: Optional[Tuple[Optional[int], Optional[int]]] = None,
        alignment: Optional[int] = 1,
        skip_type_test: bool = False,
        additional_structures: Optional[List[str]] = None,
    ) -> None:
        self.tag = tag
        self.type_name = type_name
        self.object_type = object_type
        self.page_type = page_type
        self.size = size
        self.index = index
        self.alignment = alignment
        self.skip_type_test = skip_type_test
        self.additional_structures = additional_structures


class PoolHeaderScanner(interfaces.layers.ScannerInterface):
    _version = (1, 0, 0)

    def __init__(
        self,
        module: interfaces.context.ModuleInterface,
        constraint_lookup: Dict[bytes, PoolConstraint],
        alignment: int,
    ):
        super().__init__()
        self._module = module
        self._constraint_lookup = constraint_lookup
        self._alignment = alignment

        header_type = self._module.get_type("_POOL_HEADER")
        self._header_offset = header_type.relative_child_offset("PoolTag")
        self._subscanner = scanners.MultiStringScanner(
            [c for c in constraint_lookup.keys()]
        )

    def __call__(self, data: bytes, data_offset: int):
        for offset, pattern in self._subscanner(data, data_offset):
            header = self._module.object(
                object_type="_POOL_HEADER",
                offset=offset - self._header_offset,
                absolute=True,
            )

            constraint = self._constraint_lookup[pattern]
            try:
                # Size check
                if constraint.size is not None:
                    if constraint.size[0]:
                        if (self._alignment * header.BlockSize) < constraint.size[0]:
                            continue
                    if constraint.size[1]:
                        if (self._alignment * header.BlockSize) > constraint.size[1]:
                            continue

                # Type check
                if constraint.page_type is not None:
                    checks_pass = False

                    if (constraint.page_type & PoolType.FREE) and header.is_free_pool():
                        checks_pass = True
                    elif (
                        constraint.page_type & PoolType.NONPAGED
                    ) and header.is_nonpaged_pool():
                        checks_pass = True
                    elif (
                        constraint.page_type & PoolType.PAGED
                    ) and header.is_paged_pool():
                        checks_pass = True

                    if not checks_pass:
                        continue

                if constraint.index is not None:
                    if constraint.index[0]:
                        if header.PoolIndex < constraint.index[0]:
                            continue
                    if constraint.index[1]:
                        if header.PoolIndex > constraint.index[1]:
                            continue

            except exceptions.InvalidAddressException:
                # The tested object's header doesn't point to valid addresses, ignore it
                continue

            # We found one that passed!
            yield (constraint, header)


class PoolScanner(plugins.PluginInterface):
    """A generic pool scanner plugin."""

    _required_framework_version = (2, 0, 0)
    _version = (3, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="handles", component=handles.Handles, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pool_header_scanner",
                component=PoolHeaderScanner,
                version=(1, 0, 0),
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        symbol_table = kernel.symbol_table_name
        constraints = self.builtin_constraints(symbol_table)

        for constraint, mem_object, header in self.generate_pool_scan(
            self.context, self.config["kernel"], constraints
        ):
            # generate some type-specific info for sanity checking
            if constraint.object_type == "Process":
                name = mem_object.ImageFileName.cast(
                    "string",
                    max_length=mem_object.ImageFileName.vol.count,
                    errors="replace",
                )
            elif constraint.object_type == "File":
                try:
                    name = mem_object.FileName.String
                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Skipping file at {mem_object.vol.offset:#x}",
                    )
                    continue
            else:
                name = renderers.NotApplicableValue()

            yield (
                0,
                (
                    constraint.type_name,
                    format_hints.Hex(header.vol.offset),
                    header.vol.layer_name,
                    name,
                ),
            )

    @staticmethod
    def gui_poolscanner_constraints(
        gui_table: str, tags_filter: Optional[List[bytes]] = None
    ) -> List[PoolConstraint]:
        """
        Constraints for objects managed by the GUI subsystem (win32k*.sys)
        """
        builtins = [
            PoolConstraint(
                b"Wind",
                type_name=gui_table + constants.BANG + "tagWINDOWSTATION",
                size=(0x90, None),
                page_type=PoolType.PAGED | PoolType.NONPAGED,
                object_type="WindowStation",
                skip_type_test=True,
            ),
            PoolConstraint(
                b"Desk",
                type_name=gui_table + constants.BANG + "tagDESKTOP",
                page_type=PoolType.PAGED | PoolType.NONPAGED,
                object_type="Desktop",
                skip_type_test=True,
            ),
        ]

        if not tags_filter:
            return builtins

        return [constraint for constraint in builtins if constraint.tag in tags_filter]

    @classmethod
    def builtin_constraints(
        cls, symbol_table: str, tags_filter: Optional[List[bytes]] = None
    ) -> List[PoolConstraint]:
        """Get built-in PoolConstraints given a list of pool tags.

        The tags_filter is a list of pool tags, and the associated
        PoolConstraints are  returned. If tags_filter is empty or
        not supplied, then all builtin constraints are returned.

        Args:
            symbol_table: The name of the symbol table to prepend to the types used
            tags_filter: List of tags to return or None to return all

        Returns:
            A list of well-known constructed PoolConstraints that match the provided tags
        """

        builtins = [
            # atom tables
            PoolConstraint(
                b"AtmT",
                type_name=symbol_table + constants.BANG + "_RTL_ATOM_TABLE",
                size=(200, None),
                # TODO - update this after the GUI code goes on
                page_type=PoolType.PAGED | PoolType.NONPAGED | PoolType.FREE,
            ),
            # processes on windows before windows 8
            PoolConstraint(
                b"Pro\xe3",
                type_name=symbol_table + constants.BANG + "_EPROCESS",
                object_type="Process",
                size=(600, None),
                skip_type_test=True,
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # processes on windows starting with windows 8
            PoolConstraint(
                b"Proc",
                type_name=symbol_table + constants.BANG + "_EPROCESS",
                object_type="Process",
                size=(600, None),
                skip_type_test=True,
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # threads on windows before windows8
            PoolConstraint(
                b"Thr\xe5",  # -> “protected” allocation, MSB is set.
                type_name=symbol_table + constants.BANG + "_ETHREAD",
                object_type="Thread",
                size=(600, None),  # -> 0x0258 - size of struct in win5.1
                skip_type_test=True,
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # threads on windows starting with windows8
            PoolConstraint(
                b"Thre",
                type_name=symbol_table + constants.BANG + "_ETHREAD",
                object_type="Thread",
                size=(600, None),  # -> 0x0258 - size of struct in win5.1
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # files on windows before windows 8
            PoolConstraint(
                b"Fil\xe5",
                type_name=symbol_table + constants.BANG + "_FILE_OBJECT",
                object_type="File",
                size=(150, None),
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # files on windows starting with windows 8
            PoolConstraint(
                b"File",
                type_name=symbol_table + constants.BANG + "_FILE_OBJECT",
                object_type="File",
                size=(150, None),
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # mutants on windows before windows 8
            PoolConstraint(
                b"Mut\xe1",
                type_name=symbol_table + constants.BANG + "_KMUTANT",
                object_type="Mutant",
                size=(64, None),
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # mutants on windows starting with windows 8
            PoolConstraint(
                b"Muta",
                type_name=symbol_table + constants.BANG + "_KMUTANT",
                object_type="Mutant",
                size=(64, None),
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # drivers on windows before windows 8
            PoolConstraint(
                b"Dri\xf6",
                type_name=symbol_table + constants.BANG + "_DRIVER_OBJECT",
                object_type="Driver",
                size=(248, None),
                page_type=PoolType.NONPAGED | PoolType.FREE,
                additional_structures=["_DRIVER_EXTENSION"],
            ),
            # drivers on windows starting with windows 8
            PoolConstraint(
                b"Driv",
                type_name=symbol_table + constants.BANG + "_DRIVER_OBJECT",
                object_type="Driver",
                size=(248, None),
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # kernel modules
            PoolConstraint(
                b"MmLd",
                type_name=symbol_table + constants.BANG + "_LDR_DATA_TABLE_ENTRY",
                size=(76, None),
                page_type=PoolType.NONPAGED | PoolType.FREE,
            ),
            # symlinks on windows before windows 8
            PoolConstraint(
                b"Sym\xe2",
                type_name=symbol_table + constants.BANG + "_OBJECT_SYMBOLIC_LINK",
                object_type="SymbolicLink",
                size=(72, None),
                page_type=PoolType.PAGED | PoolType.FREE,
            ),
            # symlinks on windows starting with windows 8
            PoolConstraint(
                b"Symb",
                type_name=symbol_table + constants.BANG + "_OBJECT_SYMBOLIC_LINK",
                object_type="SymbolicLink",
                size=(72, None),
                page_type=PoolType.PAGED | PoolType.FREE,
            ),
            # registry hives
            PoolConstraint(
                b"CM10",
                type_name=symbol_table + constants.BANG + "_CMHIVE",
                size=(800, None),
                page_type=PoolType.PAGED | PoolType.FREE,
                skip_type_test=True,
            ),
        ]

        if not tags_filter:
            return builtins

        return [constraint for constraint in builtins if constraint.tag in tags_filter]

    @classmethod
    def generate_pool_scan_extended(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        object_symbol_table_name: str,
        constraints: List[PoolConstraint],
    ) -> Generator[
        Tuple[
            PoolConstraint,
            interfaces.objects.ObjectInterface,
            interfaces.objects.ObjectInterface,
        ],
        None,
        None,
    ]:
        """
        The extended version of `generate_pool_scan` to support pool scanning for objects outside of the kernel (ntoskrnl).
        This requires the symbol table of the object being scanned for.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module for the kernel
            object_symbol_table_name: The name of the symbol table for the object being scanned for
            constraints: List of pool constraints used to limit the scan results
        Returns:
            Iterable of tuples, containing the constraint that matched, the object from memory, the object header used to determine the object
        """

        kernel = context.modules[kernel_module_name]

        # get the object type map
        type_map = handles.Handles.get_type_map(
            context=context, kernel_module_name=kernel_module_name
        )

        cookie = handles.Handles.find_cookie(
            context=context, kernel_module_name=kernel_module_name
        )

        is_windows_10 = versions.is_windows_10(context, kernel.symbol_table_name)
        is_windows_8_or_later = versions.is_windows_8_or_later(
            context, kernel.symbol_table_name
        )

        # start off with the primary virtual layer
        scan_layer = kernel.layer_name

        # switch to a non-virtual layer if necessary
        if not is_windows_10:
            scan_layer = context.layers[scan_layer].config["memory_layer"]

        if symbols.symbol_table_is_64bit(
            context=context, symbol_table_name=kernel.symbol_table_name
        ):
            alignment = 0x10
        else:
            alignment = 8

        # scan in the main kernel layer for the object(s)
        for constraint, header in cls.pool_scan(
            context,
            kernel_module_name,
            scan_layer,
            object_symbol_table_name,
            constraints,
            alignment=alignment,
        ):

            mem_objects = header.get_object(
                constraint=constraint,
                use_top_down=is_windows_8_or_later,
                native_layer_name=kernel.layer_name,
                kernel_symbol_table=kernel.symbol_table_name,
            )

            for mem_object in mem_objects:
                if mem_object is None:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Cannot create an instance of {constraint.type_name}",
                    )

                    continue

                if constraint.object_type is not None and not constraint.skip_type_test:
                    try:
                        if (
                            mem_object.get_object_header().get_object_type(
                                type_map, cookie
                            )
                            != constraint.object_type
                        ):
                            continue
                    except exceptions.InvalidAddressException:
                        vollog.log(
                            constants.LOGLEVEL_VVV,
                            f"Cannot test instance type check for {constraint.type_name}",
                        )
                        continue

                yield constraint, mem_object, header

    @classmethod
    def generate_pool_scan(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        constraints: List[PoolConstraint],
    ) -> Generator[
        Tuple[
            PoolConstraint,
            interfaces.objects.ObjectInterface,
            interfaces.objects.ObjectInterface,
        ],
        None,
        None,
    ]:
        """
        The original version of `generate_pool_scan` which is sufficient for objects in the kernel (ntoskrnl),

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the module for the kernel
            constraints: List of pool constraints used to limit the scan results

        Returns:
            Iterable of tuples, containing the constraint that matched, the object from memory, the object header used to determine the object
        """

        kernel = context.modules[kernel_module_name]

        # repeat the symbol table to match the original `generate_pool_scan` behaviour
        yield from cls.generate_pool_scan_extended(
            context, kernel_module_name, kernel.symbol_table_name, constraints
        )

    @classmethod
    def pool_scan(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        layer_name: str,
        symbol_table: str,
        pool_constraints: List[PoolConstraint],
        alignment: int = 8,
        progress_callback: Optional[constants.ProgressCallback] = None,
    ) -> Generator[
        Tuple[PoolConstraint, interfaces.objects.ObjectInterface], None, None
    ]:
        """Returns the _POOL_HEADER object (based on the symbol_table template)
        after scanning through layer_name returning all headers that match any
        of the constraints provided.  Only one constraint can be provided per
        tag.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            pool_constraints: List of pool constraints used to limit the scan results
            alignment: An optional value that all pool headers will be aligned to
            progress_callback: An optional function to provide progress feedback whilst scanning

        Returns:
            An Iterable of pool constraints and the pool headers associated with them
        """
        # Setup the pattern
        constraint_lookup: Dict[bytes, PoolConstraint] = {}
        for constraint in pool_constraints:
            if constraint.tag in constraint_lookup:
                raise ValueError(
                    f"Constraint tag is used for more than one constraint: {repr(constraint.tag)}"
                )
            constraint_lookup[constraint.tag] = constraint

        kernel = context.modules[kernel_module_name]

        if kernel.has_type("_POOL_HEADER"):
            pool_header_table_name = kernel.symbol_table_name
        else:
            pool_header_table_name = cls.get_pool_header_table(context, symbol_table)

        module = context.module(
            pool_header_table_name, layer_name, offset=kernel.offset
        )

        # Run the scan locating the offsets of a particular tag
        layer = context.layers[layer_name]
        scanner = PoolHeaderScanner(module, constraint_lookup, alignment)
        yield from layer.scan(context, scanner, progress_callback)

    @classmethod
    def get_pool_header_table(
        cls, context: interfaces.context.ContextInterface, symbol_table: str
    ) -> str:
        """Returns the appropriate symbol_table containing a _POOL_HEADER type, even if the original symbol table
        doesn't contain one.

        Args:
            context: The context that the symbol tables does (or will) reside in
            symbol_table: The expected symbol_table to contain the _POOL_HEADER type
        """
        # We have to manually load a symbol table

        if symbols.symbol_table_is_64bit(
            context=context, symbol_table_name=symbol_table
        ):
            is_win_7 = versions.is_windows_7(context, symbol_table)
            if is_win_7:
                pool_header_json_filename = "poolheader-x64-win7"
            else:
                pool_header_json_filename = "poolheader-x64"
        else:
            pool_header_json_filename = "poolheader-x86"

        # set the class_type to match the normal WindowsKernelIntermedSymbols
        is_vista_or_later = versions.is_vista_or_later(context, symbol_table)
        if is_vista_or_later:
            class_type = extensions.pool.POOL_HEADER_VISTA
        else:
            class_type = extensions.pool.POOL_HEADER

        table_name = intermed.IntermediateSymbolTable.create(
            context=context,
            config_path=configuration.path_join(
                context.symbol_space[symbol_table].config_path, "poolheader"
            ),
            sub_path="windows",
            filename=pool_header_json_filename,
            table_mapping={"nt_symbols": symbol_table},
            class_types={"_POOL_HEADER": class_type},
        )

        return table_name

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [("Tag", str), ("Offset", format_hints.Hex), ("Layer", str), ("Name", str)],
            self._generator(),
        )
