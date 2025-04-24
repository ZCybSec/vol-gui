# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import logging
import pefile

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, pe_symbols 

vollog = logging.getLogger(__name__)

class EtwPatch(interfaces.plugins.PluginInterface):
    """Detects ETW patching by examining the first opcode of EtwEventWrite in ntdll.dll."""

    # Plugin metadata for auto-discovery
    _version = (1, 0, 0)
    _required_framework_version = (2, 26, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name='kernel',
                description='Windows kernel',
                architectures=["Intel32", "Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pe_symbols", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name='pid',
                description='Filter on specific process IDs',
                element_type=int,
                optional=True
            )
        ]

    def _generator(self):
        pid_filter = self.config.get('pid', None)

        for proc in pslist.PsList.list_processes(
                context=self.context,
                kernel_module_name=self.config['kernel']):
            
            # If the user passed --pid, only process those IDs
            if pid_filter and proc.UniqueProcessId not in pid_filter:
                continue

            pid = int(proc.UniqueProcessId)
            proc_name = proc.ImageFileName.cast(
                "string",
                max_length = proc.ImageFileName.vol.count,
                errors = 'replace'
            )

            # Build a per-process memory layer
            try:
                proc_layer_name = proc.add_process_layer()
            except Exception:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            # Find ntdll.dll module
            for module in proc.load_order_modules():
                BaseDllName = FullDllName = renderers.UnreadableValue()
                with contextlib.suppress(exceptions.InvalidAddressException):
                    BaseDllName = module.BaseDllName.get_string()
                    FullDllName = module.FullDllName.get_string()
                
                if BaseDllName != 'ntdll.dll':
                    continue

                base = module.DllBase
                size = module.SizeOfImage

                pe_table_name = intermed.IntermediateSymbolTable.create(
                    self.context, self.config_path, "windows", "pe", class_types=pe.class_types
                )
                
                pe_obj = pe_symbols.PESymbols.get_pefile_obj(
                    self.context, pe_table_name, proc_layer_name, base
                )
                
                try:
                    pe_obj.parse_data_directories(
                        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
                    )
                except Exception as e:
                    vollog.debug(f"Error parsing IMAGE_DIRECTORY_ENTRY_EXPORT with {e}")
                    continue
                
                if not hasattr(pe_obj, "DIRECTORY_ENTRY_EXPORT"):
                    return None
                
                for export in pe_obj.DIRECTORY_ENTRY_EXPORT.symbols:
                    if export.name not in [b"EtwEventWrite", b"EtwEventWriteFull", b"NtTraceEvent"]:
                        continue
        
                    function_start = base + export.address
                    try:
                        with contextlib.suppress(exceptions.InvalidAddressException):
                            opcode = self.context.layers[proc_layer_name].read(
                                function_start, 1
                            ).hex()
                        
                            # 0xC3 = RET, 0xE9 = JMP (common ETW patches)
                            if opcode in ('c3', 'e9'):
                                yield (0, (
                                    pid,
                                    proc_name,
                                    BaseDllName,
                                    export.name.decode(),
                                    format_hints.Hex(function_start),
                                    opcode
                                ))
                    except Exception as e:
                        vollog.debug(f"Error parsing IMAGE_DIRECTORY_ENTRY_EXPORT with {e}")
                        continue
                    finally:
                      break

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("DLL", str),
                ("Function", str),
                ("Offset", format_hints.Hex),
                ("Opcode", str)
            ],
            self._generator()
        )
